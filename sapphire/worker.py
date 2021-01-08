# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server worker
"""
from logging import getLogger
from os import stat
from os.path import isfile
from re import compile as re_compile
from socket import error as sock_error, timeout as sock_timeout
from sys import exc_info
from threading import active_count, Thread, ThreadError
from time import sleep
from urllib.parse import unquote_plus

from .server_map import Resource

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class WorkerError(Exception):
    """Raised by Worker"""


class Worker:
    DEFAULT_REQUEST_LIMIT = 0x1000  # 4KB
    DEFAULT_TX_SIZE = 0x10000  # 64KB
    REQ_PATTERN = re_compile(b"^GET\\s/(?P<request>\\S*)\\sHTTP/1")

    __slots__ = ("_conn", "_thread")

    def __init__(self, conn, thread):
        self._conn = conn
        self._thread = thread

    @staticmethod
    def _200_header(c_length, c_type, encoding="ascii"):
        assert c_type is not None
        data = "HTTP/1.1 200 OK\r\n" \
               "Cache-Control: max-age=0, no-cache\r\n" \
               "Content-Length: %d\r\n" \
               "Content-Type: %s\r\n" \
               "Connection: close\r\n\r\n" % (c_length, c_type)
        return data.encode(encoding)

    @staticmethod
    def _307_redirect(redirct_to, encoding="ascii"):
        data = "HTTP/1.1 307 Temporary Redirect\r\n" \
               "Location: %s\r\n" \
               "Connection: close\r\n\r\n" % (redirct_to,)
        return data.encode(encoding)

    @staticmethod
    def _4xx_page(code, hdr_msg, close=-1, encoding="ascii"):
        if close < 0:
            content = "<h3>%d!</h3>" % (code,)
        else:
            content = "<script>window.setTimeout(window.close, %d)</script>\n" \
                      "<body style=\"background-color:#ffffe0\">\n" \
                      "<h3>%d! - Calling window.close() in %d seconds</h3>\n" \
                      "</body>\n" % (close * 1000, code, close)
        data = "HTTP/1.1 %d %s\r\n" \
               "Content-Length: %d\r\n" \
               "Content-Type: text/html\r\n" \
               "Connection: close\r\n\r\n%s" % (code, hdr_msg, len(content), content)
        return data.encode(encoding)

    def close(self):
        if not self.done:
            LOG.debug("closing socket while thread is running!")
        self._conn.close()
        self.join(timeout=60)
        if self._thread is not None and self._thread.is_alive():
            # this is here to catch unexpected hangs
            raise WorkerError("Worker thread failed to join!")

    @property
    def done(self):
        if self._thread is not None and not self._thread.is_alive():
            self.join()
            self._thread = None
        return self._thread is None

    @classmethod
    def handle_request(cls, conn, serv_job):
        finish_job = False  # call finish() on return
        try:
            # receive all the incoming data
            raw_request = conn.recv(cls.DEFAULT_REQUEST_LIMIT)
            if not raw_request:
                LOG.debug("raw_request was empty")
                serv_job.accepting.set()
                return

            request = cls.REQ_PATTERN.match(raw_request)
            if request is None:
                serv_job.accepting.set()
                conn.sendall(cls._4xx_page(400, "Bad Request", serv_job.auto_close))
                LOG.debug("400 request length %d (%d to go)", len(raw_request), serv_job.pending)
                return

            request = unquote_plus(request.group("request").decode("ascii"))
            LOG.debug("check_request(%r)", request)
            resource = serv_job.check_request(request)
            if resource is None:
                LOG.debug("resource is None")  # 404
            elif resource.type in (Resource.URL_FILE, Resource.URL_INCLUDE):
                finish_job = serv_job.remove_pending(resource.target)
            elif resource.type in (Resource.URL_DYNAMIC, Resource.URL_REDIRECT):
                finish_job = serv_job.remove_pending(request)
            else:  # pragma: no cover
                # this should never happen
                raise WorkerError("Unknown resource type %r" % (resource.type,))

            if finish_job and serv_job.forever:
                LOG.debug("serv_job.forever is set, resetting finish_job")
                finish_job = False

            if not finish_job:
                serv_job.accepting.set()
            else:
                LOG.debug("expecting to finish")

            if resource is None:
                conn.sendall(cls._4xx_page(404, "Not Found", serv_job.auto_close))
                LOG.debug("404 %r (%d to go)", request, serv_job.pending)
                return
            if resource.type in (Resource.URL_FILE, Resource.URL_INCLUDE):
                LOG.debug("target %r", resource.target)
                # isfile() check for Resource.URL_FILE happens in serv_job.check_request()
                if resource.type == Resource.URL_INCLUDE and not isfile(resource.target):
                    conn.sendall(cls._4xx_page(404, "Not Found", serv_job.auto_close))
                    LOG.debug("404 %r (%d to go)", request, serv_job.pending)
                    return
                if serv_job.is_forbidden(resource.target):
                    # NOTE: this does info leak if files exist on disk.
                    # We could replace 403 with 404 if it turns out we care but this
                    # is meant to run locally and only be accessible from localhost
                    conn.sendall(cls._4xx_page(403, "Forbidden", serv_job.auto_close))
                    LOG.debug("403 %r (%d to go)", request, serv_job.pending)
                    return
            elif resource.type == Resource.URL_REDIRECT:
                conn.sendall(cls._307_redirect(resource.target))
                LOG.debug("307 %r -> %r (%d to go)", request, resource.target, serv_job.pending)
                return
            elif resource.type == Resource.URL_DYNAMIC:
                data = resource.target()
                if not isinstance(data, bytes):
                    LOG.debug("dynamic request: %r", request)
                    raise TypeError("dynamic request callback must return 'bytes'")
                conn.sendall(cls._200_header(len(data), resource.mime))
                conn.sendall(data)
                LOG.debug("200 %r - dynamic request (%d to go)", request, serv_job.pending)
                return

            # at this point we know "resource.target" maps to a file on disk
            # serve the file
            data_size = stat(resource.target).st_size
            LOG.debug("sending: %s bytes, mime: %r", format(data_size, ","), resource.mime)
            with open(resource.target, "rb") as in_fp:
                conn.sendall(cls._200_header(data_size, resource.mime))
                offset = 0
                while offset < data_size:
                    conn.sendall(in_fp.read(cls.DEFAULT_TX_SIZE))
                    offset = in_fp.tell()
            LOG.debug("200 %r (%d to go)", resource.target, serv_job.pending)
            serv_job.increment_served(resource.target)

        except (sock_error, sock_timeout):
            _, exc_obj, exc_tb = exc_info()
            LOG.debug("%r - line %d", exc_obj, exc_tb.tb_lineno)
            if not finish_job:
                serv_job.accepting.set()

        except Exception:  # pylint: disable=broad-except
            # set finish_job to abort immediately
            finish_job = True
            if serv_job.exceptions.empty():
                serv_job.exceptions.put(exc_info())

        finally:
            conn.close()
            if finish_job:
                serv_job.finish()
            serv_job.worker_complete.set()

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if not self._thread.is_alive():
                self._thread = None

    @classmethod
    def launch(cls, listen_sock, job):
        assert job.accepting.is_set()
        conn = None
        try:
            conn, _ = listen_sock.accept()
            conn.settimeout(None)
            # create a worker thread to handle client request
            w_thread = Thread(target=cls.handle_request, args=(conn, job))
            job.accepting.clear()
            w_thread.start()
            return cls(conn, w_thread)
        except (sock_error, sock_timeout):
            if conn is not None:  # pragma: no cover
                conn.close()
        except ThreadError:
            if conn is not None:  # pragma: no cover
                conn.close()
            # reset accepting status
            job.accepting.set()
            LOG.warning("ThreadError (worker), threads: %d", active_count())
            # wait for system resources to free up
            sleep(0.1)
        return None
