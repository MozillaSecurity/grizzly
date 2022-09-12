# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server worker
"""
from logging import getLogger
from re import compile as re_compile
from socket import SHUT_RDWR
from socket import error as sock_error
from socket import timeout as sock_timeout
from sys import exc_info
from threading import Thread, ThreadError, active_count
from time import sleep
from urllib.parse import quote, unquote, urlparse

from .server_map import Resource

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class WorkerError(Exception):
    """Raised by Worker"""


class Worker:
    DEFAULT_REQUEST_LIMIT = 0x1000  # 4KB
    DEFAULT_TX_SIZE = 0x10000  # 64KB
    REQ_PATTERN = re_compile(b"^GET\\s/(?P<url>\\S*)\\sHTTP/1")

    __slots__ = ("_conn", "_thread")

    def __init__(self, conn, thread):
        self._conn = conn
        self._thread = thread

    @staticmethod
    def _200_header(c_length, c_type, encoding="ascii"):
        assert c_type is not None
        data = (
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=0, no-cache\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: %s\r\n"
            "Connection: close\r\n\r\n" % (c_length, c_type)
        )
        return data.encode(encoding)

    @staticmethod
    def _307_redirect(redirect_to, encoding="ascii"):
        data = (
            "HTTP/1.1 307 Temporary Redirect\r\n"
            "Location: %s\r\n"
            "Connection: close\r\n\r\n" % (redirect_to,)
        )
        return data.encode(encoding)

    @staticmethod
    def _4xx_page(code, hdr_msg, close=-1, encoding="ascii"):
        if close < 0:
            content = "<h3>%d!</h3>" % (code,)
        else:
            content = (
                "<script>\n"
                "window.onload = () => { window.setTimeout(window.close, %d) }\n"
                "</script>\n"
                '<body style="background-color:#ffffe0">\n'
                "<h3>%d! - Calling window.close() in %d seconds</h3>\n"
                "</body>\n" % (close * 1000, code, close)
            )
        data = (
            "HTTP/1.1 %d %s\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n%s" % (code, hdr_msg, len(content), content)
        )
        return data.encode(encoding)

    def close(self):
        if not self.done:
            LOG.debug("closing socket while thread is running!")
            # shutdown socket to avoid hang
            self._conn.shutdown(SHUT_RDWR)
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

            # check if request can be handled
            raw_url = cls.REQ_PATTERN.match(raw_request)
            if raw_url is None:
                serv_job.accepting.set()
                conn.sendall(cls._4xx_page(400, "Bad Request", serv_job.auto_close))
                LOG.debug(
                    "400 request length %d (%d to go)",
                    len(raw_request),
                    serv_job.pending,
                )
                return

            # lookup resource
            url = urlparse(unquote(raw_url.group("url").decode("ascii")))
            LOG.debug("lookup_resource(%r)", url.path)
            resource = serv_job.lookup_resource(url.path)
            if resource:
                if resource.type in (Resource.URL_FILE, Resource.URL_INCLUDE):
                    finish_job = serv_job.remove_pending(str(resource.target))
                elif resource.type in (Resource.URL_DYNAMIC, Resource.URL_REDIRECT):
                    finish_job = serv_job.remove_pending(url.path)
                else:  # pragma: no cover
                    # this should never happen
                    raise WorkerError("Unknown resource type %r" % (resource.type,))
                if serv_job.forever:
                    finish_job = False

            if not finish_job:
                serv_job.accepting.set()
            else:
                LOG.debug("expecting to finish")

            # send response
            if resource is None:
                conn.sendall(cls._4xx_page(404, "Not Found", serv_job.auto_close))
                LOG.debug("404 %r (%d to go)", url.path, serv_job.pending)
            elif resource.type == Resource.URL_REDIRECT:
                redirect_to = [quote(resource.target)]
                if url.query:
                    LOG.debug("appending query %r", url.query)
                    redirect_to.append(url.query)
                conn.sendall(cls._307_redirect("?".join(redirect_to)))
                LOG.debug(
                    "307 %r -> %r (%d to go)",
                    url.path,
                    resource.target,
                    serv_job.pending,
                )
            elif resource.type == Resource.URL_DYNAMIC:
                # pass query string to callback
                data = resource.target(url.query)
                if not isinstance(data, bytes):
                    LOG.debug("dynamic request: %r", url.path)
                    raise TypeError("dynamic request callback must return 'bytes'")
                conn.sendall(cls._200_header(len(data), resource.mime))
                conn.sendall(data)
                LOG.debug(
                    "200 %r - dynamic request (%d to go)", url.path, serv_job.pending
                )
            elif serv_job.is_forbidden(
                resource.target, is_include=resource.type == Resource.URL_INCLUDE
            ):
                # NOTE: this does info leak if files exist on disk.
                # We could replace 403 with 404 if it turns out we care.
                # However this is meant to only be accessible via localhost.
                LOG.debug("target %r", str(resource.target))
                conn.sendall(cls._4xx_page(403, "Forbidden", serv_job.auto_close))
                LOG.debug("403 %r (%d to go)", url.path, serv_job.pending)
            else:
                # serve the file
                LOG.debug("target %r", str(resource.target))
                data_size = resource.target.stat().st_size
                LOG.debug(
                    "sending: %s bytes, mime: %r", format(data_size, ","), resource.mime
                )
                with resource.target.open("rb") as in_fp:
                    conn.sendall(cls._200_header(data_size, resource.mime))
                    offset = 0
                    while offset < data_size:
                        conn.sendall(in_fp.read(cls.DEFAULT_TX_SIZE))
                        offset = in_fp.tell()
                LOG.debug("200 %r (%d to go)", url.path, serv_job.pending)
                serv_job.mark_served(resource.target)

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
