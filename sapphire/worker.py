# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server worker
"""
from logging import getLogger
from re import compile as re_compile
from socket import SHUT_RDWR
from socket import timeout as sock_timeout  # Py3.10 socket.timeout => TimeoutError
from sys import exc_info
from threading import Thread, ThreadError, active_count
from time import sleep
from urllib.parse import quote, unquote, urlparse

from .server_map import Resource

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class Request:
    REQ_PATTERN = re_compile(rb"^(?P<method>\w+)\s(?P<url>\S+)\sHTTP/1")

    __slots__ = ("method", "url")

    def __init__(self, method, url):
        self.method = method
        self.url = url

    @classmethod
    def parse(cls, raw_data):
        assert isinstance(raw_data, bytes)
        req_match = cls.REQ_PATTERN.match(raw_data)
        if not req_match:
            LOG.debug("request failed to match regex")
            return None

        # TODO: parse headers if needed

        try:
            # unquote() accepts str | bytes as of Python 3.9
            url = urlparse(
                unquote(req_match.group("url").decode("ascii", errors="replace"))
            )
        except ValueError as exc:
            if "Invalid IPv6 URL" not in str(exc):  # pragma: no cover
                raise
            LOG.debug("failed to parse url from request")
            return None

        return cls(req_match.group("method").decode("ascii", errors="replace"), url)


class WorkerError(Exception):
    """Raised by Worker"""


class Worker:
    DEFAULT_REQUEST_LIMIT = 0x1000  # 4KB
    DEFAULT_TX_SIZE = 0x10000  # 64KB

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
            f"Content-Length: {c_length}\r\n"
            f"Content-Type: {c_type}\r\n"
            "Connection: close\r\n\r\n"
        )
        return data.encode(encoding)

    @staticmethod
    def _307_redirect(redirect_to, encoding="ascii"):
        data = (
            "HTTP/1.1 307 Temporary Redirect\r\n"
            f"Location: {redirect_to}\r\n"
            "Connection: close\r\n\r\n"
        )
        return data.encode(encoding)

    @staticmethod
    def _4xx_page(code, hdr_msg, close=-1, encoding="ascii"):
        if close < 0:
            content = f"<h3>{code}!</h3>"
        else:
            content = (
                "<script>\n"
                "window.onload = () => "
                f"{{ window.setTimeout(window.close, {close * 1000}) }}\n"
                "</script>\n"
                '<body style="background-color:#ffffe0">\n'
                f"<h3>{code}! - Calling window.close() in {close} seconds</h3>\n"
                "</body>\n"
            )
        data = (
            f"HTTP/1.1 {code} {hdr_msg}\r\n"
            f"Content-Length: {len(content)}\r\n"
            "Content-Type: text/html\r\n"
            f"Connection: close\r\n\r\n{content}"
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
            # receive incoming request data
            raw_request = conn.recv(cls.DEFAULT_REQUEST_LIMIT)
            if not raw_request:
                LOG.debug("request was empty")
                serv_job.accepting.set()
                return
            request = Request.parse(raw_request)
            # handle bad request
            if not request:
                serv_job.accepting.set()
                conn.sendall(cls._4xx_page(400, "Bad Request", serv_job.auto_close))
                LOG.debug(
                    "400 bad request %r... length %d (%d to go)",
                    raw_request[:16],
                    len(raw_request),
                    serv_job.pending,
                )
                return
            # handle unsupported method
            if request.method != "GET":
                serv_job.accepting.set()
                conn.sendall(
                    cls._4xx_page(405, "Method Not Allowed", serv_job.auto_close)
                )
                LOG.debug(
                    "405 method %r (%d to go)",
                    request.method,
                    serv_job.pending,
                )
                return

            # lookup resource
            LOG.debug("lookup_resource(%r)", request.url.path)
            resource = serv_job.lookup_resource(request.url.path)
            if resource:
                if resource.type in (Resource.URL_FILE, Resource.URL_INCLUDE):
                    finish_job = serv_job.remove_pending(str(resource.target))
                elif resource.type in (Resource.URL_DYNAMIC, Resource.URL_REDIRECT):
                    finish_job = serv_job.remove_pending(request.url.path.lstrip("/"))
                else:  # pragma: no cover
                    # this should never happen
                    raise WorkerError(f"Unknown resource type {resource.type!r}")
                if serv_job.forever:
                    finish_job = False

            if not finish_job:
                serv_job.accepting.set()
            else:
                LOG.debug("expecting to finish")

            # send response
            if resource is None:
                conn.sendall(cls._4xx_page(404, "Not Found", serv_job.auto_close))
                LOG.debug("404 %r (%d to go)", request.url.path, serv_job.pending)
            elif resource.type == Resource.URL_REDIRECT:
                redirect_to = [quote(resource.target)]
                if request.url.query:
                    LOG.debug("appending query %r", request.url.query)
                    redirect_to.append(request.url.query)
                conn.sendall(cls._307_redirect("?".join(redirect_to)))
                LOG.debug(
                    "307 %r -> %r (%d to go)",
                    request.url.path,
                    resource.target,
                    serv_job.pending,
                )
            elif resource.type == Resource.URL_DYNAMIC:
                # pass query string to callback
                data = resource.target(request.url.query)
                if not isinstance(data, bytes):
                    LOG.debug("dynamic request: %r", request.url.path)
                    raise TypeError("dynamic request callback must return 'bytes'")
                conn.sendall(cls._200_header(len(data), resource.mime))
                conn.sendall(data)
                LOG.debug(
                    "200 %r - dynamic request (%d to go)",
                    request.url.path,
                    serv_job.pending,
                )
            elif serv_job.is_forbidden(
                resource.target, is_include=resource.type == Resource.URL_INCLUDE
            ):
                # NOTE: this does info leak if files exist on disk.
                # We could replace 403 with 404 if it turns out we care.
                # However this is meant to only be accessible via localhost.
                LOG.debug("target %r", str(resource.target))
                conn.sendall(cls._4xx_page(403, "Forbidden", serv_job.auto_close))
                LOG.debug("403 %r (%d to go)", request.url.path, serv_job.pending)
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
                LOG.debug("200 %r (%d to go)", request.url.path, serv_job.pending)
                serv_job.mark_served(resource.target)

        except (OSError, sock_timeout):
            _, exc_obj, exc_tb = exc_info()
            LOG.debug("%r - line %r", exc_obj, exc_tb.tb_lineno if exc_tb else None)
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
        except sock_timeout:
            # no connections to accept
            pass
        except OSError as exc:
            LOG.debug("worker thread not launched: %s", exc)
        except ThreadError:
            # reset accepting status
            job.accepting.set()
            LOG.warning("ThreadError (worker), threads: %d", active_count())
            # wait for system resources to free up
            sleep(0.1)
        if conn is not None:
            conn.close()
        return None
