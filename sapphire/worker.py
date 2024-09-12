# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server worker
"""
from __future__ import annotations

from logging import getLogger
from re import compile as re_compile
from select import select
from socket import SHUT_RDWR, socket
from socket import timeout as sock_timeout  # Py3.10 socket.timeout => TimeoutError
from sys import exc_info
from threading import Thread, ThreadError, active_count
from time import sleep
from typing import TYPE_CHECKING
from urllib.parse import ParseResult, quote, unquote, urlparse

from .server_map import DynamicResource, FileResource, RedirectResource

if TYPE_CHECKING:
    from .job import Job

# TODO: urlparse -> urlsplit


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class Request:
    REQ_PATTERN = re_compile(rb"^(?P<method>\w+)\s(?P<url>\S+)\sHTTP/1")

    __slots__ = ("method", "url")

    def __init__(self, method: str, url: ParseResult) -> None:
        self.method = method
        self.url = url

    @classmethod
    def parse(cls, raw_data: bytes) -> Request | None:
        assert isinstance(raw_data, bytes)
        req_match = cls.REQ_PATTERN.match(raw_data)
        if not req_match:
            LOG.debug("request failed to match regex")
            return None

        # TODO: parse headers if needed

        try:
            url_str = req_match.group("url").decode("ascii", errors="replace")
            # unquote() accepts str | bytes as of Python 3.9
            url = urlparse(unquote(url_str))
        except ValueError as exc:
            msg = str(exc)
            if (
                "contains invalid characters under NFKC normalization" not in msg
                and "Invalid IPv6 URL" not in msg
                and "does not appear to be an IPv4 or IPv6 address" not in msg
            ):
                LOG.error("Failed to parse URL: %r", url_str)
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

    def __init__(self, conn: socket, thread: Thread) -> None:
        self._conn = conn
        self._thread: Thread | None = thread

    @staticmethod
    def _200_header(c_length: int, c_type: str) -> bytes:
        assert c_type is not None
        data = (
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=0, no-cache\r\n"
            f"Content-Length: {c_length}\r\n"
            f"Content-Type: {c_type}\r\n"
            "Connection: close\r\n\r\n"
        )
        return data.encode(encoding="ascii")

    @staticmethod
    def _307_redirect(redirect_to: str) -> bytes:
        data = (
            "HTTP/1.1 307 Temporary Redirect\r\n"
            f"Location: {redirect_to}\r\n"
            "Connection: close\r\n\r\n"
        )
        return data.encode(encoding="ascii")

    @staticmethod
    def _4xx_page(code: int, hdr_msg: str, close: int = -1) -> bytes:
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
        return data.encode(encoding="ascii")

    def close(self) -> None:
        # workers that are no longer running will have had close() called
        if self.is_alive():
            # shutdown socket to avoid hang
            LOG.debug("closing socket while thread is running!")
            try:
                self._conn.shutdown(SHUT_RDWR)
            except OSError as exc:
                LOG.debug("close - shutdown(): %s", exc)
            self._conn.close()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @classmethod
    def handle_request(cls, conn: socket, serv_job: Job) -> None:
        finish_job = False  # call finish() on return
        try:
            # socket operations should not block forever
            assert conn.gettimeout() is not None
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
                LOG.debug("405 method %r (%d to go)", request.method, serv_job.pending)
                return

            # lookup resource
            LOG.debug("lookup resource %r", request.url.path)
            resource = serv_job.lookup_resource(request.url.path)
            if resource:
                if isinstance(resource, FileResource):
                    finish_job = serv_job.remove_pending(str(resource.target))
                elif isinstance(resource, (DynamicResource, RedirectResource)):
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
                LOG.debug(
                    "404 '%s%s' (%d to go)",
                    "..." if len(request.url.path) > 40 else "",
                    request.url.path[-40:],
                    serv_job.pending,
                )
            elif isinstance(resource, RedirectResource):
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
            elif isinstance(resource, DynamicResource):
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
            else:
                assert isinstance(resource, FileResource)
                # serve the file
                data_size = resource.target.stat().st_size
                LOG.debug(
                    "sending: %s, %r, '%s'",
                    f"{data_size:,}B",
                    resource.mime,
                    resource.target,
                )
                assert resource.mime is not None
                with resource.target.open("rb") as in_fp:
                    conn.sendall(cls._200_header(data_size, resource.mime))
                    offset = 0
                    while offset < data_size:
                        conn.sendall(in_fp.read(cls.DEFAULT_TX_SIZE))
                        offset = in_fp.tell()
                LOG.debug("200 %r (%d to go)", request.url.path, serv_job.pending)
                serv_job.mark_served(resource)

        except (OSError, sock_timeout):
            _, exc_obj, exc_tb = exc_info()
            LOG.debug("%r - line %r", exc_obj, exc_tb.tb_lineno if exc_tb else None)
            if not finish_job:
                serv_job.accepting.set()

        except Exception:  # pylint: disable=broad-except
            LOG.debug("worker thread exception")
            # set finish_job to abort immediately
            finish_job = True
            if serv_job.exceptions.empty():
                serv_job.exceptions.put(exc_info())

        finally:
            conn.close()
            if finish_job:
                serv_job.finish()
            serv_job.worker_complete.set()

    def join(self, timeout: float = 30) -> bool:
        assert timeout >= 0
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if not self._thread.is_alive():
                self._thread = None
        return self._thread is None

    @classmethod
    def launch(
        cls, listen_sock: socket, job: Job, timeout: float = 30
    ) -> Worker | None:
        assert timeout >= 0
        assert job.accepting.is_set()
        # TODO: is select() timeout value too short, too long?
        readable, _, _ = select([listen_sock], (), (), 0.25)
        if listen_sock in readable:
            conn = None
            try:
                conn, _ = listen_sock.accept()
                conn.settimeout(timeout)
                # create a worker thread to handle client request
                w_thread = Thread(target=cls.handle_request, args=(conn, job))
                job.accepting.clear()
                w_thread.start()
                return cls(conn, w_thread)
            except BlockingIOError:
                # accept() can block because of race between select() and accept()
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
