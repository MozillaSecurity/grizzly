# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server
"""
from __future__ import annotations

from logging import getLogger
from pathlib import Path
from socket import SO_REUSEADDR, SOL_SOCKET, gethostname, socket
from ssl import PROTOCOL_TLS_SERVER, SSLContext, SSLSocket
from time import perf_counter, sleep
from typing import TYPE_CHECKING, Callable, Iterable, Mapping, cast

from .connection_manager import ConnectionManager
from .job import Job, Served

if TYPE_CHECKING:
    from argparse import Namespace

    from .certificate_bundle import CertificateBundle
    from .server_map import ServerMap

__all__ = (
    "BLOCKED_PORTS",
    "create_listening_socket",
    "Sapphire",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


# collection of ports to avoid
# see: searchfox.org/mozilla-central/source/netwerk/base/nsIOService.cpp
# include ports above 1024
BLOCKED_PORTS = frozenset(
    (
        1719,
        1720,
        1723,
        2049,
        3659,
        4045,
        5060,
        5061,
        6000,
        6566,
        6665,
        6666,
        6667,
        6668,
        6669,
        6697,
        10080,
    )
)
LOG = getLogger(__name__)


def create_listening_socket(
    attempts: int = 10,
    port: int = 0,
    remote: bool = False,
) -> socket:
    """Create listening socket. Search for an open socket if needed and configure the
    socket. If the specified port is unavailable an OSError or PermissionError will be
    raised. If an available port cannot be found a RuntimeError will be raised.

    Args:
        attempts: Number of attempts to configure the socket.
        port: Port to listen on. Use 0 for system assigned port.
        remote: Accept all (non-local) incoming connections.

    Returns:
        A listening socket.
    """
    assert attempts > 0
    assert 0 <= port <= 65535

    if port in BLOCKED_PORTS or 0 < port <= 1024:
        raise ValueError("Cannot bind to blocked ports or ports <= 1024")

    for remaining in reversed(range(attempts)):
        sock = socket()
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        # attempt to bind/listen
        try:
            sock.bind(("0.0.0.0" if remote else "127.0.0.1", port))
            sock.listen(5)
            # put socket in non-blocking mode
            sock.settimeout(0)
        except (OSError, PermissionError) as exc:
            sock.close()
            if remaining > 0:
                LOG.debug("%s: %s", type(exc).__name__, exc)
                sleep(0.1)
                continue
            raise
        # avoid blocked ports
        if port == 0 and sock.getsockname()[1] in BLOCKED_PORTS:
            LOG.debug("bound to blocked port, retrying...")
            sock.close()
            continue
        # success
        break
    else:
        raise RuntimeError("Could not find available port")
    return sock


class Sapphire:
    __slots__ = ("_auto_close", "_max_workers", "_socket", "scheme", "timeout")

    def __init__(
        self,
        allow_remote: bool = False,
        auto_close: int = -1,
        certs: CertificateBundle | None = None,
        max_workers: int = 10,
        port: int = 0,
        timeout: int = 60,
    ) -> None:
        assert timeout >= 0
        self._auto_close = auto_close  # call 'window.close()' on 4xx error pages
        self._max_workers = max_workers  # limit worker threads
        sock = create_listening_socket(port=port, remote=allow_remote)
        # enable https if certificates are provided
        if certs:
            context = SSLContext(PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certs.host, certs.key)
            self._socket: socket | SSLSocket = context.wrap_socket(
                sock, server_side=True
            )
            self.scheme = "https"
        else:
            self._socket = sock
            self.scheme = "http"
        self.timeout = timeout

    def __enter__(self) -> Sapphire:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def clear_backlog(self, timeout: float = 10) -> bool:
        """Remove all pending connections from backlog. This should only be
        called when there isn't anything actively trying to connect.

        Args:
            timeout: Maximum number of seconds to run.

        Returns:
            True if all connections are cleared from the backlog otherwise False.
        """
        # this assumes the socket is in non-blocking mode
        assert not self._socket.getblocking()
        LOG.debug("clearing socket backlog")
        deadline = perf_counter() + timeout
        while True:
            try:
                self._socket.accept()[0].close()
            except BlockingIOError:
                # no remaining pending connections
                break
            except OSError as exc:
                LOG.debug("Error closing socket: %r", exc)
            else:
                LOG.debug("pending socket closed")
            # if this fires something is likely actively trying to connect
            if deadline <= perf_counter():
                return False
            # avoid hogging the cpu
            sleep(0.1)
        return True

    def close(self) -> None:
        """Close listening server socket.

        Args:
            None

        Returns:
            None
        """
        self._socket.close()

    @property
    def port(self) -> int:
        """Port number of listening socket.

        Args:
            None

        Returns:
            Listening port number.
        """
        return cast(int, self._socket.getsockname()[1])

    def serve_path(
        self,
        path: Path,
        continue_cb: Callable[[], bool] | None = None,
        forever: bool = False,
        required_files: Iterable[str] | None = None,
        server_map: ServerMap | None = None,
    ) -> tuple[Served, Mapping[str, Path]]:
        """Serve files in path.

        The status codes include:
            - Served.ALL: All required files were served
            - Served.NONE: No files were served
            - Served.REQUEST: Some files were requested

        Args:
            path: Directory to use as wwwroot.
            continue_cb: A callback that can be used to exit the serve loop.
                This must be a callable that returns a bool.
            forever: Continue to handle requests even after all files have been served.
                This is meant to be used with continue_cb.
            required_files: Files that need to be served in order to exit the
                serve loop.
            server_map: Map of server includes, dynamic requests and redirects.

        Returns:
            Status code and files served.
        """
        assert isinstance(path, Path)
        assert self.timeout >= 0
        LOG.debug("serving '%s' (forever=%r, timeout=%d)", path, forever, self.timeout)
        job = Job(
            path,
            auto_close=self._auto_close,
            forever=forever,
            required_files=required_files,
            server_map=server_map,
        )
        with ConnectionManager(job, self._socket, limit=self._max_workers) as mgr:
            timed_out = not mgr.serve(self.timeout, continue_cb=continue_cb)
        LOG.debug("%s, timed out: %r", job.status, timed_out)
        return (Served.TIMEOUT if timed_out else job.status, job.served)

    @classmethod
    def main(cls, args: Namespace) -> None:
        try:
            with cls(
                allow_remote=args.remote, port=args.port, timeout=args.timeout
            ) as serv:
                LOG.info(
                    "Serving '%s' @ http://%s:%d/",
                    args.path.resolve(),
                    gethostname() if args.remote else "127.0.0.1",
                    serv.port,
                )
                serv.serve_path(args.path, forever=True)
        except KeyboardInterrupt:
            LOG.warning("Ctrl+C detected. Shutting down...")
