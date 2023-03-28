# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server
"""
from logging import getLogger
from pathlib import Path
from socket import SO_REUSEADDR, SOL_SOCKET, gethostname, socket
from time import sleep, time

from .connection_manager import ConnectionManager
from .job import Job, Served

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


LOG = getLogger(__name__)


class Sapphire:
    LISTEN_TIMEOUT = 0.25

    __slots__ = ("_auto_close", "_max_workers", "_socket", "_timeout")

    def __init__(
        self, allow_remote=False, auto_close=-1, max_workers=10, port=0, timeout=60
    ):
        self._auto_close = auto_close  # call 'window.close()' on 4xx error pages
        self._max_workers = max_workers  # limit worker threads
        self._socket = Sapphire._create_listening_socket(allow_remote, port=port)
        self._timeout = None
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @staticmethod
    def _create_listening_socket(remote, port=0, attempts=10, timeout=LISTEN_TIMEOUT):
        """Create listening socket. Search for an open socket if needed and
        and configure the socket. If a specific port is unavailable or no
        available ports can be found socket.error will be raised.

        Args:
            remote (bool): Accept all (non-local) incoming connections.
            port (int): Port to listen on. Use 0 for system assigned port.
            attempts (int): Number of attempts to configure the socket.
            timeout (float): Used to set socket timeout.

        Returns:
            socket: A listening socket.
        """
        assert attempts > 0
        assert port >= 0
        assert timeout > 0

        # see: searchfox.org/mozilla-central/source/netwerk/base/nsIOService.cpp
        # include ports above 1024
        blocked_ports = (
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

        for remaining in reversed(range(attempts)):
            sock = socket()
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            # attempt to bind/listen
            try:
                sock.bind(("0.0.0.0" if remote else "127.0.0.1", port))
                sock.listen(5)
            except (OSError, PermissionError) as exc:
                sock.close()
                if remaining > 0:
                    LOG.debug("%s: %s", type(exc).__name__, exc)
                    sleep(0.1)
                    continue
                raise
            # avoid blocked ports
            if port == 0 and sock.getsockname()[1] in blocked_ports:
                LOG.debug("bound to blocked port, retrying...")
                sock.close()
                continue
            # success
            break
        else:
            raise RuntimeError("Could not find available port")
        return sock

    def clear_backlog(self):
        """Remove all pending connections from backlog. This should only be
        called when there isn't anything actively trying to connect.

        Args:
            None

        Returns:
            None
        """
        LOG.debug("clearing socket backlog")
        self._socket.settimeout(0)
        deadline = time() + 10
        while True:
            try:
                self._socket.accept()[0].close()
            except BlockingIOError:
                break
            except OSError as exc:
                LOG.debug("Error closing socket: %r", exc)
            else:
                LOG.debug("pending socket closed")
            # if this fires something is likely actively trying to connect
            assert deadline > time()
        self._socket.settimeout(self.LISTEN_TIMEOUT)

    def close(self):
        """Close listening server socket.

        Args:
            None

        Returns:
            None
        """
        self._socket.close()

    @property
    def port(self):
        """Port number of listening socket.

        Args:
            None

        Returns:
            int: Listening port number.
        """
        return self._socket.getsockname()[1]

    def serve_path(
        self,
        path,
        continue_cb=None,
        forever=False,
        optional_files=None,
        server_map=None,
    ):
        """Serve files in path. On completion a list served files and a status
        code will be returned.
        The status codes include:
            - Served.ALL: All files excluding files in optional_files were served
            - Served.NONE: No files were served
            - Served.REQUEST: Some files were requested

        Args:
            path (Path): Directory to use as wwwroot.
            continue_cb (callable): A callback that can be used to exit the serve loop.
                                    This must be a callable that returns a bool.
            forever (bool): Continue to handle requests even after all files have
                            been served. This is meant to be used with continue_cb.
            optional_files (list(str)): Files that do not need to be served in order
                                        to exit the serve loop.
            server_map (ServerMap):

        Returns:
            tuple(int, tuple(str)): Status code and files served.
        """
        assert isinstance(path, Path)
        LOG.debug("serving '%s' (forever=%r, timeout=%r)", path, forever, self.timeout)
        job = Job(
            path,
            auto_close=self._auto_close,
            forever=forever,
            optional_files=optional_files,
            server_map=server_map,
        )
        if not job.pending:
            job.finish()
            LOG.debug("nothing to serve")
            return (Served.NONE, tuple())
        with ConnectionManager(job, self._socket, self._max_workers) as loadmgr:
            was_timeout = not loadmgr.wait(self.timeout, continue_cb=continue_cb)
        LOG.debug("%s, timeout: %r", job.status, was_timeout)
        return (Served.TIMEOUT if was_timeout else job.status, tuple(job.served))

    @property
    def timeout(self):
        """The amount of time that must pass before exiting the serve loop and
        indicating a timeout.

        Args:
            None

        Returns:
            int: Timeout in seconds.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        """The amount of time that must pass before exiting the serve loop and
        indicating a timeout.

        Args:
            value (int): Timeout in seconds.

        Returns:
            None
        """
        assert value >= 0
        self._timeout = value

    @classmethod
    def main(cls, args):
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
                status = serv.serve_path(args.path)[0]
            if status == Served.ALL:
                LOG.info("All test case content was served")
            else:
                LOG.warning("Failed to serve all test content")
        except KeyboardInterrupt:
            LOG.warning("Ctrl+C detected. Shutting down...")
