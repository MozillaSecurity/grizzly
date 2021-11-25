# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server
"""
from errno import EADDRINUSE
from logging import getLogger
from pathlib import Path
from random import randint
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, gethostname, socket
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
        self, allow_remote=False, auto_close=-1, max_workers=10, port=None, timeout=60
    ):
        self._auto_close = auto_close  # call 'window.close()' on 4xx error pages
        self._max_workers = max_workers  # limit worker threads
        self._socket = Sapphire._create_listening_socket(allow_remote, port)
        self._timeout = None
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @classmethod
    def _create_listening_socket(cls, remote, port=None, retries=20):
        """Create listening socket. Search for an open socket if needed and
        and configure the socket. If a specific port is unavailable or no
        available ports can be found socket.error will be raised.

        Args:
            remote (bool): Accept all (non-local) incoming connections.
            port (int): Port to listen on. If None is given a random port will
                        be used.
            retries (int): Number of attempts to configure the socket.

        Returns:
            socket: A listening socket.
        """
        addr = "0.0.0.0" if remote else "127.0.0.1"
        for retry in reversed(range(retries)):
            sock = None
            try:
                sock = socket(AF_INET, SOCK_STREAM)
                sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                sock.settimeout(cls.LISTEN_TIMEOUT)
                # find an unused port and avoid blocked ports
                # see: searchfox.org/mozilla-central/source/netwerk/base/nsIOService.cpp
                sock.bind((addr, port or randint(0x2000, 0xFFFF)))
                sock.listen(5)
            except OSError as soc_e:
                if sock is not None:
                    sock.close()
                if retry > 1 and soc_e.errno in (EADDRINUSE, 10013):
                    sleep(0.1)
                    continue
                raise
            break
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
        if self._socket is not None:
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
            path (str): Directory to use as wwwroot.
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
        path = Path(path)
        LOG.debug("serving %r (forever=%r)", str(path), forever)
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
        if not value:
            self._timeout = 0
        else:
            self._timeout = max(value, 1)

    @classmethod
    def main(cls, args):
        try:
            with cls(
                allow_remote=args.remote, port=args.port, timeout=args.timeout
            ) as serv:
                LOG.info(
                    "Serving %r @ http://%s:%d/",
                    str(Path(args.path).resolve()),
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
