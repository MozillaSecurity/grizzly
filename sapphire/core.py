# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server
"""
from errno import EADDRINUSE
from logging import getLogger
from os.path import abspath
from random import randint
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from socket import error as sock_error, gethostname, socket
from time import sleep

from .job import Job, SERVED_ALL, SERVED_NONE, SERVED_TIMEOUT
from .connection_manager import ConnectionManager


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


LOG = getLogger(__name__)


class Sapphire(object):
    __slots__ = ("_auto_close", "_max_workers", "_socket", "_timeout")

    def __init__(self, allow_remote=False, auto_close=-1, max_workers=10, port=None, timeout=60):
        self._auto_close = auto_close  # call 'window.close()' on 4xx error pages
        self._max_workers = max_workers  # limit worker threads
        self._socket = Sapphire._create_listening_socket(allow_remote, port)
        self._timeout = None
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @staticmethod
    def _create_listening_socket(remote, port=None, retries=20):
        """Create listening socket. Search for an open socket if needed and
        and configure the socket. If a specific port is unavailable or no
        available ports can be found a socket.error will be raised.

        Args:
            remote (bool): Accept all (non-local) incoming connections.
            port (int): Port to listen on. If None is given a random port will
                        be used.
            retries (int): Number of attempts to the socket.

        Returns:
            socket: A listening socket.
        """
        addr = "0.0.0.0" if remote else "127.0.0.1"
        for retry in reversed(range(retries)):
            sock = None
            try:
                sock = socket(AF_INET, SOCK_STREAM)
                sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                sock.settimeout(0.25)
                # find an unused port and avoid blocked ports
                # see: dxr.mozilla.org/mozilla-central/source/netwerk/base/nsIOService.cpp
                sock.bind((addr, port or randint(0x2000, 0xFFFF)))
                sock.listen(5)
            except (OSError, sock_error) as soc_e:
                if sock is not None:
                    sock.close()
                if retry > 1 and soc_e.errno in (EADDRINUSE, 10013):
                    sleep(0.1)
                    continue
                raise
            break
        return sock

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

    def serve_path(self, path, continue_cb=None, forever=False, optional_files=None, server_map=None):
        """Serve files in path. On completion a list served files and a status
        code will be returned.
        The status codes include:
            - SERVED_ALL: All files excluding files in optional_files were served
            - SERVED_NONE: No files were served
            - SERVED_REQUEST: Some files were requested

        Args:
            path (str): Directory to use a wwwroot.
            continue_cb (str): A callback that can be used to exit the serve loop.
                               This should a function that returns a bool.
            forever (bool): Continue to handle requests even after all files have
                            been served. This is meant to be used with continue_cb.
            optional_files (list): Files that do not need to be served in order
                                   to exit the serve loop.
            server_map (ServerMap):
        Returns:
            tuple: Files served and status code
        """
        LOG.debug("serving %r (forever=%r)", path, forever)
        job = Job(
            path,
            auto_close=self._auto_close,
            forever=forever,
            optional_files=optional_files,
            server_map=server_map)
        if not job.pending:
            job.finish()
            LOG.debug("nothing to serve")
            return (SERVED_NONE, tuple())
        with ConnectionManager(job, self._socket, self._max_workers) as loadmgr:
            was_timeout = not loadmgr.wait(self.timeout, continue_cb=continue_cb)
        LOG.debug("status: %r, timeout: %r", job.status, was_timeout)
        return (SERVED_TIMEOUT if was_timeout else job.status, tuple(job.served))

    @property
    def timeout(self):
        """The amount of time that must pass before exit the serve loop and
        indicating a timeout.

        Args:
            None

        Returns:
            int: Timeout in seconds.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        """The amount of time that must pass before exit the serve loop and
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
            with cls(allow_remote=args.remote, port=args.port, timeout=args.timeout) as serv:
                LOG.info(
                    "Serving %r @ http://%s:%d/",
                    abspath(args.path),
                    gethostname() if args.remote else "127.0.0.1",
                    serv.port)
                status = serv.serve_path(args.path)[0]
            if status == SERVED_ALL:
                LOG.info("All test case content was served")
            else:
                LOG.warning("Failed to serve all test content")
        except KeyboardInterrupt:
            LOG.warning("Ctrl+C detected. Shutting down...")
