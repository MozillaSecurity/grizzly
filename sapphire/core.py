# coding=utf-8
"""
Sapphire HTTP server
"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import errno
import logging
import os
import random
import shutil
import socket
import tempfile
import threading
import time
import traceback

from .sapphire_job import SapphireJob
from .status_codes import SERVED_ALL, SERVED_NONE, SERVED_TIMEOUT


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


LOG = logging.getLogger("sapphire")


class Sapphire(object):
    ABORT_ON_THREAD_ERROR = False
    SHUTDOWN_DELAY = 0.25  # allow extra time before closing socket if needed

    def __init__(self, allow_remote=False, auto_close=-1, max_workers=10, port=None, timeout=60):
        assert max_workers > 0
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
    def _create_listening_socket(allow_remote, requested_port):
        # The intention of this function is to contain the socket creation code
        # along with all the searching and retrying code. If a specific port is requested
        # and it is not available a socket.error will be raised.
        while True:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(0.25)
                # find an unused port and avoid blocked ports
                # see: dxr.mozilla.org/mozilla-central/source/netwerk/base/nsIOService.cpp
                port = random.randint(0x2000, 0xFFFF) if requested_port is None else requested_port
                sock.bind(("0.0.0.0" if allow_remote else "127.0.0.1", port))
                sock.listen(5)
            except (OSError, socket.error) as soc_e:
                if sock is not None:
                    sock.close()
                # try another port if a specific port was not requested
                if requested_port is None and soc_e.errno in (errno.EADDRINUSE, 10013):
                    continue
                raise
            break
        return sock

    def close(self):
        """
        close()

        This function closes the listening server socket if it is open.
        """
        if self._socket is not None:
            self._socket.close()

    @property
    def port(self):
        """
        port -> int

        returns the port number the socket is listening on
        """

        return self._socket.getsockname()[1]

    def serve_path(self, path, continue_cb=None, forever=False, optional_files=None, server_map=None):
        """
        serve_path() -> tuple
        path is the directory that will be used as wwwroot. The callback continue_cb should
        be a function that returns True or False. If continue_cb is specified and returns False
        the server serve loop will exit. optional_files is list of files that do not need to be
        served in order to exit the serve loop.

        returns a tuple (server status, files served)
        server status is an int:
        - SERVED_ALL: All files excluding files int the optional_files list were served
        - SERVED_NONE: No files were served
        - SERVED_REQUEST: Some files were requested
        files served is a list of the files that were served
        """

        LOG.debug("serve_path: %s", path)
        LOG.debug("serving forever: %r", forever)

        if continue_cb is not None and not callable(continue_cb):
            raise TypeError("continue_cb must be callable")
        if not os.path.isdir(os.path.abspath(path)):
            raise IOError("%r does not exist" % (path,))

        job = SapphireJob(
            path,
            auto_close=self._auto_close,
            forever=forever,
            optional_files=optional_files,
            server_map=server_map)

        if not job.pending:
            job.finish()
            return SERVED_NONE, tuple()

        # create the client listener thread to handle incoming requests
        listener = threading.Thread(
            target=job.client_listener,
            args=(self._socket, job, self._max_workers),
            kwargs={"raise_thread_error": self.ABORT_ON_THREAD_ERROR, "shutdown_delay": 0})

        # launch listener thread and handle thread errors
        # thread errors can be due to low system resources while fuzzing
        tries = 10
        while True:
            try:
                listener.start()
            except threading.ThreadError:
                LOG.warning(
                    "ThreadError launching listener, active threads: %d",
                    threading.active_count())
                tries -= 1
                if tries < 1:
                    raise
                time.sleep(0.1)  # wait for system resources to free up
            if self._timeout:
                exp_time = time.time() + self._timeout
            else:
                exp_time = None
                LOG.warning("timeout is not set!")
            break

        status = None
        try:
            # it is important to keep this loop fast because it can limit
            # the total iteration rate of Grizzly
            while not job.is_complete(wait=0.5):
                # check for a timeout
                if exp_time is not None and exp_time <= time.time():
                    status = SERVED_TIMEOUT
                    break
                # check if callback returns False
                if continue_cb is not None and not continue_cb():
                    break
            # check for exceptions from workers
            if not job.exceptions.empty():
                exc_type, exc_obj, exc_tb = job.exceptions.get()
                LOG.error(
                    "Sapphire worker exception:\n%s",
                    "".join(traceback.format_exception(exc_type, exc_obj, exc_tb)))
                raise exc_obj  # re-raise exception from worker
        finally:
            if status is None:
                status = job.status
            job.finish()
            if listener.ident is not None:
                listener.join()

        return status, job.served

    def serve_testcase(self, testcase, continue_cb=None, forever=False, working_path=None, server_map=None):
        """
        serve_testcase() -> tuple
        testcase is the Grizzly TestCase to serve. The callback continue_cb should
        be a function that returns True or False. If continue_cb is specified and returns False
        the server serve loop will exit. working_path is where the testcase will be unpacked
        temporary.

        returns a tuple (server status, files served)
        see serve_path() for more info
        """
        LOG.debug("serve_testcase() called")
        wwwdir = tempfile.mkdtemp(prefix="sphr_test_", dir=working_path)
        try:
            testcase.dump(wwwdir)
            serve_start = time.time()
            result = self.serve_path(
                wwwdir,
                continue_cb=continue_cb,
                forever=forever,
                optional_files=tuple(testcase.optional),
                server_map=server_map)
            testcase.duration = time.time() - serve_start
            return result
        finally:
            # remove test case working directory
            shutil.rmtree(wwwdir, ignore_errors=True)

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        if not value:
            self._timeout = 0
        else:
            self._timeout = max(value, 1)

    @classmethod
    def main(cls, argv=None):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "path",
            help="Specify a directory to act as wwwroot")
        parser.add_argument(
            "--port", type=int,
            help="Specify a port to bind to (default: random)")
        parser.add_argument(
            "--remote", action="store_true",
            help="Allow connections from addresses other than 127.0.0.1")
        parser.add_argument(
            "--timeout", type=int,
            help="Duration in seconds to serve before exiting, 0 run until served (default: 0)")
        args = parser.parse_args(argv)

        if not os.path.isdir(args.path):
            parser.error("Path does not exist %r" % (args.path,))

        try:
            with cls(allow_remote=args.remote, port=args.port, timeout=args.timeout) as serv:
                LOG.info(
                    "Serving %r @ http://%s:%d/",
                    os.path.abspath(args.path),
                    socket.gethostname() if args.remote else "127.0.0.1",
                    serv.port)
                status = serv.serve_path(args.path)[0]
            if status == SERVED_ALL:
                LOG.info("All test case content was served")
            else:
                LOG.warning("Failed to serve all test content")
        except KeyboardInterrupt:
            LOG.warning("Ctrl+C detected. Shutting down...")
