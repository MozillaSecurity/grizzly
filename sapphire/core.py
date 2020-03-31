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
import mimetypes
import os
import random
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import traceback

from .sapphire_job import SapphireJob
from .sapphire_worker import SapphireWorker
from .server_map import Resource
from .status_codes import SERVED_ALL, SERVED_NONE, SERVED_TIMEOUT


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


LOG = logging.getLogger("sapphire")


class Sapphire(object):
    ABORT_ON_THREAD_ERROR = False
    CLOSE_CLIENT_ERROR = None  # used to automatically close client error (4XX code) pages
    DEFAULT_REQUEST_LIMIT = 0x1000  # 4KB
    DEFAULT_TX_SIZE = 0x10000  # 64KB
    SHUTDOWN_DELAY = 0.25  # allow extra time before closing socket if needed
    WORKER_POOL_LIMIT = 10

    _request = re.compile(b"^GET\\s/(?P<request>\\S*)\\sHTTP/1")

    def __init__(self, allow_remote=False, port=None, timeout=60):
        self._socket = Sapphire._create_listening_socket(allow_remote, port)
        self._timeout = None
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @staticmethod
    def _200_header(c_length, c_type):
        return "HTTP/1.1 200 OK\r\n" \
               "Cache-Control: max-age=0, no-cache\r\n" \
               "Content-Length: %s\r\n" \
               "Content-Type: %s\r\n" \
               "Connection: close\r\n\r\n" % (c_length, c_type)

    @staticmethod
    def _307_redirect(redirct_to):
        return "HTTP/1.1 307 Temporary Redirect\r\n" \
               "Location: %s\r\n" \
               "Connection: close\r\n\r\n" % (redirct_to,)

    @staticmethod
    def _4xx_page(code, hdr_msg):
        assert 399 < code < 500
        if Sapphire.CLOSE_CLIENT_ERROR is not None:
            assert Sapphire.CLOSE_CLIENT_ERROR >= 0
            close_timeout = Sapphire.CLOSE_CLIENT_ERROR
            content = "<script>window.setTimeout(window.close, %d)</script>\n" \
                      "<body style=\"background-color:#ffffe0\">\n" \
                      "<h3>%d! - Calling window.close() in %0.1f seconds</h3>\n" \
                      "</body>\n" % (int(close_timeout * 1000), code, close_timeout)
        else:
            content = "<h3>%d!</h3>" % code
        return "HTTP/1.1 %d %s\r\n" \
               "Content-Length: %d\r\n" \
               "Content-Type: text/html\r\n" \
               "Connection: close\r\n\r\n%s" % (code, hdr_msg, len(content), content)

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

    @staticmethod
    def _handle_request(conn, serv_job):
        finish_job = False  # call finish() on return
        try:
            # receive all the incoming data
            raw_request = conn.recv(Sapphire.DEFAULT_REQUEST_LIMIT)
            if not raw_request:
                LOG.debug("raw_request was empty")
                serv_job.accepting.set()
                return

            request = Sapphire._request.match(raw_request)
            if request is None:
                serv_job.accepting.set()
                conn.sendall(Sapphire._4xx_page(400, "Bad Request").encode("ascii"))
                LOG.debug(
                    "400 request length %d (%d to go)",
                    len(raw_request),
                    serv_job.pending_files())
                return

            request = request.group("request").decode("ascii")
            LOG.debug("check_request(%r)", request)
            resource = serv_job.check_request(request)
            if resource is None:
                LOG.debug("resource is None")  # 404
            elif resource.type in (Resource.URL_FILE, Resource.URL_INCLUDE):
                finish_job = serv_job.remove_pending(resource.target)
            elif resource.type == Resource.URL_REDIRECT:
                finish_job = serv_job.remove_pending(request)

            if finish_job and serv_job.forever:
                LOG.debug("serv_job.forever is set, resetting finish_job")
                finish_job = False

            if not finish_job:
                serv_job.accepting.set()
            else:
                LOG.debug("expecting to finish")

            if resource is None:
                conn.sendall(Sapphire._4xx_page(404, "Not Found").encode("ascii"))
                LOG.debug("404 %r (%d to go)", request, serv_job.pending_files())
                return
            if resource.type in (Resource.URL_FILE, Resource.URL_INCLUDE):
                LOG.debug("target %r", resource.target)
                if not os.path.isfile(resource.target):
                    conn.sendall(Sapphire._4xx_page(404, "Not Found").encode("ascii"))
                    LOG.debug("404 %r (%d to go)", request, serv_job.pending_files())
                    return
                if serv_job.is_forbidden(resource.target):
                    # NOTE: this does info leak if files exist on disk.
                    # We could replace 403 with 404 if it turns out we care but this
                    # is meant to run locally and only be accessible from localhost
                    conn.sendall(Sapphire._4xx_page(403, "Forbidden").encode("ascii"))
                    LOG.debug("403 %r (%d to go)", request, serv_job.pending_files())
                    return
            elif resource.type == Resource.URL_REDIRECT:
                conn.sendall(Sapphire._307_redirect(resource.target).encode("ascii"))
                LOG.debug(
                    "307 %r -> %r (%d to go)",
                    request,
                    resource.target,
                    serv_job.pending_files())
                return
            elif resource.type == Resource.URL_DYNAMIC:
                data = resource.target()
                if not isinstance(data, bytes):
                    LOG.debug("dynamic request: %r", request)
                    raise TypeError("dynamic request callback must return 'bytes'")
                conn.sendall(Sapphire._200_header(len(data), resource.mime).encode("ascii"))
                conn.sendall(data)
                LOG.debug("200 %r (dynamic request)", request)
                return
            else:
                raise RuntimeError("Unknown resource type %r" % resource.type)

            # at this point we know "resource.target" maps to a file on disk
            # default to "application/octet-stream"
            c_type = mimetypes.guess_type(resource.target)[0] or "application/octet-stream"
            # serve the file
            data_size = os.stat(resource.target).st_size
            LOG.debug("sending file: %s bytes", format(data_size, ","))
            with open(resource.target, "rb") as in_fp:
                conn.sendall(Sapphire._200_header(data_size, c_type).encode("ascii"))
                offset = 0
                while offset < data_size:
                    conn.sendall(in_fp.read(Sapphire.DEFAULT_TX_SIZE))
                    offset = in_fp.tell()
            LOG.debug("200 %r (%d to go)", resource.target, serv_job.pending_files())
            serv_job.increment_served(resource.target)

        except (socket.timeout, socket.error):
            exc_type, exc_obj, exc_tb = sys.exc_info()
            LOG.debug("%s: %r (line %d)", exc_type.__name__, exc_obj, exc_tb.tb_lineno)
            if not finish_job:
                serv_job.accepting.set()

        except Exception:  # pylint: disable=broad-except
            serv_job.exceptions.put(sys.exc_info())

        finally:
            conn.close()
            if finish_job:
                serv_job.finish()
            serv_job.worker_complete.set()

    @staticmethod
    def _client_listener(serv_sock, serv_job):
        worker_pool = list()
        pool_size = 0

        LOG.debug("starting client_listener")
        try:
            while not serv_job.is_complete():
                if not serv_job.accepting.wait(0.05):
                    continue
                try:
                    worker = SapphireWorker.launch(serv_sock, serv_job)
                    if worker is not None:
                        worker_pool.append(worker)
                        pool_size += 1
                except threading.ThreadError:
                    LOG.warning(
                        "ThreadError! pool size: %d, total active threads: %d",
                        pool_size,
                        threading.active_count())
                    if Sapphire.ABORT_ON_THREAD_ERROR:
                        raise
                    # wait for system resources to free up
                    time.sleep(0.1)
                # manage worker pool
                if pool_size >= Sapphire.WORKER_POOL_LIMIT:
                    LOG.debug("active pool size: %d, waiting for worker to finish...", pool_size)
                    serv_job.worker_complete.wait()
                    serv_job.worker_complete.clear()
                    # remove complete workers
                    LOG.debug("trimming worker pool")
                    # sometimes the thread that triggered the event doesn't quite cleanup in time
                    # so add a retry (10x with a 0.1 second sleep on failure)
                    for _ in range(10, 0, -1):
                        worker_pool = list(w for w in worker_pool if not w.done)
                        pool_size = len(worker_pool)
                        if pool_size < Sapphire.WORKER_POOL_LIMIT:
                            break
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("Failed to trim worker pool!")
                    LOG.debug("trimmed worker pool (size: %d)", pool_size)
        finally:
            LOG.debug("shutting down and cleaning up workers")
            deadline = time.time() + Sapphire.SHUTDOWN_DELAY
            for worker in worker_pool:
                # avoid cutting off connections
                while not worker.done and time.time() < deadline:
                    LOG.debug("delaying shutdown...")
                    time.sleep(0.01)
                worker.close()

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
            raise TypeError("continue_cb must be of type 'function'")
        if not os.path.isdir(os.path.abspath(path)):
            raise IOError("%r does not exist" % path)

        job = SapphireJob(path, forever=forever, optional_files=optional_files, server_map=server_map)

        if not job.pending_files():
            job.finish()
            return SERVED_NONE, list()

        # create the client listener thread to handle incoming requests
        listener = threading.Thread(
            target=self._client_listener,
            args=(self._socket, job))

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

        # served files should be relative to the www root, since that path could be a temporary
        # path created by serve_testcase()
        served_files = {os.path.relpath(file, path) for file in job._served.files.keys()}

        return status, served_files  # pylint: disable=protected-access

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


def main():
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
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        parser.error("Invalid path to use as wwwroot")

    try:
        with Sapphire(allow_remote=args.remote, port=args.port, timeout=args.timeout) as serv:
            LOG.info(
                "Serving %r @ http://%s:%d/",
                os.path.abspath(args.path),
                socket.gethostname() if args.remote else "127.0.0.1",
                serv.get_port())
        status = serv.serve_path(args.path)
        if status == SERVED_ALL:
            LOG.info("All test case content was served")
        else:
            LOG.warning("Failed to serve all test content")
    except KeyboardInterrupt:
        LOG.warning("Ctrl+C detected. Shutting down...")
