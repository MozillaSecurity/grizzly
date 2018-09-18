#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import errno
import logging
import mimetypes
import os
try: # py 2-3 compatibility
    from Queue import Queue, Empty as QueueEmpty
except ImportError:
    from queue import Queue, Empty as QueueEmpty
import random
import re
import socket
import sys
import threading
import time

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

log = logging.getLogger("sapphire") # pylint: disable=invalid-name

# status codes
SERVED_ALL = 0      # all expected requests for required files have been received
SERVED_NONE = 1     # no requests for required files have been received
SERVED_REQUEST = 2  # some requests for required files have been received
SERVED_TIMEOUT = 3  # timeout occurred

class ServeJob(object):
    URL_DYNAMIC = "dynamic"
    URL_INCLUDE = "include"
    URL_REDIRECT = "redirect"

    def __init__(self, base_path, dynamic_map, include_map, redirect_map, optional_files=None):
        assert isinstance(dynamic_map, dict)
        assert isinstance(include_map, dict)
        assert isinstance(redirect_map, dict)
        self._complete = threading.Event()
        self.base_path = os.path.abspath(base_path)  # wwwroot
        self.exceptions = Queue()
        self.f_queue = {
            "files": set(),  # files that need to be served
            "lock": threading.Lock()}
        self.f_served = {
            "files": dict(),  # files that have been served
            "lock": threading.Lock()}
        self.initial_queue_size = 0
        self.url_map = {
            "dynamic": dynamic_map,  # paths that map to a callback
            "include": include_map,  # extra paths to serve from
            "redirect": redirect_map}
        self.worker_complete = threading.Event()

        self._build_queue(optional_files)


    def _build_queue(self, optional_files):
        # build file list to track files that must be served
        for d_name, _, filenames in os.walk(self.base_path, followlinks=False):
            for f_name in filenames:
                file_path = os.path.abspath(os.path.join(d_name, f_name))
                # do not add optional files to queue of required files
                if optional_files and f_name in optional_files:
                    log.debug('optional: %r', f_name)
                    continue
                with self.f_queue["lock"]:
                    self.f_queue["files"].add(file_path)
                log.debug('required: %r', f_name)

        for redirect, (target, required) in self.url_map["redirect"].items():
            if required:
                with self.f_queue["lock"]:
                    self.f_queue["files"].add(redirect)
            log.debug('%s: %r -> %r', 'required' if required else 'optional', redirect, target)

        with self.f_queue["lock"]:
            self.initial_queue_size = len(self.f_queue["files"])
        log.debug('sapphire has %d files required to serve', self.initial_queue_size)


    def check_url(self, request):
        log.debug("check_url with request %r", request)
        try:
            return self.URL_REDIRECT, self.url_map[self.URL_REDIRECT][request]
        except KeyError:
            pass

        try:
            return self.URL_DYNAMIC, self.url_map[self.URL_DYNAMIC][request]
        except KeyError:
            pass

        if self.url_map[self.URL_INCLUDE]:
            last_split = 0
            check_includes = len([x for x in self.url_map[self.URL_INCLUDE].keys() if x != ""])
            while check_includes:
                split_req = request.rsplit("/", last_split)
                if len(split_req) != last_split + 1:
                    break
                inc = split_req[0]
                url_extra = split_req[1:]

                log.debug("looking up %r in include map", inc)
                try:
                    fpath = "/".join([self.url_map[self.URL_INCLUDE][inc]] + url_extra)
                    return self.URL_INCLUDE, fpath
                except KeyError:
                    log.debug("include map does not contain %r", inc)
                last_split += 1

            # check if this is a nested directory in a directory mounted at '/'
            try:
                log.debug("checking include map at '/'")
                fpath = os.path.join(self.url_map[self.URL_INCLUDE][""], request.lstrip('/'))
                return self.URL_INCLUDE, fpath
            except KeyError:
                log.debug("include map does not contain an entry at '/'")

        return None


    def get_status(self):
        with self.f_queue["lock"]:
            queue_size = len(self.f_queue["files"])
        if self.initial_queue_size > 0:
            if queue_size == 0:
                return SERVED_ALL
            elif queue_size < self.initial_queue_size:
                return SERVED_REQUEST
        return SERVED_NONE


    def finish(self):
        self._complete.set()


    def is_complete(self):
        return self._complete.is_set()


    def is_forbidden(self, target_file):
        target_file = os.path.abspath(target_file)
        if not target_file.startswith(self.base_path):  # does the file live somewhere in wwwroot
            for inc_path in self.url_map[self.URL_INCLUDE].values():
                if target_file.startswith(inc_path):
                    return False  # this is a valid include path
            return True  # this is NOT a valid include path
        return False  # this is a valid path


    def pending_files(self):
        with self.f_queue["lock"]:
            return len(self.f_queue["files"])


    def remove_queue_file(self, file_name):
        # only return True when the last item is removed (not before or after)
        with self.f_queue["lock"]:
            if not self.f_queue["files"]:
                return False
            self.f_queue["files"].discard(file_name)
            return not self.f_queue["files"]


class Sapphire(object):
    ABORT_ON_THREAD_ERROR = False
    CLOSE_CLIENT_ERROR = None  # used to automatically close client error (4XX code) pages
    DEFAULT_REQUEST_LIMIT = 0x1000  # 4KB
    DEFAULT_TX_SIZE = 0x10000  # 64KB
    DEFAULT_WORKER_POOL_SIZE = 20

    _request = re.compile(b"^GET\\s/(?P<request>\\S*)\\sHTTP/1")


    def __init__(self, allow_remote=False, port=None, timeout=60):
        self._dr_map = {}
        self._include_map = {}
        self._redirect_map = {}
        self._server_timeout = max(timeout, 1) if timeout else None  # set the minimum to 1 second
        self._socket = Sapphire._create_listening_socket(allow_remote, port)


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
               "Connection: close\r\n\r\n" % (redirct_to)


    @staticmethod
    def _4xx_page(code, hdr_msg):
        assert code < 500 and code > 399
        assert hdr_msg is not None

        close_timeout = Sapphire.CLOSE_CLIENT_ERROR
        assert close_timeout is None or close_timeout > -1

        page = ["HTTP/1.1 %d %s\r\n" % (code, hdr_msg)]
        if close_timeout is not None:
            content = "<script>window.setTimeout(window.close, %d)</script>\n" \
                      "<body style=\"background-color:#ffffe0\">\n" \
                      "<h3>%d! - Calling window.close() in %0.1f seconds</h3>\n" \
                      "</body>\n" % (int(close_timeout * 1000), code, close_timeout)
        else:
            content = "<h3>%d!</h3>" % code
        page.append("Content-Length: %d\r\n" % len(content))
        page.append("Content-Type: text/html\r\n")
        page.append("Connection: close\r\n\r\n")
        page.append(content)

        return "".join(page)


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
                sock.settimeout(0.05)
                # find an unused port and avoid blocked ports
                # see: dxr.mozilla.org/mozilla-central/source/netwerk/base/nsIOService.cpp
                port = random.randint(0x2000, 0xFFFF) if requested_port is None else requested_port
                sock.bind(("0.0.0.0" if allow_remote else "127.0.0.1", port))
                sock.listen(5)
            except socket.error as soc_e:
                if sock is not None:
                    sock.close()
                # try another port if a specific port was not requested
                if requested_port is None and soc_e.errno == errno.EADDRINUSE:
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


    def get_port(self):
        """
        get_port() -> int

        returns the port number the socket is listening on
        """

        return self._socket.getsockname()[1]


    @staticmethod
    def _handle_request(conn, serv_job):
        finish_job = False  # call finish() on return
        try:
            # receive all the incoming data
            raw_request = conn.recv(Sapphire.DEFAULT_REQUEST_LIMIT)

            # the intention here is to avoid losing sync with the browser...
            # for example: test_1 is served and redirects to test_2 and test_2 is requested before
            # the call to serve_path() for test_1 completes (no chance for test_2 to be generated)
            if serv_job.is_complete():
                log.debug("no files remaining in queue")
                return

            if not raw_request:
                log.debug("raw_request was empty")
                return

            request = Sapphire._request.match(raw_request)
            if request is None:
                conn.sendall(Sapphire._4xx_page(400, "Bad Request").encode("ascii"))
                log.debug("400 request length %d (%d to go)", len(raw_request), serv_job.pending_files())
                return
            request = request.group("request").decode("ascii")

            file_to_serve = os.path.join(serv_job.base_path, request)
            # check if path maps to a file
            if not os.path.isfile(file_to_serve):
                file_to_serve = None
                # check if path maps to a callback, redirect or an include directory
                url_info = serv_job.check_url(request)
                log.debug("url_info %r", url_info)
                if url_info is not None:
                    url_type, target = url_info
                else:
                    url_type = None
                    target = None

                if url_type == serv_job.URL_REDIRECT:
                    finish_job = serv_job.remove_queue_file(request)
                    conn.sendall(Sapphire._307_redirect(target[0]).encode("ascii"))
                    log.debug("307 %r -> %r (%d to go)", request, target[0], serv_job.pending_files())
                    return

                elif url_type == serv_job.URL_DYNAMIC:
                    target_cb, mime = target
                    data = target_cb()
                    if not isinstance(data, bytes):
                        log.debug("dynamic request: %r", request)
                        raise TypeError("dynamic request callback must return 'bytes'")
                    conn.sendall(Sapphire._200_header(len(data), mime).encode("ascii"))
                    conn.sendall(data)
                    log.debug("200 %r (dynamic request)", request)
                    return

                elif url_type == serv_job.URL_INCLUDE:
                    file_to_serve = target

                if file_to_serve is None or not os.path.isfile(file_to_serve):
                    conn.sendall(Sapphire._4xx_page(404, "Not Found").encode("ascii"))
                    log.debug(
                        "404 %r (%d to go)",
                        file_to_serve if file_to_serve else request,
                        serv_job.pending_files())
                    return

            if serv_job.is_forbidden(file_to_serve):
                # NOTE: this does info leak if files exist on disk.
                # We could replace 403 with 404 if it turns out we care but this is meant to run
                # locally and only be accessible from localhost
                conn.sendall(Sapphire._4xx_page(403, "Forbidden").encode("ascii"))
                log.debug("403 %r (%d to go)", request, serv_job.pending_files())
                return
            # at this point we know file_to_serve maps to a file on disk

            # default to "application/octet-stream"
            c_type = mimetypes.guess_type(file_to_serve)[0] or "application/octet-stream"

            # remove file from the pending queue
            finish_job = serv_job.remove_queue_file(file_to_serve)

            # serve the file
            data_size = os.stat(file_to_serve).st_size
            with open(file_to_serve, "rb") as in_fp:
                log.debug("sending file: %s bytes", "{:,}".format(data_size))
                conn.sendall(Sapphire._200_header(data_size, c_type).encode("ascii"))
                offset = 0
                while offset < data_size:
                    conn.sendall(in_fp.read(Sapphire.DEFAULT_TX_SIZE))
                    offset = in_fp.tell()

            # update list of served files
            with serv_job.f_served["lock"]:
                if file_to_serve in serv_job.f_served["files"]:
                    serv_job.f_served["files"][file_to_serve] += 1
                else:
                    serv_job.f_served["files"][file_to_serve] = 1

            log.debug("200 %r (%d to go)", file_to_serve, serv_job.pending_files())

        except (socket.timeout, socket.error):
            exc_type, exc_obj, tb = sys.exc_info()
            log.debug("%s: %r (line %d)", exc_type.__name__, exc_obj, tb.tb_lineno)

        except Exception:  # pylint: disable=broad-except
            serv_job.exceptions.put(sys.exc_info())

        finally:
            conn.close()
            if finish_job:
                serv_job.finish()
            serv_job.worker_complete.set()


    @staticmethod
    def _client_listener(serv_sock, serv_job):
        w_conn = None  # current worker connection
        w_pool = list()

        log.debug("starting client_listener")
        try:
            while not serv_job.is_complete():
                try:
                    w_conn, _ = serv_sock.accept()
                    w_conn.settimeout(None)
                    # create a worker thread to handle client request
                    w_thread = threading.Thread(
                        target=Sapphire._handle_request,
                        args=(w_conn, serv_job))
                    w_thread.start()
                    w_pool.append({"conn": w_conn, "thread": w_thread})
                except socket.timeout:
                    pass
                except socket.error:
                    if w_conn is not None:
                        w_conn.close()
                except threading.ThreadError:
                    if w_conn is not None:
                        w_conn.close()
                    log.warning(
                        "ThreadError! pool size: %d, total active threads: %d",
                        len(w_pool),
                        threading.active_count())
                    if Sapphire.ABORT_ON_THREAD_ERROR:
                        raise
                    time.sleep(0.1)  # wait for system resources to free up

                # manage worker pool
                pool_size = len(w_pool)
                if pool_size >= Sapphire.DEFAULT_WORKER_POOL_SIZE:
                    log.debug("active pool size: %d, waiting for worker to finish...", pool_size)
                    serv_job.worker_complete.wait()
                    serv_job.worker_complete.clear()
                    # remove complete workers
                    log.debug("trimming worker pool")
                    # sometimes the thread that triggered the event does quite cleanup in time
                    # so add a retry (10x with a 0.1 second sleep on failure)
                    for _ in range(10, 0, -1):
                        for worker in w_pool:
                            if not worker["thread"].is_alive():
                                # no need to call close() because worker threads do on exit
                                worker["thread"].join()
                                w_pool.remove(worker)
                        if len(w_pool) < pool_size:
                            break
                        time.sleep(0.1)
                    log.debug("done trimming worker pool")
                    assert len(w_pool) < pool_size, "Failed to trim worker pool!"
        finally:
            log.debug("shutting down and cleaning up workers")
            for worker in w_pool:
                worker["conn"].close()
                worker["thread"].join()


    def serve_path(self, path, continue_cb=None, optional_files=None):
        """
        serve_path() -> int
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

        log.debug("serve_path: %s", path)

        if continue_cb is not None and not callable(continue_cb):
            raise TypeError("continue_cb must be of type 'function'")
        if not os.path.isdir(os.path.abspath(path)):
            raise IOError("%r does not exist" % path)

        if self._server_timeout is not None:
            exp_time = time.time() + self._server_timeout
        else:
            exp_time = None

        job = ServeJob(
            path,
            self._dr_map,
            self._include_map,
            self._redirect_map,
            optional_files=optional_files)

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
                tries -= 1
                log.warning(
                    "ThreadError launching listener, active threads: %d",
                    threading.active_count())
                if tries > 0:
                    time.sleep(0.1)  # wait for system resources to free up
                    continue
                raise
            break

        status = None
        try:
            while True:
                # check for exceptions from workers
                try:
                    exc_type, exc_obj, exc_tb = job.exceptions.get_nowait()
                    log.warning(
                        "[sapphire worker] %s: %r (line %d)",
                        exc_type.__name__,
                        exc_obj,
                        exc_tb.tb_lineno)
                    raise exc_obj  # re-raise except from worker
                except QueueEmpty:
                    pass
                # check for a timeout
                if exp_time is not None and exp_time <= time.time():
                    status = SERVED_TIMEOUT
                    break
                # check if all required files have been served
                if job.is_complete():
                    break
                # check if callback returns False
                if continue_cb is not None and not continue_cb():
                    break
                time.sleep(0.05)
        finally:
            if status is None:
                status = job.get_status()
            job.finish()
            listener.join()

        self._redirect_map = {} # reset redirect map

        return status, job.f_served["files"].keys()


    @staticmethod
    def _check_potential_url(url_path):
        if not isinstance(url_path, str):
            raise TypeError("url_path must be of type 'str' not %r" % type(url_path))
        url_path = url_path.strip("/")
        if re.search(r"\W", url_path) is not None:
            raise RuntimeError("Invalid character, only alpha-numeric characters accepted.")
        return url_path


    def add_dynamic_response(self, url, callback, mime_type="application/octet-stream"):
        # check and sanitize url
        url = self._check_potential_url(url)

        if not callable(callback):
            raise TypeError("callback must be of type 'function'")
        if not isinstance(mime_type, str):
            raise TypeError("mime_type must be of type 'str'")

        log.debug("mapping dynamic response %r -> %r (%r)", url, callback, mime_type)
        self._dr_map[url] = (callback, mime_type)


    def add_include(self, url, target_path):
        if not os.path.isdir(target_path):
            raise IOError("Include path not found: %s" % target_path)

        # check and sanitize mount point
        url = self._check_potential_url(url)

        if url in self._include_map:
            raise RuntimeError("%r already mapped to %r" % (url, self._include_map[url]))

        log.debug("mapping include %r -> %r", url, target_path)
        self._include_map[url] = os.path.abspath(target_path)


    def set_redirect(self, url, target, required=True):
        # check and sanitize url
        url = self._check_potential_url(url)
        if not isinstance(target, str):
            raise TypeError("target must be of type 'str'")
        elif not target:
            raise TypeError("target must not be an empty string")
        self._redirect_map[url] = (target, required)


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

    serv = None
    try:
        serv = Sapphire(allow_remote=args.remote, port=args.port, timeout=args.timeout)
        log.info(
            "Serving %r @ http://%s:%d/",
            os.path.abspath(args.path),
            socket.gethostname() if args.remote else "127.0.0.1",
            serv.get_port())
        status = serv.serve_path(args.path)
        if status == SERVED_ALL:
            log.info("All test case content was served")
        else:
            log.warning("Failed to serve all test content")
    except KeyboardInterrupt:
        log.warning("Ctrl+C detected. Shutting down...")
    finally:
        if serv is not None:
            serv.close()
