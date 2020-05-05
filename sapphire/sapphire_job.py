# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server job
"""

from collections import defaultdict, namedtuple
import logging
import os
try:  # py 2-3 compatibility
    from Queue import Queue
except ImportError:
    from queue import Queue
import threading

from .server_map import Resource
from .status_codes import SERVED_ALL, SERVED_NONE, SERVED_REQUEST

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = logging.getLogger("sphr_job")


Tracker = namedtuple("Tracker", "files lock")


class SapphireJob(object):
    __slots__ = (
        "_complete", "_pending", "_served", "auto_close", "accepting", "base_path",
        "exceptions", "forever", "initial_queue_size", "server_map", "worker_complete")

    def __init__(self, base_path, auto_close=-1, forever=False, optional_files=None, server_map=None):
        self._complete = threading.Event()
        self._pending = Tracker(files=set(), lock=threading.Lock())
        self._served = Tracker(files=defaultdict(int), lock=threading.Lock())
        self.accepting = threading.Event()
        self.accepting.set()
        self.auto_close = auto_close
        self.base_path = os.path.abspath(base_path)  # wwwroot
        self.exceptions = Queue()
        self.forever = forever
        self.initial_queue_size = 0
        self.server_map = server_map
        self.worker_complete = threading.Event()
        self._build_queue(optional_files)

    def _build_queue(self, optional_files):
        # build file list to track files that must be served
        # this is intended to only be called once by __init__()
        for d_name, _, filenames in os.walk(self.base_path, followlinks=False):
            for f_name in filenames:
                # do not add optional files to queue of required files
                if optional_files and f_name in optional_files:
                    LOG.debug("optional: %r", f_name)
                    continue
                file_path = os.path.abspath(os.path.join(d_name, f_name))
                if "?" in file_path:
                    LOG.warning("Cannot add files with '?' in path. Skipping %r", file_path)
                    continue
                self._pending.files.add(file_path)
                LOG.debug("required: %r", f_name)
        # if nothing was found check if the path exists
        if not self._pending.files and not os.path.isdir(self.base_path):
            raise OSError("%r does not exist" % (self.base_path),)
        if self.server_map:
            for redirect, resource in self.server_map.redirect.items():
                if resource.required:
                    self._pending.files.add(redirect)
                LOG.debug(
                    "%s: %r -> %r",
                    "required" if resource.required else "optional",
                    redirect,
                    resource.target)
        self.initial_queue_size = len(self._pending.files)
        LOG.debug("sapphire has %d files required to serve", self.initial_queue_size)

    def check_request(self, request):
        if "?" in request:
            request = request.split("?", 1)[0]
        to_serve = os.path.normpath(os.path.join(self.base_path, request))
        if "\x00" not in to_serve and os.path.isfile(to_serve):
            res = Resource(Resource.URL_FILE, to_serve)
            with self._pending.lock:
                res.required = to_serve in self._pending.files
            return res
        if self.server_map is None:
            return None
        if request in self.server_map.redirect:
            return self.server_map.redirect[request]
        if request in self.server_map.dynamic:
            return self.server_map.dynamic[request]
        if self.server_map.include:
            check_includes = False
            for include in self.server_map.include:
                if include != "":
                    check_includes = True
                    break

            last_split = 0
            while check_includes:
                split_req = request.rsplit("/", last_split)
                if len(split_req) != last_split + 1:
                    break
                inc_path = split_req[0]
                target_path = split_req[1:]

                LOG.debug("looking up %r in include map", inc_path)
                if inc_path in self.server_map.include:
                    to_serve = os.path.normpath(
                        "/".join([self.server_map.include[inc_path].target] + target_path))
                    return Resource(
                        Resource.URL_INCLUDE,
                        to_serve,
                        mime=self.server_map.include[inc_path].mime,
                        required=self.server_map.include[inc_path].required)
                LOG.debug("include map does not contain %r", inc_path)
                last_split += 1

            # check if this is a nested directory in a directory mounted at '/'
            LOG.debug("checking include map at '/'")
            if "" in self.server_map.include:
                to_serve = os.path.normpath(
                    os.path.join(self.server_map.include[""].target, request.lstrip("/")))
                return Resource(
                    Resource.URL_INCLUDE,
                    to_serve,
                    mime=self.server_map.include[""].mime,
                    required=self.server_map.include[""].required)
            LOG.debug("include map does not contain an entry at '/'")

        return None

    def finish(self):
        self._complete.set()

    def increment_served(self, target):
        # update list of served files
        with self._served.lock:
            self._served.files[target] += 1

    def is_complete(self, wait=None):
        if wait is not None:
            return self._complete.wait(wait)
        return self._complete.is_set()

    def is_forbidden(self, target_file):
        target_file = os.path.abspath(target_file)
        # check if target_file lives somewhere in wwwroot
        if not target_file.startswith(self.base_path):
            if self.server_map:
                for resources in self.server_map.include.values():
                    if target_file.startswith(resources.target):
                        return False  # this is a valid include path
            return True  # this is NOT a valid include path
        return False  # this is a valid path

    @property
    def pending(self):
        # number of pending files
        with self._pending.lock:
            return len(self._pending.files)

    def remove_pending(self, file_name):
        # return True when all file have been removed
        with self._pending.lock:
            if self._pending.files:
                self._pending.files.discard(file_name)
            return not self._pending.files

    @property
    def served(self):
        # served files (with path relative to www root)
        with self._served.lock:
            return tuple(os.path.relpath(x, self.base_path) for x in self._served.files.keys())

    @property
    def status(self):
        with self._pending.lock:
            queue_size = len(self._pending.files)
        if queue_size == 0:
            return SERVED_ALL
        if queue_size < self.initial_queue_size:
            return SERVED_REQUEST
        return SERVED_NONE
