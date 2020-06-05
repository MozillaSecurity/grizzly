# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server job
"""

from collections import defaultdict, namedtuple
from logging import getLogger
import os
from queue import Queue
import threading

from .server_map import Resource
from .status_codes import SERVED_ALL, SERVED_NONE, SERVED_REQUEST

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger("sphr_job")


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
        LOG.debug("%d files required to serve", self.initial_queue_size)

    def check_request(self, request):
        if "?" in request:
            request = request.split("?", 1)[0]
        to_serve = os.path.normpath(os.path.join(self.base_path, request))
        if "\x00" not in to_serve and os.path.isfile(to_serve):
            res = Resource(Resource.URL_FILE, to_serve)
            with self._pending.lock:
                res.required = to_serve in self._pending.files
            return res
        if self.server_map is not None:
            if request in self.server_map.redirect:
                return self.server_map.redirect[request]
            if request in self.server_map.dynamic:
                return self.server_map.dynamic[request]
            # collect possible include matches
            includes = tuple(x for x in self.server_map.include if request.startswith(x))
            if includes:
                LOG.debug("potential include matches %r", includes)
                # attempt to find match
                url = request
                while True:
                    if url in includes:
                        LOG.debug("found include match %r", url)
                        location = request.split(url, 1)[-1].lstrip("/") if url else request
                        # check location points to something
                        if location:
                            target = os.path.join(
                                self.server_map.include[url].target,
                                location)
                            # if the mapping url is empty check the file exists
                            if url or os.path.isfile(target):
                                return Resource(
                                    Resource.URL_INCLUDE,
                                    os.path.normpath(target),
                                    mime=self.server_map.include[url].mime,
                                    required=self.server_map.include[url].required)
                    if "/" in url:
                        url = url.rsplit("/", 1)[0]
                    elif url:
                        # try empty mount point
                        url = ""
                    else:
                        # include does not exist
                        break
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
        # served files
        # files served from www root will have a path relative to www root
        # include files will have an absolute path
        with self._served.lock:
            # make a copy of what is available (maybe a copy not necessary?)
            served = tuple(self._served.files.keys())
        for fname in served:
            if fname.startswith(self.base_path):
                # file is in www root
                yield os.path.relpath(fname, self.base_path)
            else:
                # include file
                yield fname

    @property
    def status(self):
        with self._pending.lock:
            queue_size = len(self._pending.files)
        if queue_size == 0:
            return SERVED_ALL
        if queue_size < self.initial_queue_size:
            return SERVED_REQUEST
        return SERVED_NONE
