# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server job
"""
from mimetypes import guess_type
from collections import defaultdict, namedtuple
from logging import getLogger
from os import walk
from os.path import abspath, isdir, isfile, join as pathjoin, normpath, relpath, splitext
from queue import Queue
from threading import Event, Lock

from .server_map import Resource

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


# job status codes
SERVED_ALL = 0      # all expected requests for required files have been received
SERVED_NONE = 1     # no requests for required files have been received
SERVED_REQUEST = 2  # some requests for required files have been received
SERVED_TIMEOUT = 3  # timeout occurred


Tracker = namedtuple("Tracker", "files lock")


class Job:
    # MIME_MAP is used to support new or uncommon mime types.
    # Definitions in here take priority over mimetypes.guess_type().
    MIME_MAP = {
        ".avif": "image/avif",
        ".bmp": "image/bmp",
        ".ico": "image/x-icon",
        ".wave": "audio/x-wav",
        ".webp": "image/webp"
    }

    __slots__ = (
        "_complete", "_pending", "_served", "auto_close", "accepting", "base_path",
        "exceptions", "forever", "initial_queue_size", "server_map", "worker_complete")

    def __init__(self, base_path, auto_close=-1, forever=False, optional_files=None, server_map=None):
        self._complete = Event()
        self._pending = Tracker(files=set(), lock=Lock())
        self._served = Tracker(files=defaultdict(int), lock=Lock())
        self.accepting = Event()
        self.accepting.set()
        self.auto_close = auto_close
        self.base_path = abspath(base_path)  # wwwroot
        self.exceptions = Queue()
        self.forever = forever
        self.initial_queue_size = 0
        self.server_map = server_map
        self.worker_complete = Event()
        self._build_queue(optional_files)

    def _build_queue(self, optional_files):
        # build file list to track files that must be served
        # this is intended to only be called once by __init__()
        for d_name, _, filenames in walk(self.base_path, followlinks=False):
            for f_name in filenames:
                # do not add optional files to queue of required files
                if optional_files and f_name in optional_files:
                    LOG.debug("optional: %r", f_name)
                    continue
                file_path = abspath(pathjoin(d_name, f_name))
                if "?" in file_path:
                    LOG.warning("Cannot add files with '?' in path. Skipping %r", file_path)
                    continue
                self._pending.files.add(file_path)
                LOG.debug("required: %r", f_name)
        # if nothing was found check if the path exists
        if not self._pending.files and not isdir(self.base_path):
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
            for dyn_resp, resource in self.server_map.dynamic.items():
                if resource.required:
                    self._pending.files.add(dyn_resp)
                    LOG.debug("%s: %r -> %r", "required", dyn_resp, resource.target)
        self.initial_queue_size = len(self._pending.files)
        LOG.debug("%d files required to serve", self.initial_queue_size)

    @classmethod
    def lookup_mime(cls, url):
        mime = cls.MIME_MAP.get(splitext(url)[-1].lower())
        if mime is None:
            # default to "application/octet-stream"
            mime = guess_type(url)[0] or "application/octet-stream"
        return mime

    def check_request(self, request):
        if "?" in request:
            request = request.split("?", 1)[0]
        to_serve = normpath(pathjoin(self.base_path, request))
        if "\x00" not in to_serve and isfile(to_serve):
            res = Resource(Resource.URL_FILE, to_serve, mime=self.lookup_mime(to_serve))
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
                            target = pathjoin(
                                self.server_map.include[url].target,
                                location)
                            # if the mapping url is empty check the file exists
                            if url or isfile(target):
                                mime = self.server_map.include[url].mime
                                if mime is None:
                                    mime = self.lookup_mime(to_serve)
                                return Resource(
                                    Resource.URL_INCLUDE,
                                    normpath(target),
                                    mime=mime,
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
        target_file = abspath(target_file)
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
                yield relpath(fname, self.base_path)
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
