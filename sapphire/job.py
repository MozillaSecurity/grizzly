# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server job
"""
from collections import namedtuple
from enum import Enum, unique
from logging import getLogger
from mimetypes import guess_type
from os import walk
from os.path import abspath, isdir
from os.path import join as pathjoin
from os.path import relpath, splitext
from pathlib import Path
from queue import Queue
from threading import Event, Lock

from .server_map import Resource

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


@unique
class Served(Enum):
    """Server Job status codes"""

    # all expected requests for required files have been received
    ALL = 0
    # no requests for required files have been received
    NONE = 1
    # some requests for required files have been received
    REQUEST = 2
    # timeout occurred
    TIMEOUT = 3


Tracker = namedtuple("Tracker", "files lock")


class Job:
    # MIME_MAP is used to support new or uncommon mime types.
    # Definitions in here take priority over mimetypes.guess_type().
    MIME_MAP = {
        ".avif": "image/avif",
        ".bmp": "image/bmp",
        ".ico": "image/x-icon",
        ".wave": "audio/x-wav",
        ".webp": "image/webp",
    }

    __slots__ = (
        "_complete",
        "_pending",
        "_served",
        "auto_close",
        "accepting",
        "base_path",
        "exceptions",
        "forever",
        "initial_queue_size",
        "server_map",
        "worker_complete",
    )

    def __init__(
        self,
        base_path,
        auto_close=-1,
        forever=False,
        optional_files=None,
        server_map=None,
    ):
        self._complete = Event()
        self._pending = Tracker(files=set(), lock=Lock())
        self._served = Tracker(files=set(), lock=Lock())
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
                file_path = pathjoin(d_name, f_name)
                location = relpath(file_path, start=self.base_path).replace("\\", "/")
                # do not add optional files to queue of required files
                if optional_files and location in optional_files:
                    LOG.debug("optional: %r", location)
                    continue
                file_path = abspath(file_path)
                if "?" in file_path:
                    LOG.warning(
                        "Cannot add files with '?' in path. Skipping %r", file_path
                    )
                    continue
                self._pending.files.add(file_path)
                LOG.debug("required: %r", location)
        # if nothing was found check if the path exists
        if not self._pending.files and not isdir(self.base_path):
            raise OSError("%r does not exist" % (self.base_path,))
        if self.server_map:
            for redirect, resource in self.server_map.redirect.items():
                if resource.required:
                    self._pending.files.add(redirect)
                LOG.debug(
                    "%s: %r -> %r",
                    "required" if resource.required else "optional",
                    redirect,
                    resource.target,
                )
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

    def lookup_resource(self, path):
        # check if path is a file in wwwroot
        try:
            local = Path(self.base_path) / path
            if local.is_file():
                local = local.resolve()
                with self._pending.lock:
                    required = str(local) in self._pending.files
                return Resource(
                    Resource.URL_FILE,
                    local,
                    mime=self.lookup_mime(path),
                    required=required,
                )
        except ValueError:  # pragma: no cover
            # this is for compatibility with python versions < 3.8
            # is_file() will raise if the path contains characters unsupported
            # at the OS level
            pass
        # look for path in server map
        if self.server_map is not None:
            if path in self.server_map.redirect:
                return self.server_map.redirect[path]
            if path in self.server_map.dynamic:
                return self.server_map.dynamic[path]
            # search include paths for a match
            for inc in (x for x in self.server_map.include if path.startswith(x)):
                LOG.debug("checking include %r", inc)
                file = path[len(inc) :].lstrip("/")
                local = Path(self.server_map.include[inc].target) / file
                if local.is_file():
                    mime = self.server_map.include[inc].mime or self.lookup_mime(file)
                    return Resource(
                        Resource.URL_INCLUDE,
                        local,
                        mime=mime,
                        required=self.server_map.include[inc].required,
                    )
        return None

    def finish(self):
        self._complete.set()

    def mark_served(self, path):
        # update list of served files
        assert isinstance(path, Path)
        with self._served.lock:
            self._served.files.add(path)

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
        # files served from wwwroot will have a relative path
        # include files will have an absolute path
        with self._served.lock:
            # make a copy of what is available (maybe a copy not necessary?)
            served = tuple(self._served.files)
        wwwroot = Path(self.base_path)
        for path in served:
            try:
                # file is in wwwroot
                yield path.relative_to(wwwroot).as_posix()
            except ValueError:
                # include file
                yield path.as_posix()

    @property
    def status(self):
        with self._pending.lock:
            queue_size = len(self._pending.files)
        if queue_size == 0:
            return Served.ALL
        if queue_size < self.initial_queue_size:
            return Served.REQUEST
        return Served.NONE
