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
from os.path import splitext
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
        "_wwwroot",
        "auto_close",
        "accepting",
        "exceptions",
        "forever",
        "server_map",
        "worker_complete",
    )

    def __init__(
        self,
        wwwroot,
        auto_close=-1,
        forever=False,
        optional_files=None,
        server_map=None,
    ):
        self._complete = Event()
        self._pending = Tracker(files=set(), lock=Lock())
        self._served = Tracker(files=set(), lock=Lock())
        self._wwwroot = wwwroot.resolve()
        self.accepting = Event()
        self.accepting.set()
        self.auto_close = auto_close
        self.exceptions = Queue()
        self.forever = forever
        self.server_map = server_map
        self.worker_complete = Event()
        self._build_queue(optional_files)

    def _build_queue(self, optional_files):
        # build file list to track files that must be served
        # this is intended to only be called once by __init__()
        for entry in self._wwwroot.rglob("*"):
            if not entry.is_file():
                continue
            location = entry.relative_to(self._wwwroot).as_posix()
            # do not add optional files to queue of required files
            if optional_files and location in optional_files:
                LOG.debug("optional: %r", location)
                continue
            if "?" in str(entry):
                LOG.warning(
                    "Cannot add files with '?' in path. Skipping %r", str(entry)
                )
                continue
            self._pending.files.add(str(entry.resolve()))
            LOG.debug("required: %r", location)
        # if nothing was found check if the path exists
        if not self._pending.files and not self._wwwroot.is_dir():
            raise OSError("%r does not exist" % (str(self._wwwroot),))
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
        LOG.debug("%d files required to serve", len(self._pending.files))

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
            local = self._wwwroot / path
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
                try:
                    if not local.is_file():
                        continue
                except ValueError:  # pragma: no cover
                    # python versions < 3.8 compatibility
                    continue
                # file exists, look up resource
                return Resource(
                    Resource.URL_INCLUDE,
                    local.resolve(),
                    mime=self.server_map.include[inc].mime or self.lookup_mime(file),
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

    def is_forbidden(self, target, is_include=False):
        # it is assumed that these file exists on disk
        # and that the paths are absolute and sanitized
        target = str(target)
        if not is_include:
            # check if target is in wwwroot
            if target.startswith(str(self._wwwroot)):
                return False
        elif self.server_map:
            # check if target is in an included path
            for resource in self.server_map.include.values():
                if target.startswith(resource.target):
                    # target is in a valid include path
                    return False
        return True

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
        for path in served:
            try:
                # file is in wwwroot
                yield path.relative_to(self._wwwroot).as_posix()
            except ValueError:
                # include file
                yield path.as_posix()

    @property
    def status(self):
        with self._pending.lock:
            if not self._served.files:
                return Served.NONE
            if not self._pending.files:
                return Served.ALL
        return Served.REQUEST
