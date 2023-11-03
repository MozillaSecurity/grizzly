# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server job
"""
from collections import namedtuple
from enum import Enum, unique
from errno import ENAMETOOLONG
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
        required_files=None,
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
        self._build_pending(required_files)
        if not self._pending.files and not self.forever:
            raise RuntimeError("Empty Job")

    def _build_pending(self, required_files):
        """Build file list to track files that must be served.
        Note: This is intended to only be called once by __init__().

        Args:
            required_files (list(str)): List of file paths relative to wwwroot.

        Returns:
            None
        """
        assert not self._complete.is_set()
        assert not self._pending.files
        assert not self._served.files
        if required_files:
            for required in required_files:
                assert "?" not in required
                entry = self._wwwroot / required
                if entry.is_file():
                    self._pending.files.add(str(entry.resolve()))
                    LOG.debug("required: %r", entry)
        # if nothing was found check if the path exists
        if not self._pending.files and not self._wwwroot.is_dir():
            raise OSError(f"wwwroot '{self._wwwroot}' does not exist")
        if self.server_map:
            for redirect, resource in self.server_map.redirect.items():
                if resource.required:
                    self._pending.files.add(redirect)
                    LOG.debug("required: %r -> %r", redirect, resource.target)
            for dyn_resp, resource in self.server_map.dynamic.items():
                if resource.required:
                    self._pending.files.add(dyn_resp)
                    LOG.debug("required: %r -> %r", dyn_resp, resource.target)
        LOG.debug("job has %d required file(s)", len(self._pending.files))

    @classmethod
    def lookup_mime(cls, url):
        """Determine mime type for a given URL.

        Args:
            url (str): URL to inspect.

        Returns:
            str: Mime type of URL or 'application/octet-stream' if the mime type
                 cannot be determined.
        """
        mime = cls.MIME_MAP.get(splitext(url)[-1].lower())
        if mime is None:
            # default to "application/octet-stream"
            mime = guess_type(url)[0] or "application/octet-stream"
        return mime

    def lookup_resource(self, path):
        """Find the Resource mapped to a given URL path.

        Args:
            path (str): URL path.

        Returns:
            Resource: Resource for the given URL path or None if one is not found.
        """
        path = path.lstrip("/")
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
                    url=path,
                )
        except OSError as exc:
            if exc.errno == ENAMETOOLONG:
                # file name is too long to look up so ignore it
                return None
            raise  # pragma: no cover
        # look for path in server map
        if self.server_map is not None:
            if path in self.server_map.redirect:
                return self.server_map.redirect[path]
            if path in self.server_map.dynamic:
                return self.server_map.dynamic[path]
            # search include paths for a match
            for inc in (x for x in self.server_map.include if path.startswith(x)):
                LOG.debug("checking include %r", inc)
                # strip include prefix from potential file name
                file = path[len(inc) :].lstrip("/")
                local = Path(self.server_map.include[inc].target) / file
                if not local.is_file():
                    continue
                # file exists, look up resource
                return Resource(
                    Resource.URL_INCLUDE,
                    local.resolve(),
                    mime=self.server_map.include[inc].mime or self.lookup_mime(file),
                    required=self.server_map.include[inc].required,
                    url=f"{inc}/{file}" if inc else file,
                )
        return None

    def finish(self):
        """Mark Job as complete.

        Args:
            None

        Returns:
            None
        """
        self._complete.set()

    def mark_served(self, item):
        """Mark a Resource as served to track served Resources.

        Args:
            item (Resource): Resource to track.

        Returns:
            None
        """
        assert isinstance(item, Resource)
        assert item.type in (Resource.URL_FILE, Resource.URL_INCLUDE)
        with self._served.lock:
            if item.url not in self._served.files:
                self._served.files.add(item)

    def is_complete(self, wait=None):
        """Check if a Job has been marked as complete.

        Args:
            wait (float): Time to wait in seconds.

        Returns:
            boot: True if Job complete flag is set otherwise False.
        """
        if wait is not None:
            return self._complete.wait(wait)
        return self._complete.is_set()

    def is_forbidden(self, target, is_include=False):
        """Check if a path is forbidden. Anything outside of wwwroot and not
        added by an included is forbidden.

        Note: It is assumed that the files exist on disk and that the
        paths are absolute and sanitized.

        Args:
            target (Path or str): Path to check.
            is_include (bool): Indicates if given path is an include.

        Returns:
            bool: True if no forbidden otherwise False.
        """
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
        """Number of pending files.

        Args:
            None

        Returns:
            int: Number of pending file.
        """
        with self._pending.lock:
            return len(self._pending.files)

    def remove_pending(self, file_name):
        """Remove a file from pending list.

        Args:
            file_name (str): File to remove from pending list.

        Returns:
            bool: True when all files have been removed otherwise False.
        """
        with self._pending.lock:
            if self._pending.files:
                self._pending.files.discard(file_name)
            return not self._pending.files

    @property
    def served(self):
        """Served files.

        Args:
            None

        Returns:
            dict: Mapping of URLs to files on disk.
        """
        with self._served.lock:
            return {entry.url: entry.target for entry in self._served.files}

    @property
    def status(self):
        """Job Status.

        Args:
            None

        Returns:
            Served: Current status.
        """
        with self._pending.lock:
            if not self._served.files:
                return Served.NONE
            if not self._pending.files:
                return Served.ALL
        return Served.REQUEST
