# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Sapphire HTTP server job
"""
from __future__ import annotations

from enum import IntEnum, unique
from errno import ENAMETOOLONG
from itertools import chain
from logging import getLogger
from mimetypes import guess_type
from os.path import splitext
from queue import Queue
from threading import Event, Lock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Iterable, Mapping, NamedTuple, Tuple, Union, cast

from .server_map import DynamicResource, FileResource, RedirectResource, ServerMap

if TYPE_CHECKING:
    from pathlib import Path

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


@unique
class Served(IntEnum):
    """Server Job status codes"""

    # all expected requests for required files have been received
    ALL = 0
    # no requests for required files have been received
    NONE = 1
    # some requests for required files have been received
    REQUEST = 2
    # timeout occurred
    TIMEOUT = 3


class PendingTracker(NamedTuple):
    files: set[str]
    lock: Lock


class ServedTracker(NamedTuple):
    files: set[FileResource]
    lock: Lock


class Job:
    # MIME_MAP is used to support new or uncommon mime types.
    # Definitions in here take priority over mimetypes.guess_type().
    MIME_MAP = MappingProxyType(
        {
            ".avif": "image/avif",
            ".bmp": "image/bmp",
            ".ico": "image/x-icon",
            ".wave": "audio/x-wav",
            ".webp": "image/webp",
        }
    )

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
        wwwroot: Path,
        auto_close: int = -1,
        forever: bool = False,
        required_files: Iterable[str] | None = None,
        server_map: ServerMap | None = None,
    ) -> None:
        self._complete = Event()
        self._pending = PendingTracker(files=set(), lock=Lock())
        self._served = ServedTracker(files=set(), lock=Lock())
        self._wwwroot = wwwroot.resolve()
        self.accepting = Event()
        self.accepting.set()
        self.auto_close = auto_close
        # quotes around type for Python 3.8
        self.exceptions: Queue[tuple[Any, Any, Any]] = Queue()
        self.forever = forever
        self.server_map = server_map
        self.worker_complete = Event()
        self._build_pending(required_files)
        if not self._pending.files and not self.forever:
            raise RuntimeError("Empty Job")

    def _build_pending(self, required_files: Iterable[str] | None) -> None:
        """Build file list to track files that must be served.
        Note: This is intended to only be called once by __init__().

        Args:
            required_files: File paths (relative to wwwroot) that must be served.

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
                    LOG.debug("required: %r", required)
        # if nothing was found check if the path exists
        if not self._pending.files and not self._wwwroot.is_dir():
            raise OSError(f"wwwroot '{self._wwwroot}' does not exist")
        if self.server_map:
            for url, resource in cast(
                Iterable[Tuple[str, Union[DynamicResource, RedirectResource]]],
                chain(
                    self.server_map.redirect.items(), self.server_map.dynamic.items()
                ),
            ):
                if resource.required:
                    self._pending.files.add(url)
                    LOG.debug("required: %r -> %r", url, resource.target)
        LOG.debug("job has %d required file(s)", len(self._pending.files))

    @classmethod
    def lookup_mime(cls, url: str) -> str:
        """Determine mime type for a given URL.

        Args:
            url: URL to inspect.

        Returns:
            Mime type of URL. 'application/octet-stream' is returned if the mime
            type cannot be determined.
        """
        mime = cls.MIME_MAP.get(splitext(url)[-1].lower())
        if mime is None:
            # default to "application/octet-stream"
            mime = guess_type(url)[0] or "application/octet-stream"
        return mime

    def lookup_resource(
        self, path: str
    ) -> FileResource | DynamicResource | RedirectResource | None:
        """Find the Resource mapped to a given URL path.

        Args:
            path: URL path.

        Returns:
            Resource: Resource for the given URL path or None if one is not found.
        """
        path = path.lstrip("/")
        # check if path is a file in wwwroot
        try:
            local = self._wwwroot / path
            if local.is_file():
                local = local.resolve()
                if self._wwwroot in local.parents:
                    with self._pending.lock:
                        required = str(local) in self._pending.files
                    return FileResource(path, required, local, self.lookup_mime(path))
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
                local = self.server_map.include[inc].target / file
                # check that the file exists within the include path
                if local.is_file():
                    local = local.resolve()
                    if self.server_map.include[inc].target in local.parents:
                        return FileResource(
                            f"{inc}/{file}" if inc else file,
                            self.server_map.include[inc].required,
                            local,
                            self.lookup_mime(file),
                        )
        return None

    def finish(self) -> None:
        """Mark Job as complete.

        Args:
            None

        Returns:
            None
        """
        self._complete.set()

    def mark_served(self, item: FileResource) -> None:
        """Mark a Resource as served to track served Resources.

        Args:
            item: Resource to track.

        Returns:
            None
        """
        with self._served.lock:
            self._served.files.add(item)

    def is_complete(self, wait: float | None = None) -> bool:
        """Check if a Job has been marked as complete.

        Args:
            wait: Time to wait in seconds.

        Returns:
            True if Job complete flag is set otherwise False.
        """
        if wait is not None:
            return self._complete.wait(wait)
        return self._complete.is_set()

    @property
    def pending(self) -> int:
        """Number of files that have not been served.

        Args:
            None

        Returns:
            Number of pending files.
        """
        with self._pending.lock:
            return len(self._pending.files)

    def remove_pending(self, file_name: str) -> bool:
        """Remove a file from pending list.

        Args:
            file_name (str): File to remove from pending list.

        Returns:
            True when all files have been removed otherwise False.
        """
        with self._pending.lock:
            self._pending.files.discard(file_name)
            return not self._pending.files

    @property
    def served(self) -> Mapping[str, Path]:
        """Served files.

        Args:
            None

        Returns:
            Mapping of URLs to files on disk.
        """
        with self._served.lock:
            return MappingProxyType({x.url: x.target for x in self._served.files})

    @property
    def status(self) -> Served:
        """Job Status.

        Args:
            None

        Returns:
            Current status.
        """
        with self._pending.lock:
            if not self._served.files:
                return Served.NONE
            if not self._pending.files:
                return Served.ALL
        return Served.REQUEST
