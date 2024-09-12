# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from dataclasses import dataclass
from inspect import signature
from logging import getLogger
from re import search as re_search
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ("Resource", "ServerMap")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class InvalidURLError(Exception):
    """Raised what a URL string string contained invalid characters"""


class MapCollisionError(Exception):
    """Raised when a URL is already in use by ServerMap"""


@dataclass(frozen=True)
class Resource:
    url: str
    required: bool


@dataclass(frozen=True)
class DynamicResource(Resource):
    target: Callable[[str], bytes]
    mime: str


@dataclass(frozen=True)
class FileResource(Resource):
    target: Path
    mime: str


@dataclass(frozen=True)
class IncludeResource(Resource):
    target: Path


@dataclass(frozen=True)
class RedirectResource(Resource):
    target: str


class ServerMap:
    __slots__ = ("dynamic", "include", "redirect")

    def __init__(self) -> None:
        self.dynamic: dict[str, DynamicResource] = {}
        # mapping of directories that can be requested
        self.include: dict[str, IncludeResource] = {}
        # document paths to map to file names using 307s
        self.redirect: dict[str, RedirectResource] = {}

    @staticmethod
    def _check_url(url: str) -> str:
        # check and sanitize URL
        url = url.strip("/")
        if re_search(r"\W", url) is not None:
            raise InvalidURLError("Only alphanumeric characters accepted in URL.")
        return url

    def set_dynamic_response(
        self,
        url: str,
        callback: Callable[[str], bytes],
        mime_type: str = "application/octet-stream",
        required: bool = False,
    ) -> None:
        url = self._check_url(url)
        if not callable(callback):
            raise TypeError("callback must be callable")
        if len(signature(callback).parameters) != 1:
            raise TypeError("callback requires 1 argument")
        if not isinstance(mime_type, str):
            raise TypeError("mime_type must be of type 'str'")
        if url in self.include or url in self.redirect:
            raise MapCollisionError(f"URL collision on {url!r}")
        LOG.debug("mapping dynamic response %r -> %r (%r)", url, callback, mime_type)
        self.dynamic[url] = DynamicResource(url, required, callback, mime_type)

    def set_include(self, url: str, target: Path) -> None:
        url = self._check_url(url)
        if not target.is_dir():
            raise OSError(f"Include path not found: {target}")
        if url in self.dynamic or url in self.redirect:
            raise MapCollisionError(f"URL collision on {url!r}")
        # sanity check to prevent mapping overlapping paths
        # Note: This was added to help map file served via includes back to
        # the files on disk. This is a temporary workaround until mapping of
        # requests to files that were served is available outside of Sapphire.
        for existing_url, resource in self.include.items():
            if url == existing_url:
                # allow overwriting entry
                continue
            if resource.target in target.parents:
                LOG.error("%r mapping includes path '%s'", existing_url, target)
                raise MapCollisionError(
                    f"{url!r} and {existing_url!r} include '{target}'"
                )
            if target in resource.target.parents:
                LOG.error("%r mapping includes path '%s'", url, resource.target)
                raise MapCollisionError(
                    f"{url!r} and {existing_url!r} include '{resource.target}'"
                )
        LOG.debug("mapping include %r -> '%s'", url, target)
        self.include[url] = IncludeResource(url, False, target)

    def set_redirect(self, url: str, target: str, required: bool = True) -> None:
        url = self._check_url(url)
        if not isinstance(target, str):
            raise TypeError("target must be of type 'str'")
        if not target:
            raise TypeError("target must not be an empty string")
        if url in self.dynamic or url in self.include:
            raise MapCollisionError(f"URL collision on {url!r}")
        self.redirect[url] = RedirectResource(url, required, target)
