# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
URL-to-resource mapping for the Sapphire HTTP server.

Provides ServerMap for managing custom URL mappings.
Defines Resource types representing different kinds of servable content.
"""

from __future__ import annotations

from dataclasses import dataclass
from inspect import signature
from logging import getLogger
from re import search as re_search
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

__all__ = ("Resource", "ServerMap")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class InvalidURLError(Exception):
    """Raised when a URL string contains invalid characters."""


class MapCollisionError(Exception):
    """Raised when a URL is already mapped in the ServerMap."""


@dataclass(frozen=True, slots=True)
class Resource:
    """Base class for all servable resources.

    Attributes:
        url: The URL path where this resource is accessible.
        required: Whether this resource must be served for the job to complete.
    """

    url: str
    required: bool


@dataclass(frozen=True, slots=True)
class DynamicResource(Resource):
    """Resource with content generated dynamically by a callback.

    Attributes:
        target: Callback function that takes a query string and returns content bytes.
        mime: MIME type of the generated content.
    """

    target: Callable[[str], bytes]
    mime: str


@dataclass(frozen=True, slots=True)
class FileResource(Resource):
    """Resource served from a file on disk.

    Attributes:
        target: Path to the file on the filesystem.
        mime: MIME type of the file content.
    """

    target: Path
    mime: str


@dataclass(frozen=True, slots=True)
class IncludeResource(Resource):
    """Resource representing an included directory tree.

    Allows serving files from a directory at a custom URL prefix.

    Attributes:
        target: Path to the directory to serve.
    """

    target: Path


@dataclass(frozen=True, slots=True)
class RedirectResource(Resource):
    """Resource that redirects to another URL.

    Attributes:
        target: The URL to redirect to (HTTP 307).
    """

    target: str


class ServerMap:
    """Maps URLs to custom resources for the HTTP server.

    Manages three types of URL mappings:
    - Dynamic: URLs that generate content via callback functions
    - Include: URL prefixes that map to filesystem directories
    - Redirect: URLs that redirect to other locations

    All mappings are validated to prevent collisions and invalid URLs.
    """

    __slots__ = ("dynamic", "include", "redirect")

    def __init__(self) -> None:
        """Initialize an empty ServerMap.

        Args:
            None

        Returns:
            None
        """
        self.dynamic: dict[str, DynamicResource] = {}
        # mapping of directories that can be requested
        self.include: dict[str, IncludeResource] = {}
        # document paths to map to file names using 307s
        self.redirect: dict[str, RedirectResource] = {}

    @staticmethod
    def _check_url(url: str) -> str:
        """Validate and sanitize a URL string.

        Args:
            url: URL to validate.

        Returns:
            Sanitized URL with leading/trailing slashes removed.

        Raises:
            InvalidURLError: If URL contains non-alphanumeric characters.
        """
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
        """Map a URL to dynamically generated content.

        Args:
            url: URL path to map.
            callback: Function that takes a query string and returns bytes.
            mime_type: MIME type of the generated content.
            required: Whether this resource must be served for job completion.

        Returns:
            None

        Raises:
            InvalidURLError: If URL contains invalid characters.
            MapCollisionError: If URL is already mapped.
            TypeError: If callback is not callable or has wrong signature.
        """
        url = self._check_url(url)
        if not callable(callback):
            raise TypeError("callback must be callable")
        if len(signature(callback).parameters) != 1:
            raise TypeError("callback requires 1 argument")
        if not isinstance(mime_type, str):
            raise TypeError("mime_type must be of type 'str'")
        if url in self.include or url in self.redirect:
            raise MapCollisionError(f"URL collision on '{url}'")
        LOG.debug("mapping dynamic response '%s' -> %r (%s)", url, callback, mime_type)
        self.dynamic[url] = DynamicResource(url, required, callback, mime_type)

    def set_include(self, url: str, target: Path) -> None:
        """Map a URL prefix to serve files from a directory.

        Args:
            url: URL prefix for the mapping.
            target: Directory path to serve files from.

        Returns:
            None

        Raises:
            InvalidURLError: If URL contains invalid characters.
            FileNotFoundError: If target directory does not exist.
            MapCollisionError: If URL is already mapped or overlaps with existing
                includes.
        """
        url = self._check_url(url)
        if not target.is_dir():
            raise FileNotFoundError(f"Include path not found: {target}")
        if url in self.dynamic or url in self.redirect:
            raise MapCollisionError(f"URL collision on '{url}'")
        # sanity check to prevent mapping overlapping paths
        # Note: This was added to help map file served via includes back to
        # the files on disk. This is a temporary workaround until mapping of
        # requests to files that were served is available outside of Sapphire.
        for existing_url, resource in self.include.items():
            if url == existing_url:
                # allow overwriting entry
                continue
            if resource.target in target.parents:
                LOG.error("'%s' mapping includes path '%s'", existing_url, target)
                raise MapCollisionError(
                    f"'{url}' and '{existing_url}' include '{target}'"
                )
            if target in resource.target.parents:
                LOG.error("'%s' mapping includes path '%s'", url, resource.target)
                raise MapCollisionError(
                    f"'{url}' and '{existing_url}' include '{resource.target}'"
                )
        LOG.debug("mapping include '%s' -> '%s'", url, target)
        self.include[url] = IncludeResource(url, False, target)

    def set_redirect(self, url: str, target: str, required: bool = True) -> None:
        """Map a URL to redirect to another location (HTTP 307).

        Args:
            url: URL path to redirect from.
            target: URL to redirect to.
            required: Whether this redirect must be requested for job completion.

        Returns:
            None

        Raises:
            InvalidURLError: If URL contains invalid characters.
            MapCollisionError: If URL is already mapped.
            TypeError: If target is not a string or is empty.
        """
        url = self._check_url(url)
        if not isinstance(target, str):
            raise TypeError("target must be of type 'str'")
        if not target:
            raise TypeError("target must not be an empty string")
        if url in self.dynamic or url in self.include:
            raise MapCollisionError(f"URL collision on '{url}'")
        self.redirect[url] = RedirectResource(url, required, target)
