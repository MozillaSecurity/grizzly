# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import re


__all__ = ("Resource", "ServerMap")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = logging.getLogger("sphr_map")  # pylint: disable=invalid-name


class InvalidURLError(Exception):
    """Raised what a URL string string contained invalid characters"""


class MapCollisionError(Exception):
    """Raised when a URL is already in use by ServerMap"""


class Resource(object):
    URL_DYNAMIC = 0
    URL_FILE = 1
    URL_INCLUDE = 2
    URL_REDIRECT = 3

    __slots__ = ("mime", "required", "target", "type")

    def __init__(self, resource_type, target, mime=None, required=False):
        self.mime = mime
        self.required = required
        self.target = target
        self.type = resource_type


class ServerMap(object):
    __slots__ = ("dynamic", "include", "redirect")

    def __init__(self):
        self.dynamic = dict()
        self.include = dict()  # mapping of directories that can be requested
        self.redirect = dict()  # document paths to map to file names using 307s

    @staticmethod
    def _check_url(url):
        # check and sanitize URL
        url = url.strip("/")
        if re.search(r"\W", url) is not None:
            raise InvalidURLError("Only alpha-numeric characters accepted in URL.")
        return url

    def set_dynamic_response(self, url, callback, mime_type="application/octet-stream"):
        url = self._check_url(url)
        if not callable(callback):
            raise TypeError("callback must be callable")
        if not isinstance(mime_type, str):
            raise TypeError("mime_type must be of type 'str'")
        if url in self.include or url in self.redirect:
            raise MapCollisionError("URL collision on %r" % (url,))
        LOG.debug("mapping dynamic response %r -> %r (%r)", url, callback, mime_type)
        self.dynamic[url] = Resource(
            Resource.URL_DYNAMIC,
            callback,
            mime=mime_type)

    def set_include(self, url, target_path):
        url = self._check_url(url)
        if not os.path.isdir(target_path):
            raise IOError("Include path not found: %s" % (target_path,))
        if url in self.dynamic or url in self.redirect:
            raise MapCollisionError("URL collision on %r" % (url,))
        LOG.debug("mapping include %r -> %r", url, target_path)
        self.include[url] = Resource(
            Resource.URL_INCLUDE,
            os.path.abspath(target_path))

    def set_redirect(self, url, target, required=True):
        url = self._check_url(url)
        if not isinstance(target, str):
            raise TypeError("target must be of type 'str'")
        if not target:
            raise TypeError("target must not be an empty string")
        if url in self.dynamic or url in self.include:
            raise MapCollisionError("URL collision on %r" % (url,))
        self.redirect[url] = Resource(
            Resource.URL_REDIRECT,
            target,
            required=required)
