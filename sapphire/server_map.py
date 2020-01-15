# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os


__all__ = ("ServerMap",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class ServerMap(object):
    def __init__(self):
        self._dynamic = dict()
        self._include = dict()  # mapping of directories that can be requested
        self._redirect = dict()  # document paths to map to file names using 307s

    @property
    def dynamic_responses(self):
        out = list()
        for url, (callback, mime) in self._dynamic.items():
            out.append({"url":url, "callback":callback, "mime":mime})
        return out

    @property
    def includes(self):
        return list(self._include.items())

    @property
    def redirects(self):
        out = list()
        for url, (file_name, required) in self._redirect.items():
            out.append({"url":url, "file_name":file_name, "required":required})
        return out

    def reset(self, dynamic_response=False, include=False, redirect=False):
        assert dynamic_response or include or redirect, "At least one kwarg should be True"
        if dynamic_response:
            self._dynamic.clear()
        if include:
            self._include.clear()
        if redirect:
            self._redirect.clear()

    def remove_dynamic_response(self, url_path):
        assert isinstance(url_path, str)
        self._dynamic.pop(url_path)

    def remove_include(self, url_path):
        assert isinstance(url_path, str)
        self._include.pop(url_path)

    def remove_redirect(self, url):
        assert isinstance(url, str)
        self._redirect.pop(url)

    def set_dynamic_response(self, url_path, callback, mime_type="application/octet-stream"):
        assert isinstance(url_path, str)
        assert callable(callback)
        assert isinstance(mime_type, str)
        self._dynamic[url_path] = (callback, mime_type)

    def set_include(self, url_path, target_path):
        assert isinstance(url_path, str)
        assert isinstance(target_path, str)
        if not os.path.isdir(target_path):
            raise IOError("%r does not exist" % (target_path,))
        self._include[url_path] = os.path.abspath(target_path)

    def set_redirect(self, url, file_name, required=True):
        assert isinstance(file_name, str)
        assert isinstance(required, bool)
        assert isinstance(url, str)
        self._redirect[url] = (file_name, required)

