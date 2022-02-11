# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from collections import deque

from sapphire.server_map import ServerMap

from .storage import TestCase

__all__ = ("IOManager",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class IOManager:
    __slots__ = (
        "_generated",
        "_report_size",
        "_test",
        "server_map",
        "tests",
    )

    def __init__(self, report_size=1):
        assert report_size > 0
        self.server_map = ServerMap()
        self.tests = deque()
        self._generated = 0  # number of test cases generated
        self._report_size = report_size
        self._test = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def cleanup(self):
        self.purge()

    def commit(self):
        assert self._test is not None
        self.tests.appendleft(self._test)
        self._test = None
        # manage testcase cache size
        if len(self.tests) > self._report_size:
            self.tests.pop().cleanup()

    def create_testcase(self, adapter_name, time_limit):
        assert self._test is None
        # create testcase object and landing page names
        self._test = TestCase(
            self.page_name(),
            self.page_name(offset=1),
            adapter_name=adapter_name,
            time_limit=time_limit,
        )
        # reset redirect map
        self.server_map.set_redirect(
            "grz_current_test", self.page_name(), required=False
        )
        self.server_map.set_redirect("grz_next_test", self.page_name(offset=1))
        self._generated += 1
        return self._test

    def page_name(self, offset=0):
        return "test_%04d.html" % (self._generated + offset,)

    def purge(self):
        if self._test is not None:
            self._test.cleanup()
            self._test = None
        for testcase in self.tests:
            testcase.cleanup()
        self.tests.clear()
