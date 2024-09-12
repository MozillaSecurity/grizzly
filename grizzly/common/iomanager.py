# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

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

    def __init__(self, report_size: int = 1) -> None:
        assert report_size > 0
        self.server_map = ServerMap()
        # tests will be ordered oldest to newest
        self.tests: list[TestCase] = []
        # total number of test cases generated
        self._generated = 0
        self._report_size = report_size
        self._test: TestCase | None = None

    def __enter__(self) -> IOManager:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        self.purge()

    def commit(self) -> None:
        assert self._test is not None
        self.tests.append(self._test)
        self._test = None
        # manage testcase cache size
        if len(self.tests) > self._report_size:
            self.tests.pop(0).cleanup()

    def create_testcase(self, adapter_name: str) -> TestCase:
        assert self._test is None
        self._test = TestCase(self.page_name(), adapter_name)
        # reset redirect map
        self.server_map.set_redirect(
            "grz_current_test", self.page_name(), required=False
        )
        self.server_map.set_redirect("grz_next_test", self.page_name(offset=1))
        self._generated += 1
        return self._test

    def page_name(self, offset: int = 0) -> str:
        return f"test_{self._generated + offset:04d}.html"

    def purge(self) -> None:
        if self._test is not None:
            self._test.cleanup()
            self._test = None
        for testcase in self.tests:
            testcase.cleanup()
        self.tests.clear()
