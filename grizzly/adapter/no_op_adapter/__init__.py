# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from typing import TYPE_CHECKING

from ..adapter import Adapter

if TYPE_CHECKING:
    from sapphire import ServerMap

    from ...common.storage import TestCase

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class NoOpAdapter(Adapter):
    """This is a simple adapter that has very little overhead. It can be used
    to help measure a baseline iteration rate for Grizzly.
    """

    NAME = "no-op"

    def setup(self, input_path: str | None, server_map: ServerMap) -> None:
        """Generate a static test case that calls `window.close()` when run.
        Normally this is done in generate() but since the test is static only
        do it once. Use the default harness to allow running multiple test cases
        in a row without closing the browser after each one.

        Args:
            _input: Unused.
            _server_map: Unused.

        Returns:
            None
        """
        self.enable_harness()
        self.fuzz["test"] = (
            b"<!DOCTYPE html>\n"
            b"<html>\n"
            b"<head>\n"
            b"<script>window.close()</script>\n"
            b"</head>\n"
            b"</html>"
        )

    def generate(self, testcase: TestCase, server_map: ServerMap) -> None:
        """The test case contents have been created now add the data to the TestCase.

        All TestCases require an entry point and the one expected by Grizzly
        is provided in `testcase.entry_point` so use it as the file name for
        the test.

        Args:
            testcase: TestCase to be populated.
            _server_map: Unused in this example.

        Returns:
            None
        """
        testcase.add_from_bytes(self.fuzz["test"], testcase.entry_point, required=True)
