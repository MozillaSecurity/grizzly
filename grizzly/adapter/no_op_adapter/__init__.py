# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from grizzly.adapter import Adapter

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class NoOpAdapter(Adapter):
    """This is a simple adapter that has very little overhead. It can be used
    to help measure a baseline iteration rate for Grizzly.
    """

    NAME = "no-op"

    def setup(self, _input, _server_map):
        """Generate a static test case that calls `window.close()` when run.
        Normally this is done in generate() but since the test is static only
        do it once. Use the default harness to allow running multiple test cases
        in a row without closing the browser after each one.

        Args:
            _input (str): Unused.
            _server_map (sapphire.server_map.ServerMap): Unused.

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

    def generate(self, testcase, _server_map):
        """Since the test case has already been created just add the data to the
        TestCase.

        Also all TestCases require an entry point and the one expected by Grizzly
        is provided in `testcase.landing_page` so use it as the file name for
        the test.

        Args:
            testcase (grizzly.common.storage.TestCase): TestCase to be populated.
            _server_map (sapphire.server_map.ServerMap): Unused.

        Returns:
            None
        """
        testcase.add_from_bytes(self.fuzz["test"], testcase.landing_page)
