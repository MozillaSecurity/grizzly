# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import grizzly.corpman
from grizzly.corpman.storage import TestFile

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class NoOpAdapter(grizzly.corpman.Adapter):
    """
    This is an simple adapter that has very little overhead. It can be used
    to get a baseline iteration rate for Grizzly.
    """
    NAME = "no-op"

    def setup(self, _):
        self.enable_harness()
        self.fuzz["test"] = "\n".join([
            "<html>",
            "<head>",
            "<script>",
            "window.close()",
            "</script>",
            "</head>",
            "</html>"])


    def generate(self, testcase, *_):
        testcase.add_file(TestFile.from_data(self.fuzz["test"], testcase.landing_page))
