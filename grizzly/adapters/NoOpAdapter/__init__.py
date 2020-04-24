# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from grizzly.common import Adapter

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class NoOpAdapter(Adapter):
    """
    This is an simple adapter that has very little overhead. It can be used
    to get a baseline iteration rate for Grizzly.
    """
    NAME = "no-op"

    def setup(self, *_):
        self.enable_harness()
        self.fuzz["test"] = "<!DOCTYPE html>\n" \
            "<html>\n" \
            "<head>\n" \
            "<script>window.close()</script>\n" \
            "</head>\n" \
            "</html>"

    def generate(self, testcase, _):
        testcase.add_from_data(self.fuzz["test"], testcase.landing_page)
