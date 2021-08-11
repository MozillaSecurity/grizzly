# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from enum import Enum, unique
from random import randint

from grizzly.adapter import Adapter

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


@unique
class Mode(Enum):
    # normal fuzzing operation, generate test cases
    FUZZ = 0
    # reduce mode, apply reduction operations to a single test
    REDUCE = 1
    # no more reductions can be performed indicate we are complete
    REPORT = 2


class FeedbackAdapter(Adapter):
    """FeedbackAdapter"""

    NAME = "feedback-example"

    def setup(self, _input, server_map):
        # indicates if a result was found
        self.fuzz["found"] = False
        # current operation mode
        self.fuzz["mode"] = Mode.FUZZ
        self.enable_harness()
        # adds '/found' to server so the test case/browser can send 'signals'
        # back to the framework
        server_map.set_dynamic_response("found", self._found)

    def _found(self):
        self.fuzz["found"] = True
        return b""

    def generate(self, testcase, _server_map):
        if self.fuzz["mode"] == Mode.REDUCE:
            # are we done reduction?
            if randint(0, 10) == 5:
                # let's say we are done
                self.fuzz["mode"] = Mode.REPORT
            else:
                # generate next reduced version to test
                pass

        if self.fuzz["mode"] == Mode.REPORT:
            # here we should force crash the browser so grizzly detects a result
            # see bug https://bugzilla.mozilla.org/show_bug.cgi?id=1725008
            # finish_op = "FuzzingFunctions.moz_crash()"
            finish_op = "setTimeout(window.close, 10)"
            # return to fuzzing mode
            self.fuzz["mode"] = Mode.FUZZ
        else:
            finish_op = "setTimeout(window.close, 10)"

        # generate a test
        test_data = (
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "<script>\n"
            "window.onload = async () => {\n"
            "  if (Math.floor((Math.random() * 30) + 1) == 1) {\n"
            '    await fetch("/found")\n'
            "  }\n"
            "  %s\n"
            "}\n"
            "</script>\n"
            "</head>\n"
            "<body><h1>%s</h1></body>\n"
            "</html>"
        ) % (finish_op, self.fuzz["mode"].name)
        # add to testcase as entry point
        testcase.add_from_data(test_data, testcase.landing_page)

    def on_served(self, _test, _served):
        # check if a result was detected
        if self.fuzz["found"]:
            # enable reduction mode
            if self.fuzz["mode"] == Mode.FUZZ:
                self.fuzz["mode"] = Mode.REDUCE
            self.fuzz["found"] = False

    def on_timeout(self, _test, _served):
        self.fuzz["found"] = False
