# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os

from .storage import TestFile

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class Adapter(object):
    HARNESS_FILE = os.path.join(os.path.dirname(__file__), "harness.html")
    NAME = None  # must be set by subclass
    ROTATION_PERIOD = 10  # iterations per input file before switching
    TEST_DURATION = 30  # maximum execution time per test

    #############################
    # Builtins do NOT overload!
    #############################

    def __init__(self):
        if self.NAME is None:
            raise NotImplementedError("NAME member must be set by subclass")
        self._harness = None
        self.fuzz = dict()
        self.monitor = None


    def cleanup(self):
        if self._harness is not None:
            self._harness.close()
            self._harness = None
        self.shutdown()


    def enable_harness(self, file_path=None):
        if self._harness is not None:
            self._harness.close()
        self._harness = TestFile.from_file(
            self.HARNESS_FILE if file_path is None else file_path,
            "grizzly_fuzz_harness.html")


    def get_harness(self):
        return self._harness


    #############################
    # Methods to overload
    #############################

    def generate(self, testcase, server_map):
        raise NotImplementedError("Must be implemented by subclass")


    def on_served(self, testcase, served):
        pass


    def on_timeout(self, testcase, served):
        # by default call on_served
        self.on_served(testcase, served)


    def setup(self, server_map):
        pass


    def shutdown(self):
        pass
