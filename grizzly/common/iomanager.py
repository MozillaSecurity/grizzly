# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from collections import deque
import os

from sapphire.server_map import ServerMap
from .storage import TestCase, TestFile
from ..target import sanitizer_opts


__all__ = ("IOManager",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class IOManager(object):
    TRACKED_ENVVARS = (
        "ASAN_OPTIONS",
        "LSAN_OPTIONS",
        "GNOME_ACCESSIBILITY",
        "GRZ_FORCED_CLOSE",
        "MOZ_CHAOSMODE")

    def __init__(self, report_size=1, mime_type=None, working_path=None):
        assert report_size > 0
        self.harness = None
        self.server_map = ServerMap()  # manage redirects, include directories and dynamic responses
        self.tests = deque()
        self.working_path = working_path
        self._environ_files = list()  # collection of files that should be added to the testcase
        self._generated = 0  # number of test cases generated
        self._mime = mime_type
        self._report_size = report_size
        # used to record environment variable that directly impact the browser
        self._tracked_env = self.tracked_environ()
        self._add_suppressions()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def _add_suppressions(self):
        # Add suppression files to environment files
        for env_var in (e_var for e_var in os.environ if "SAN_OPTIONS" in e_var):
            opts = sanitizer_opts(os.environ.get(env_var, ""))
            if "suppressions" not in opts:
                continue
            supp_file = opts["suppressions"].strip("'\"")
            if os.path.isfile(supp_file):
                fname = "%s.supp" % (env_var.split("_")[0].lower(),)
                self._environ_files.append(TestFile.from_file(supp_file, fname))

    def cleanup(self):
        if self.harness is not None:
            self.harness.close()
        for e_file in self._environ_files:
            e_file.close()
        self.purge_tests()

    def create_testcase(self, adapter_name):
        # create testcase object and landing page names
        test = TestCase(
            self.page_name(),
            self.page_name(offset=1),
            adapter_name=adapter_name)
        # add environment variable info to the test case
        for e_name, e_value in self._tracked_env.items():
            test.add_environ_var(e_name, e_value)
        # add environment files to the test case
        for e_file in self._environ_files:
            test.add_meta(e_file.clone())
        # reset redirect map
        self.server_map.redirect.clear()
        if self.harness is not None:
            # setup redirects for harness
            self.server_map.set_redirect("first_test", self.page_name(), required=False)
            self.server_map.set_redirect("next_test", self.page_name(offset=1))
            # add harness to testcase
            test.add_file(self.harness.clone(), required=False)
        self._generated += 1
        self.tests.append(test)
        # manage testcase cache size
        if len(self.tests) > self._report_size:
            self.tests.popleft().cleanup()
        return test

    def landing_page(self):
        if self.harness is None:
            return self.page_name()
        return self.harness.file_name

    def page_name(self, offset=0):
        return "test_%04d.html" % (self._generated + offset,)

    def purge_tests(self):
        for testcase in self.tests:
            testcase.cleanup()
        self.tests.clear()

    @staticmethod
    def tracked_environ():
        # Scan os.environ and collect environment variables
        # that are relevant to Grizzly or the test case.
        env = dict()
        tracked_san_opts = ("detect_leaks",)
        for e_var in IOManager.TRACKED_ENVVARS:
            if e_var not in os.environ:
                continue
            if e_var.endswith("SAN_OPTIONS"):
                opts = sanitizer_opts(os.environ.get(e_var, ""))
                # strip unwanted options
                tracked = dict()
                for opt in tracked_san_opts:
                    if opt in opts:
                        tracked[opt] = opts[opt]
                # only record *SAN_OPTIONS if there are options
                if tracked:
                    env[e_var] = ":".join("=".join((k, v)) for k, v in tracked.items())
            else:
                env[e_var] = os.environ[e_var]
        return env
