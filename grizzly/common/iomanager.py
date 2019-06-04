# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from collections import deque
import os
import random
import re

from .storage import InputFile, TestCase, TestFile

__all__ = ("IOManager", "ServerMap")
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


class IOManager(object):
    TRACKED_ENVVARS = (
        "ASAN_OPTIONS",
        "LSAN_OPTIONS",
        "GNOME_ACCESSIBILITY",
        "GRZ_FORCED_CLOSE",
        "MOZ_CHAOSMODE")

    def __init__(self, report_size=1, mime_type=None, working_path=None):
        assert report_size > 0
        self.active_input = None  # current active input file
        self.harness = None
        self.input_files = list()  # paths to files to use as a corpus
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

    def _add_suppressions(self):
        # Add suppression files to environment files
        for opt_var in (e_var for e_var in os.environ if "SAN_OPTIONS" in e_var):
            opts = os.environ.get(opt_var)
            if not opts or "suppressions" not in opts:
                continue
            for opt in re.split(r":(?![\\|/])", opts):
                if not opt.startswith("suppressions"):
                    continue
                supp_file = opt.split("=")[-1].strip("'\"")
                if os.path.isfile(supp_file):
                    fname = "%s.supp" % (opt_var.split("_")[0].lower(),)
                    self._environ_files.append(TestFile.from_file(supp_file, fname))
                    break

    def cleanup(self):
        if self.active_input is not None:
            self.active_input.close()
        if self.harness is not None:
            self.harness.close()
        for e_file in self._environ_files:
            e_file.close()
        self.purge_tests()

    def create_testcase(self, adapter_name, rotation_period=10):
        # check if we should choose a new active input file
        if self._rotation_required(rotation_period):
            assert self.input_files
            # close previous input if needed
            if self.active_input is not None:
                self.active_input.close()
            if rotation_period > 0:
                self.active_input = InputFile(random.choice(self.input_files))
            else:
                # single pass mode
                self.active_input = InputFile(self.input_files.pop())
        # create testcase object and landing page names
        test = TestCase(
            self.page_name(),
            self.page_name(offset=1),
            adapter_name=adapter_name,
            input_fname=self.active_input.file_name if self.active_input else None)
        # add environment variable info to the test case
        for e_name, e_value in self._tracked_env.items():
            test.add_environ_var(e_name, e_value)
        # add environment files to the test case
        for e_file in self._environ_files:
            test.add_meta(e_file.clone())
        # reset redirect map
        self.server_map.reset(redirect=True)
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

    def redirect_page(self):
        return self.page_name(offset=1)

    def _rotation_required(self, rotation_period):
        if not self.input_files:
            # only rotate if we have input files
            return False
        if self.active_input is None:
            # we need a file
            return True
        if not rotation_period:
            # single pass mode
            return True
        if len(self.input_files) < 2:
            # single pass mode
            return False
        if not self._generated % rotation_period:
            return True
        return False

    def scan_input(self, scan_path, accepted_extensions=None, sort=False):
        assert scan_path is not None, "scan_path should be a valid path"
        if os.path.isdir(scan_path):
            # create a set of normalized file extensions to look in
            if accepted_extensions is not None:
                normalized_exts = set(ext.lstrip(".").lower() for ext in accepted_extensions)
            else:
                normalized_exts = set()

            # ignored_list is a list of ignored files (usually auto generated OS files)
            ignored_list = ("desktop.ini", "thumbs.db")
            for d_name, _, filenames in os.walk(scan_path):
                for f_name in filenames:
                    # check for unwanted files
                    if f_name.startswith(".") or f_name.lower() in ignored_list:
                        continue
                    if normalized_exts:
                        ext = os.path.splitext(f_name)[1].lstrip(".").lower()
                        if ext not in normalized_exts:
                            continue
                    input_file = os.path.abspath(os.path.join(d_name, f_name))
                    # skip empty files
                    if os.path.getsize(input_file) > 0:
                        self.input_files.append(input_file)
        elif os.path.isfile(scan_path) and os.path.getsize(scan_path) > 0:
            self.input_files.append(os.path.abspath(scan_path))

        if sort and self.input_files:
            self.input_files.sort(reverse=True)

    @staticmethod
    def tracked_environ():
        # Scan os.environ and collect environment variables
        # that are relevant to Grizzly or the test case.
        env = dict()
        for e_var in IOManager.TRACKED_ENVVARS:
            if e_var not in os.environ:
                continue
            if e_var in ("ASAN_OPTIONS", "LSAN_OPTIONS"):
                # strip unwanted options
                # FFPuppet ensures that this is formatted correctly
                track = ("detect_leaks",)
                opts = list()
                for opt in re.split(r":(?![\\|/])", os.environ[e_var]):
                    if opt.split("=")[0] in track:
                        opts.append(opt)
                # only record *SAN_OPTIONS if there are options
                if opts:
                    env[e_var] = ":".join(opts)
            else:
                env[e_var] = os.environ[e_var]
        return env
