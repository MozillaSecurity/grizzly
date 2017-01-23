# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import hashlib
import os
import random

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class Template(object):
    def __init__(self, file_name):
        self._data = None # file data
        self._data_hash = None # SHA1 hash of data
        self.extension = None # file extension
        self.file_name = file_name # file name of the template

        if self.file_name is None:
            raise IOError("File does not exist: %s" % self.file_name)

        if "." in self.file_name:
            self.extension = os.path.splitext(self.file_name)[1].lstrip(".")


    def _load_and_hash_data(self):
        # read data from disk
        if not os.path.isfile(self.file_name):
            raise IOError("File does not exist: %s" % self.file_name)
        with open(self.file_name, "rb") as in_fp:
            self._data = in_fp.read()

        # calculate SHA1 hash
        self._data_hash = hashlib.sha1(self._data).hexdigest()


    def get_data(self):
        """
        get_data()
        Provide the raw template data to the caller. If data has not been loaded
        _load_and_hash_data() is called

        returns template data from file.read()
        """

        # load template data the first time it is requested
        if self._data is None:
            self._load_and_hash_data()

        return self._data


    def get_hash(self):
        """
        get_hash()
        Provide the template data hash to the caller. If the SHA1 hash has not been calculated yet
        _load_and_hash_data() is called.

        returns SHA1 hash string
        """

        if self._data_hash is None:
            self._load_and_hash_data()

        return self._data_hash


class TestCase(object):
    def __init__(self, landing_page, corpman_name, template=None):
        self.corpman_name = corpman_name
        self.landing_page = landing_page
        self.template = template
        self._test_files = [] # contains TestFile(s) that make up a test case
        self._optional_files = [] # contains TestFile(s) that are not strictly required


    def add_testfile(self, test_file):
        if not isinstance(test_file, TestFile):
            raise TypeError("add_testfile() only accepts TestFile objects")

        self._test_files.append(test_file)
        if not test_file.required:
            self._optional_files.append(test_file.file_name)


    def dump(self, log_dir, info_file=False):
        """
        dump(log_dir)
        Write all the test case data to the filesystem.
        This includes:
        - the generated test case
        - template file details
        All data will be located in log_dir.

        returns None
        """

        # save test file page
        for test_file in self._test_files:
            with open(os.path.join(log_dir, test_file.file_name), "wb") as out_fp:
                out_fp.write(test_file.data)

        # save test case and template file information
        if info_file:
            with open(os.path.join(log_dir, "test_info.txt"), "w") as out_fp:
                out_fp.write("[Grizzly template/test case details]\n")
                out_fp.write("Corpus Manager: %s\n" % self.corpman_name)
                out_fp.write("Landing Page:   %s\n" % self.landing_page)
                if self.template is not None:
                    out_fp.write("Template File:  %s\n" % os.path.basename(self.template.file_name))
                    out_fp.write("Template SHA1:  %s\n" % self.template.get_hash())


    def get_optional(self):
        if self._optional_files:
            return self._optional_files
        return None


class TestFile(object):
    def __init__(self, file_name, data, required=True):
        self.file_name = file_name # name including path relative to wwwroot
        self.data = data
        self.required = required # this file must be served to complete test case


class CorpusManager(object):
    """
    CorpusManager is the base class that is used when creating specific corpus
    managers.
    """

    key = None # this must be overloaded in the subclass

    def __init__(self, path, accepted_extensions=None, aggression=0.001, is_replay=False, rotate=10):
        self.test_duration = 5000 # used by the html harness to redirect to next testcase
        self._active_template = None
        self._corpus_path = path # directory to look for template files in
        self._fuzzer = None
        self._generated = 0 # number of test cases generated
        self._harness = None # dict holding the name and data of the in browser grizzly test harness
        self._include_map = {} # mapping of directories that can be requested
        self._is_replay = is_replay
        self._redirect_map = {} # document paths to map to file names using 307s
        self._rotate_period = 0 if is_replay else rotate # how often a new template is selected
        self._templates = list() # fuzzed test cases will be based on these files
        self._use_transition = True # use transition redirect to next test case

        self._init_fuzzer(aggression)
        self._scan_for_templates(accepted_extensions)


    def _init_fuzzer(self, aggression):
        """
        _init_fuzzer is meant to be implemented in subclass
        """
        pass


    def _add_include(self, url_path, target_path):
        if not os.path.isdir(target_path):
            raise IOError("%r does not exist")
        self._include_map[url_path] = os.path.abspath(target_path)


    def _set_redirect(self, url, file_name, required=True):
        self._redirect_map[url] = (file_name, required)


    def _scan_for_templates(self, accepted_extensions=None):
        # ignored_list is a list of ignored files (usually auto generated OS files)
        ignored_list = ["desktop.ini", "thumbs.db"]

        if os.path.isdir(self._corpus_path):
            # create a set of normalized file extensions to look in
            normalized_exts = set()
            if accepted_extensions:
                for ext in accepted_extensions:
                    normalized_exts.add(ext.lstrip(".").lower())

            for d_name, _, filenames in os.walk(self._corpus_path):
                for f_name in filenames:
                    # check for unwanted files
                    if f_name.startswith(".") or f_name.lower() in ignored_list:
                        continue
                    if normalized_exts:
                        ext = os.path.splitext(f_name)[1].lstrip(".").lower()
                        if ext not in normalized_exts:
                            continue
                    test_file = os.path.abspath(os.path.join(d_name, f_name))
                    # skip empty files
                    if os.path.getsize(test_file) > 0:
                        self._templates.append(test_file)
        elif os.path.isfile(self._corpus_path) and os.path.getsize(self._corpus_path) > 0:
            self._templates.append(os.path.abspath(self._corpus_path))

        # TODO: should we force CMs to have templates???
        if not self._templates:
            raise IOError("Could not find test case(s) at %s" % self._corpus_path)

        # order list for replay to help manually remove items if needed
        if self._is_replay:
            # reverse since we use .pop()
            self._templates.sort(reverse=True)


    @staticmethod
    def to_data_url(data, mime_type=None):
        if mime_type is None:
            mime_type = "application/octet-stream"
        return "data:%s;base64,%s" % (mime_type, base64.standard_b64encode(data))


    def enable_harness(self, file_name=None, harness_data=None):
        self._use_transition = False
        self._harness = {}
        if file_name is None:
            self._harness["name"] = "grizzly_fuzz_harness.html"
        else:
            self._harness["name"] = file_name

        if harness_data is None:
            with open(os.path.join(os.path.dirname(__file__), "harness.html"), "r") as in_fp:
                self._harness["data"] = in_fp.read()
        else:
            self._harness["data"] = harness_data


    def _generate(self, test, redirect_page, mime_type=None):
        raise NotImplementedError("_generate must be implemented in the subclass")


    def generate(self, mime_type=None):
        # check if we should choose a new active template
        if self._rotate_period > 0 and (self._generated % self._rotate_period) == 0:
            # only switch templates if we have more than one
            if len(self._templates) > 1:
                self._active_template = None

        # choose a template
        if self._is_replay:
            self._active_template = Template(self._templates.pop())
        elif self._active_template is None:
            self._active_template = Template(random.choice(self._templates))

        # create test case object and landing page names
        test = TestCase(
            self.landing_page(),
            corpman_name=self.key,
            template=self._active_template)

        # reset redirect map
        self._redirect_map = {}

        # handle page redirects (to next test case)
        if self._use_transition:
            redirect_page = self.landing_page(transition=True)
            self._set_redirect(redirect_page, self.landing_page(next=True))
        else:
            redirect_page = self.landing_page(next=True)

        if self._harness:
            # setup redirects for harness
            self._set_redirect("first_test", self.landing_page(), required=False)
            self._set_redirect("next_test", self.landing_page(next=True))
            # add harness to test case
            test.add_testfile(
                TestFile(self._harness["name"], self._harness["data"], required=False))

        self._generate(test, redirect_page, mime_type=mime_type)
        self._generated += 1

        return test


    def get_active_file_name(self):
        try:
            return self._active_template.file_name
        except AttributeError:
            return None


    def get_includes(self):
        return self._include_map.items()


    def get_redirects(self):
        out = []
        for url, (file_name, required) in self._redirect_map.items():
            out.append({"url":url, "file_name":file_name, "required":required})
        return out


    def landing_page(self, harness=False, next=False, transition=False):
        if harness and self._harness is not None:
            return self._harness["name"]
        if transition:
            return "next_test" # point to redirect
        return "test_page_%04d.html" % ((self._generated + 1) if next else self._generated)


    def size(self):
        return len(self._templates)


    def finish_test(self, clone_log_cb, test, files_served=None):
        """
        finish_test is meant to be implemented in subclass
        """
        return None
