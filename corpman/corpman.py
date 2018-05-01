# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import os
import random
import shutil
import tempfile

from .browser_monitor import BrowserMonitor

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class InputFile(object):
    MEMORY_BUF_LIMIT = 0xA00000 # 10MB

    def __init__(self, file_name):
        self.extension = None # file extension
        self.file_name = file_name
        self.fp = None

        if self.file_name is None or not os.path.isfile(file_name):
            raise IOError("File does %r does not exist" % self.file_name)

        if "." in self.file_name:
            self.extension = os.path.splitext(self.file_name)[-1].lstrip(".")


    def _cache_data(self):
        self.fp = tempfile.SpooledTemporaryFile(max_size=self.MEMORY_BUF_LIMIT)
        with open(self.file_name, "rb") as src_fp:
            shutil.copyfileobj(src_fp, self.fp, 0x10000) # 64KB


    def close(self):
        if self.fp is not None:
            self.fp.close()
        self.fp = None


    def get_data(self):
        """
        get_data()
        Provide the raw input file data to the caller.

        returns input file data from file.read()
        """

        if self.fp is None:
            self._cache_data()
        self.fp.seek(0)
        return self.fp.read() # TODO: add size limit


    def get_fp(self):
        if self.fp is None:
            self._cache_data()
        self.fp.seek(0)
        return self.fp


class TestCase(object):
    def __init__(self, landing_page, corpman_name, input_fname=None):
        self.corpman_name = corpman_name
        self.landing_page = landing_page
        self.input_fname = input_fname # file that was use to create the test case
        self._env_files = dict() # # environment files: prefs.js, etc...
        self._env_vars = dict() # environment variables required
        self._optional_files = [] # contains TestFile(s) that are not strictly required
        self._test_files = [] # contains TestFile(s) that make up a test case


    def add_environ_file(self, full_path, fname=None):
        full_path = os.path.abspath(full_path)
        if not os.path.isfile(full_path):
            raise IOError("Could not find environ file %r" % full_path)
        if fname is None:
            fname = os.path.basename(full_path)
        self._env_files[fname] = full_path


    def add_environ_var(self, var_name, value):
        self._env_vars[var_name] = value


    def add_testfile(self, test_file):
        if not isinstance(test_file, TestFile):
            raise TypeError("add_testfile() only accepts TestFile objects")

        self._test_files.append(test_file)
        if not test_file.required:
            self._optional_files.append(test_file.file_name)


    def dump(self, log_dir, include_details=False):
        """
        dump(log_dir)
        Write all the test case data to the filesystem.
        This includes:
        - the generated test case
        - details of input file used
        All data will be located in log_dir.

        returns None
        """

        # save test file page
        for test_file in self._test_files:
            target_path = os.path.join(log_dir, os.path.dirname(test_file.file_name))
            if not os.path.isdir(target_path):
                os.makedirs(target_path)
            with open(os.path.join(log_dir, test_file.file_name), "wb") as out_fp:
                if isinstance(test_file.data, bytes) or not test_file.encoding:
                    out_fp.write(test_file.data)
                else:
                    out_fp.write(test_file.data.encode(test_file.encoding))

        # save test case, input file, file information, environment info
        if include_details:
            with open(os.path.join(log_dir, "test_info.txt"), "w") as out_fp:
                out_fp.write("[Grizzly test case details]\n")
                out_fp.write("Corpus Manager:    %s\n" % self.corpman_name)
                out_fp.write("Landing Page:      %s\n" % self.landing_page)
                if self.input_fname is not None:
                    out_fp.write("Input File:        %s\n" % os.path.basename(self.input_fname))

            for env_file, env_path in self._env_files.items():
                shutil.copyfile(env_path, os.path.join(log_dir, env_file))

            if self._env_vars.items():
                with open(os.path.join(log_dir, "env_vars.txt"), "w") as out_fp:
                    for env_var, env_val in self._env_vars.items():
                        out_fp.write("%s=%s\n" % (env_var, env_val))


    def get_optional(self):
        if self._optional_files:
            return self._optional_files
        return None


class TestFile(object):
    def __init__(self, file_name, data, encoding="UTF-8", required=True):
        self.data = data
        self.encoding = encoding
        self.file_name = os.path.normpath(file_name) # name including path relative to wwwroot
        self.required = required # this file must be served to complete test case

        # XXX: This is a naive fix for a larger path issue
        if "\\" in self.file_name:
            self.file_name.replace("\\", "/")
        self.file_name = self.file_name.lstrip("/")


class CorpusManager(object):
    """
    CorpusManager is the base class that is used when creating specific corpus
    managers.
    """

    key = None # this must be overloaded in the subclass

    def __init__(self, path, accepted_extensions=None):
        self.abort_tokens = list() # tokens that when added to the log with trigger an abort
        self.input_files = list() # fuzzed test cases will be based on these files
        self.br_mon = BrowserMonitor() # provide browser details
        self.rotation_period = 10 # input file rotation period
        self.single_pass = False # only run each input file for one rotation period
        self.test_duration = 30000 # used by the html harness to redirect to next testcase
        self._active_input = None
        self._corpus_path = os.path.abspath(path)
        if not os.path.isdir(path):
            self._corpus_path = os.path.dirname(self._corpus_path)
        self._environ = dict() # recorded environment variables
        self._environ_files = dict() # collection of files that should be added to the testcase
        self._fuzzer = None # meant for fuzzer specific data
        self._generated = 0 # number of test cases generated
        self._harness = None # dict holding the name and data of the in browser grizzly test harness
        self._srv_map = {  # TODO: should this be standalone object?
            "dynamic": dict(),
            "include": dict(),  # mapping of directories that can be requested
            "redirect": dict()  # document paths to map to file names using 307s
        }
        self._use_transition = True # use transition redirect to next test case

        self._scan_input(path, accepted_extensions)
        self._init_fuzzer()
        self._add_suppressions()
        if self.single_pass and self.input_files:
            self.input_files.sort(reverse=True)


    def _init_fuzzer(self):
        """
        _init_fuzzer is meant to be implemented in subclass
        """
        pass


    def _add_dynamic_response(self, url_path, callback, mime_type="application/octet-stream"):
        self._srv_map["dynamic"][url_path] = (callback, mime_type)


    def _add_include(self, url_path, target_path):
        if not os.path.isdir(target_path):
            raise IOError("%r does not exist")
        self._srv_map["include"][url_path] = os.path.abspath(target_path)


    def _add_suppressions(self):
        # Add suppression files to environment files
        for san_opts in [san_opt for san_opt in os.environ if ("SAN_OPTIONS" in san_opt)]:
            env_var = os.environ.get(san_opts)
            if not env_var or "suppressions" not in env_var:
                continue
            for opt in env_var.split(":"):
                if not opt.startswith("suppressions"):
                    continue
                supp_file = opt.split("=")[-1]
                if os.path.isfile(supp_file):
                    fname = "%s.supp" % san_opts.split("_")[0].lower()
                    self._environ_files[fname] = supp_file
                    break


    def _select_active_input(self):
        if self.single_pass:
            assert self.rotation_period > 0, "rotation_period must be greater than zero"
        else:
            assert self.rotation_period > -1, "rotation_period must not be negative"

        # check if we should choose a new active input file
        if self.rotation_period > 0 and (self._generated % self.rotation_period) == 0:
            # only switch input files if we have more than one
            if self._active_input is not None:
                if len(self.input_files) > 1 or self.single_pass:
                    self._active_input.close()
                    self._active_input = None

        # choose an input file
        if self._active_input is None:
            if self.single_pass:
                self._active_input = InputFile(self.input_files.pop())
            else:
                self._active_input = InputFile(random.choice(self.input_files))


    def _set_redirect(self, url, file_name, required=True):
        self._srv_map["redirect"][url] = (file_name, required)


    def _scan_input(self, scan_path, accepted_extensions):
        # ignored_list is a list of ignored files (usually auto generated OS files)
        ignored_list = ["desktop.ini", "thumbs.db"]

        if os.path.isdir(scan_path):
            # create a set of normalized file extensions to look in
            normalized_exts = set()
            if accepted_extensions:
                for ext in accepted_extensions:
                    normalized_exts.add(ext.lstrip(".").lower())

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

        # TODO: should we force CMs to have input files???
        if not self.input_files:
            raise IOError("Could not find input files(s) at %s" % scan_path)


    @staticmethod
    def to_data_url(data, mime_type=None):
        if mime_type is None:
            mime_type = "application/octet-stream"
        return "data:%s;base64,%s" % (mime_type, base64.standard_b64encode(data))


    def add_abort_token(self, tokens):
        self.abort_tokens.append(tokens)


    def cleanup(self):
        if self._active_input is not None:
            self._active_input.close()
        self.close()


    def close(self):
        """
        close is meant to be implemented in subclass.
        This is where any clean up should be performed.
        """
        pass


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
        self._select_active_input()

        # create test case object and landing page names
        test = TestCase(
            self.landing_page(),
            corpman_name=self.key,
            input_fname=self._active_input.file_name)

        # add environment variable info to test case
        # TODO: make this more like env_files
        for key, (value, _) in self._environ.items():
            if key in os.environ:
                test.add_environ_var(key, value)

        for fname, fpath in self._environ_files.items():
            test.add_environ_file(fpath, fname)

        # reset redirect map
        self._srv_map["redirect"] = {}

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

    @property
    def active_file(self):
        try:
            return self._active_input.file_name
        except AttributeError:
            return None


    @property
    def dynamic_responses(self):
        out = list()
        for url, (callback, mime) in self._srv_map["dynamic"].items():
            out.append({"url":url, "callback":callback, "mime":mime})
        return out


    @property
    def includes(self):
        return self._srv_map["include"].items()


    @property
    def redirects(self):
        out = list()
        for url, (file_name, required) in self._srv_map["redirect"].items():
            out.append({"url":url, "file_name":file_name, "required":required})
        return out


    def landing_page(self, harness=False, next=False, transition=False):
        if harness and self._harness is not None:
            return self._harness["name"]
        if transition:
            return "next_test" # point to redirect
        return "test_page_%04d.html" % ((self._generated + 1) if next else self._generated)


    def record_envvar(self, var_name, required=False):
        var_name = var_name.upper()
        # grab currently set value if available
        if var_name in os.environ:
            self._environ[var_name] = (os.environ[var_name], required)
        elif required:
            raise RuntimeError("Missing required environment variable %r" % var_name)


    def size(self):
        return len(self.input_files)


    def finish_test(self, test, files_served=None):
        """
        finish_test is meant to be implemented in subclass
        """
        pass
