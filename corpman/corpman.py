# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
CorpusManager is the base class that is used when creating specific corpus
managers.
"""

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

import os
import random


class TestCase(object):
    def __init__(self):
        self.fuzzed_data = None     # raw fuzzed data
        self.extension = None       # file extension
        self.template_data = None   # unfuzzed template data
        self.template_name = None   # file name of the template
        self.test_data = None       # data that will be used in test


class CorpusManager(object):
    def __init__(self, path, aggression=0.001, is_replay=False, rotate=10):
        self._can_splice = False
        self._fuzzer = None
        self._gen_count = 0 # number of test cases generated
        self._is_replay = is_replay
        self._rotate_period = 0
        self._test = None
        self._test_cases = None
        self._test_corpus = path

        self._init_fuzzer(aggression)

        self._scan_testcases()
        if not self._test_cases:
            raise IOError("Could not find test cases at %s" % path)

        if len(self._test_cases) > 1 and not is_replay:
            self._can_splice = True

        if len(self._test_cases) > 1 and not is_replay:
            self._rotate_period = rotate


    def _init_fuzzer(self, aggression):
        raise NotImplementedError("_init_fuzzer implemented in subclass")


    def _scan_testcases(self):
        self._test_cases = list()
        if os.path.isdir(self._test_corpus):
            abs_path = os.path.abspath(self._test_corpus)
            for test_file in os.listdir(abs_path):
                test_file = os.path.join(abs_path, test_file)
                if os.path.isfile(test_file) and os.path.getsize(test_file) > 0:
                    self._test_cases.append(test_file)
        elif os.path.isfile(self._test_corpus) and os.path.getsize(self._test_corpus) > 0:
            self._test_cases.append(os.path.abspath(self._test_corpus))

        # order list for replay to help manually remove items if needed
        if self._is_replay:
            # reverse since we use .pop()
            self._test_cases.sort(reverse=True)

        if not self._test_cases:
            raise IOError("Could not find test cases at %s" % self._test_corpus)


    def _load_template(self):
        self._test = TestCase()

        # rescan test case directory to pick up any new additions
        if not self._test_cases or not self._is_replay:
            self._scan_testcases()

        # choose a template
        if self._is_replay:
            self._test.template_name = self._test_cases.pop()
        elif len(self._test_cases) > 0:
            self._test.template_name = random.choice(self._test_cases)

        # load template data
        if self._test.template_name is not None:
            with open(self._test.template_name, "rb") as fp:
                self._test.template_data = fp.read()

            if "." in self._test.template_name:
                self._test.extension = self._test.template_name.split(".")[-1]


    def _rotate_template(self):
        if self._rotate_period > 0 and (self._gen_count % self._rotate_period) == 0:
            self._test = None
        elif self._is_replay:
            self._test = None

        if self._test is None:
            self._load_template()


    def dump(self, log_dir, file_prefix):
        output_name = os.path.join(log_dir, file_prefix)

        # save html test page
        with open(".".join([output_name, "html"]), "w") as fp:
            fp.write(self._test.test_data)

        # save raw test case
        if self._test.extension is not None:
            output_name = ".".join([output_name, self._test.extension])
        with open(output_name, "wb") as fp:
            fp.write(self._test.fuzzed_data)


    def generate(self):
        raise NotImplementedError("generate should be implemented in subclass")


    def get_test_case_data(self):
        if self._test is not None:
            return self._test.test_data
        return None


    def get_test_case_fname(self):
        if self._test is not None:
            return self._test.template_name
        return None


    def size(self):
        return len(self._test_cases)
