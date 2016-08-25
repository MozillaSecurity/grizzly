# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import shutil
import tempfile
import time

import stack_hasher
#from FuzzManager.Collector.Collector import Collector

__all__ = ("FilesystemReporter")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

def create_log(path=None):
    fd, file_name = tempfile.mkstemp(
        dir=path,
        prefix="grizzly_",
        suffix="_log.txt"
    )
    os.close(fd)

    return file_name


class Reporter(object):
    def __init__(self, ignore_stackless=False):
        self._file_prefix = None # prefix for results
        self._ignore_stackless = ignore_stackless
        self._log_path = tempfile.mkdtemp(prefix="grz_report_")
        self._major = None # stack hash
        self._minor = None # stack hash
        self.log_file = create_log(self._log_path)


    def _process_log(self):
        # parse log file
        with open(self.log_file) as log_fp:
            stack = stack_hasher.stack_from_text(log_fp.read())

        if self._ignore_stackless and not stack:
            return False

        # calculate hashes
        self._minor = stack_hasher.stack_to_hash(stack)
        if self._minor is not None:
            self._major = stack_hasher.stack_to_hash(stack, major=True)
        else:
            self._minor = "0"
            self._major = "NO_STACK"

        self._file_prefix = "%s_%s" % (self._minor[:8], time.strftime("%Y-%m-%d_%H-%M-%S"))

        return True


    def _report(self, *args, **kwargs):
        raise NotImplementedError("_report must be implemented in the subclass")


    def report(self, *args, **kwargs):
        if self._process_log():
            self._report(*args, **kwargs)
        if os.path.isdir(self._log_path):
            shutil.rmtree(self._log_path)


class FilesystemReporter(Reporter):
    def _report(self, test_cases, results_path=None):
        if results_path is None:
            results_path = os.path.join(os.getcwd(), "results")

        # create results directory if needed
        if not os.path.isdir(results_path):
            os.mkdir(results_path)

        # create major bucket directory in working directory if needed
        major_dir = os.path.join(results_path, self._major)
        if not os.path.isdir(major_dir):
            os.mkdir(major_dir)

        # dump results to working dirctory
        for test_number, test_case in enumerate(test_cases):
            test_case.dump(major_dir, "%s-%d" % (self._file_prefix, test_number))

        # move log into bucket directory
        shutil.move(self.log_file, "%s.log.txt" % os.path.join(major_dir, self._file_prefix))
