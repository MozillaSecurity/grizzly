# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import logging
import os
import shutil
import tempfile
import time
import zipfile

# check if required FuzzManager modules are available
try:
    from Collector.Collector import Collector
    from FTB.ProgramConfiguration import ProgramConfiguration
    from FTB.Signatures.CrashInfo import CrashInfo
    import fasteners
    _fm_import_error = None
except ImportError as err:
    _fm_import_error = err

import stack_hasher

__all__ = ("FilesystemReporter", "FuzzManagerReporter")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


log = logging.getLogger("grizzly") # pylint: disable=invalid-name


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


    @staticmethod
    def tail(in_file, size_limit):
        with open(in_file, "r") as in_fp:
            # check if tail is needed
            in_fp.seek(0, os.SEEK_END)
            if in_fp.tell() <= size_limit:
                return # no tail needed

            # perform tail operation
            in_fp.seek(size_limit * -1, os.SEEK_END)
            out_file = create_log()
            with open(out_file, "w") as out_fp:
                out_fp.write("[LOG TAILED]\n")
                out_fp.write(in_fp.read())

        os.remove(in_file)
        shutil.move(out_file, in_file)


class FilesystemReporter(Reporter):
    def _report(self, test_cases, results_path=None, log_limit=0):
        if log_limit > 0:
            self.tail(self.log_file, log_limit)

        if results_path is None:
            results_path = os.path.join(os.getcwd(), "results")

        # create results directory if needed
        if not os.path.isdir(results_path):
            os.mkdir(results_path)

        # create major bucket directory in working directory if needed
        major_dir = os.path.join(results_path, self._major)
        if not os.path.isdir(major_dir):
            os.mkdir(major_dir)

        # dump test cases and the contained files to working directory
        for test_number, test_case in enumerate(test_cases):
            dump_path = os.path.join(major_dir, "%s-%d" % (self._file_prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)

        # rename and move log into bucket directory
        shutil.move(self.log_file, "%s_log.txt" % os.path.join(major_dir, self._file_prefix))


class FuzzManagerReporter(Reporter):
    # this is where Collector looks for the '.fuzzmanagerconf' (see Collector.py)
    fm_config = os.path.join(os.path.expanduser("~"), ".fuzzmanagerconf")
    # max number of times to report a non-frequent signature to FuzzManager
    rate_limit = 50


    @staticmethod
    def sanity_check(bin_file):
        if _fm_import_error is not None:
            raise _fm_import_error
        if not os.path.isfile(FuzzManagerReporter.fm_config):
            raise IOError("Missing: %s" % FuzzManagerReporter.fm_config)
        if not os.path.isfile("".join([bin_file, ".fuzzmanagerconf"])):
            raise IOError("Missing: %s" % "".join([bin_file, ".fuzzmanagerconf"]))
        ProgramConfiguration.fromBinary(bin_file)


    def _report(self, test_cases, target_binary, log_limit=0):
        if log_limit > 0:
            self.tail(self.log_file, log_limit)

        # rename log
        log_file = "%s_log.txt" % os.path.join(self._log_path, self._file_prefix)
        shutil.move(self.log_file, log_file)

        # prepare data for submission as CrashInfo
        with open(log_file, "r") as log_fp:
            crash_info = CrashInfo.fromRawCrashData(
                None,
                log_fp.read().splitlines(),
                ProgramConfiguration.fromBinary(target_binary))

        collector = Collector()

        # search for a cached signature match and if the signature
        # is already in the cache and marked as frequent, don't bother submitting
        with fasteners.process_lock.InterProcessLock(os.path.join(tempfile.gettempdir(), "fm_sigcache.lock")):
            cache_sig_file, cache_metadata = collector.search(crash_info)
            if cache_metadata is not None:
                if cache_metadata['frequent']:
                    log.info("Frequent crash matched existing signature: %s", cache_metadata["shortDescription"])
                    return
                # there is already a signature, initialize count
                cache_metadata.setdefault("_grizzly_seen_count", 0)
            else:
                # there is no signature, create one locally so we can count the number of times we've seen it
                cache_sig_file = collector.generate(crash_info, numFrames=8)
                cache_metadata = {
                    "_grizzly_seen_count": 0,
                    "frequent": False,
                    "shortDescription": crash_info.createShortSignature()
                }
            # limit the number of times we report per cycle
            cache_metadata["_grizzly_seen_count"] += 1
            if cache_metadata["_grizzly_seen_count"] >= self.rate_limit:
                # we will still report this one, but no more
                cache_metadata['frequent'] = True
            metadata_file = cache_sig_file.replace(".signature", ".metadata")
            with open(metadata_file, "w") as meta_fp:
                json.dump(cache_metadata, meta_fp)

        # dump test cases and the contained files to working directory
        test_case_meta = []
        for test_number, test_case in enumerate(test_cases):
            test_case_meta.append([test_case.corpman_name, test_case.input_fname])
            dump_path = os.path.join(self._log_path, "%s-%d" % (self._file_prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)
        crash_info.configuration.addMetadata({"grizzly_input": repr(test_case_meta)})

        # add results to a zip file
        zip_name = ".".join([self._file_prefix, "zip"])
        with zipfile.ZipFile(zip_name, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_fp:
            for dir_name, _, dir_files in os.walk(self._log_path):
                arc_path = os.path.relpath(dir_name, self._log_path)
                for file_name in dir_files:
                    zip_fp.write(
                        os.path.join(dir_name, file_name),
                        arcname=os.path.join(arc_path, file_name))

        # submit results to the FuzzManager server
        collector.submit(crash_info, testCase=zip_name, testCaseQuality=5)

        # remove zipfile
        if os.path.isfile(zip_name):
            os.remove(zip_name)
