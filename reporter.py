# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import logging
import os
import re
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


class Reporter(object):
    DEFAULT_MAJOR = "NO_STACK"
    DEFAULT_MINOR = "0"

    def __init__(self, log_path):
        self.log_files = os.listdir(log_path)
        self.log_path = log_path
        self._major = None # stack hash
        self._map = {} # map logs (stderr, stdout, aux/preferred crash log) to file names
        self._minor = None # stack hash
        self._prefix = None # prefix for results


    def _find_preferred_stack(self):
        # pattern to identify the crash triggered when the parent process goes away
        re_e10s_forced = re.compile(r"""
            ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
            #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
            """, re.DOTALL | re.VERBOSE)
        log_size = 0
        for fname in self.log_files:
            if "asan" not in fname:
                continue # ignore non-ASan logs at this point
            # check for e10s forced crash
            with open(os.path.join(self.log_path, fname)) as log_fp:
                if re_e10s_forced.search(log_fp.read(4096)) is not None:
                    continue
            if "aux" not in self._map:
                self._map["aux"] = fname # use this ASan log
                log_size = os.stat(os.path.join(self.log_path, fname)).st_size
            # prefer larger log if there is more than one
            elif os.stat(os.path.join(self.log_path, fname)).st_size > log_size:
                self._map["aux"] = fname # use this ASan log
                log_size = os.stat(os.path.join(self.log_path, fname)).st_size

        # prefer ASan logs over minidump logs
        if "aux" not in self._map:
            for fname in self.log_files:
                if "minidump" in fname: # for now just use the first one we come across
                    self._map["aux"] = fname # use this minidump log
                    break

        for fname in self.log_files:
            if "stderr" in fname:
                self._map["stderr"] = fname
                continue
            if "stdout" in fname:
                self._map["stdout"] = fname
                continue


    def _process_logs(self):
        self._find_preferred_stack()
        log_to_scan = self._map["aux"] if "aux" in self._map else self._map["stderr"]
        if log_to_scan is not None:
            with open(os.path.join(self.log_path, log_to_scan), "r") as log_fp:
                stack = stack_hasher.stack_from_text(log_fp.read())
            # calculate hashes
            if stack is not None:
                self._minor = stack_hasher.stack_to_hash(stack)
                self._major = stack_hasher.stack_to_hash(stack, major=True)
        if self._minor is None:
            self._minor = self.DEFAULT_MINOR
            self._major = self.DEFAULT_MAJOR
        self._prefix = "_".join([self._minor[:8], time.strftime("%Y-%m-%d_%H-%M-%S")])


    def _report(self, *args, **kwargs):
        raise NotImplementedError("_report must be implemented in the subclass")


    def report(self, *args, **kwargs):
        self._process_logs()
        if self._minor is not None:
            self._report(*args, **kwargs)
        if os.path.isdir(self.log_path):
            shutil.rmtree(self.log_path)


    @staticmethod
    def tail(in_file, size_limit):
        assert size_limit > 0
        with open(in_file, "rb") as in_fp:
            # check if tail is needed
            in_fp.seek(0, os.SEEK_END)
            if in_fp.tell() <= size_limit:
                return # no tail needed
            # perform tail operation
            dump_pos = max((in_fp.tell() - size_limit), 0)
            in_fp.seek(dump_pos)
            out_fd, out_file = tempfile.mkstemp()
            os.close(out_fd)
            with open(out_file, "wb") as out_fp:
                out_fp.write(b"[LOG TAILED]\n")
                shutil.copyfileobj(in_fp, out_fp, 0x10000) # 64KB chunks
        os.remove(in_file)
        shutil.move(out_file, in_file)


class FilesystemReporter(Reporter):
    def _report(self, test_cases, results_path=None, log_limit=0):
        if log_limit > 0:
            for fname in self.log_files:
                self.tail(os.path.join(self.log_path, fname), log_limit)

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
            dump_path = os.path.join(major_dir, "%s-%d" % (self._prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)

        # move logs into bucket directory
        shutil.move(self.log_path, os.path.join(major_dir, "_".join([self._prefix, "logs"])))


class FuzzManagerReporter(Reporter):
    # this is where Collector looks for the '.fuzzmanagerconf' (see Collector.py)
    fm_config = os.path.join(os.path.expanduser("~"), ".fuzzmanagerconf")
    # max number of times to report a non-frequent signature to FuzzManager
    rate_limit = 10


    @staticmethod
    def sanity_check(bin_file):
        if _fm_import_error is not None:
            raise _fm_import_error # pylint: disable=raising-bad-type
        if not os.path.isfile(FuzzManagerReporter.fm_config):
            raise IOError("Missing: %s" % FuzzManagerReporter.fm_config)
        if not os.path.isfile("".join([bin_file, ".fuzzmanagerconf"])):
            raise IOError("Missing: %s" % "".join([bin_file, ".fuzzmanagerconf"]))
        ProgramConfiguration.fromBinary(bin_file)


    def _create_crash_info(self, target_binary):
        aux_data = None
        if "aux" in self._map:
            with open(os.path.join(self.log_path, self._map["aux"]), "r") as log_fp:
                aux_data = log_fp.read().splitlines()
        with open(os.path.join(self.log_path, self._map["stderr"]), "r") as err_fp:
            with open(os.path.join(self.log_path, self._map["stdout"]), "r") as out_fp:
                return CrashInfo.fromRawCrashData(
                    out_fp.read().splitlines(),
                    err_fp.read().splitlines(),
                    ProgramConfiguration.fromBinary(target_binary),
                    auxCrashData=aux_data)


    def _report(self, test_cases, target_binary, log_limit=0):
        if log_limit > 0:
            for fname in self.log_files:
                self.tail(os.path.join(self.log_path, fname), log_limit)

        # prepare data for submission as CrashInfo
        crash_info = self._create_crash_info(target_binary)

        # search for a cached signature match and if the signature
        # is already in the cache and marked as frequent, don't bother submitting
        with fasteners.process_lock.InterProcessLock(os.path.join(tempfile.gettempdir(), "fm_sigcache.lock")):
            collector = Collector()
            cache_sig_file, cache_metadata = collector.search(crash_info)
            if cache_metadata is not None:
                if cache_metadata['frequent']:
                    log.info("Frequent crash matched existing signature: %s",
                             cache_metadata["shortDescription"])
                    return
                # there is already a signature, initialize count
                cache_metadata.setdefault("_grizzly_seen_count", 0)
            else:
                # there is no signature, create one locally so we can count
                # the number of times we've seen it
                cache_sig_file = collector.generate(crash_info, numFrames=8)
                cache_metadata = {
                    "_grizzly_seen_count": 0,
                    "frequent": False,
                    "shortDescription": crash_info.createShortSignature()}
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
            dump_path = os.path.join(self.log_path, "%s-%d" % (self._prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)
        crash_info.configuration.addMetadata({"grizzly_input": repr(test_case_meta)})

        # add results to a zip file
        zip_name = ".".join([self._prefix, "zip"])
        with zipfile.ZipFile(zip_name, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_fp:
            # add test files
            for dir_name, _, dir_files in os.walk(self.log_path):
                arc_path = os.path.relpath(dir_name, self.log_path)
                for file_name in dir_files:
                    zip_fp.write(
                        os.path.join(dir_name, file_name),
                        arcname=os.path.join(arc_path, file_name))

        # submit results to the FuzzManager server
        collector.submit(crash_info, testCase=zip_name, testCaseQuality=5)

        # remove zipfile
        if os.path.isfile(zip_name):
            os.remove(zip_name)
