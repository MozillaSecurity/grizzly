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

    def __init__(self, log_limit=0):
        self.log_limit = max(log_limit, 0)  # maximum log file size
        self._log_path = None
        self._major = None  # stack hash
        self._map = None  # map logs (stderr, stdout, aux/preferred crash log) to file names
        self._minor = None  # stack hash
        self._prefix = None  # prefix for results
        self._test_cases = None
        self._reset()


    def _find_preferred_stack(self):
        # pattern to identify the crash triggered when the parent process goes away
        # TODO: add e10s forced check for minidumps
        re_e10s_forced = re.compile(r"""
            ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
            #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
            """, re.DOTALL | re.VERBOSE)
        log_size = 0
        log_files = os.listdir(self._log_path)
        if not log_files:
            raise IOError("No logs found in %r" % self._log_path)

        for fname in log_files:
            if "asan" not in fname:
                continue # ignore non-ASan logs at this point
            # check for e10s forced crash
            with open(os.path.join(self._log_path, fname)) as log_fp:
                if re_e10s_forced.search(log_fp.read(4096)) is not None:
                    continue
            if "aux" not in self._map:
                self._map["aux"] = fname # use this ASan log
                log_size = os.stat(os.path.join(self._log_path, fname)).st_size
            # prefer larger log if there is more than one
            elif os.stat(os.path.join(self._log_path, fname)).st_size > log_size:
                self._map["aux"] = fname # use this ASan log
                log_size = os.stat(os.path.join(self._log_path, fname)).st_size

        # prefer ASan logs over minidump logs
        if "aux" not in self._map:
            for fname in log_files:
                if "minidump" in fname: # for now just use the first one we come across
                    self._map["aux"] = fname # use this minidump log
                    break

        for fname in log_files:
            if "stderr" in fname:
                self._map["stderr"] = fname
                continue
            if "stdout" in fname:
                self._map["stdout"] = fname
                continue


    def _process_logs(self):
        self._find_preferred_stack()
        log_to_scan = None
        for log_src in ("aux", "stderr", "stdout"):
            if log_src in self._map:
                log_to_scan = self._map[log_src]
                break
        if log_to_scan:
            with open(os.path.join(self._log_path, log_to_scan), "r") as log_fp:
                stack = stack_hasher.stack_from_text(log_fp.read())
            # calculate hashes
            if stack is not None:
                self._minor = stack_hasher.stack_to_hash(stack)
                self._major = stack_hasher.stack_to_hash(stack, major=True)
        if self._minor is None:
            self._minor = self.DEFAULT_MINOR
            self._major = self.DEFAULT_MAJOR
        self._prefix = "_".join([self._minor[:8], time.strftime("%Y-%m-%d_%H-%M-%S")])


    def _report(self):
        raise NotImplementedError("_report must be implemented in the subclass")


    def _reset(self):
        if self._log_path is not None and os.path.isdir(self._log_path):
            shutil.rmtree(self._log_path)
        self._log_path = None
        self._major = None
        self._map = dict()
        self._minor = None
        self._prefix = None
        self._test_cases = None


    def report(self, log_path, test_cases):
        assert self._log_path is None
        assert self._test_cases is None
        self._log_path = log_path
        self._test_cases = test_cases
        if not os.path.isdir(self._log_path):
            raise IOError("No such directory %r" % self._log_path)
        self._process_logs()
        # tails logs before reporting if needed
        if self.log_limit > 0:
            for fname in os.listdir(log_path):
                self.tail(os.path.join(log_path, fname), self.log_limit)
        self._report()
        self._reset()


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
                shutil.copyfileobj(in_fp, out_fp, 0x10000)  # 64KB chunks
        os.remove(in_file)
        shutil.move(out_file, in_file)


class FilesystemReporter(Reporter):
    def __init__(self, log_limit=0, report_path=None):
        Reporter.__init__(self, log_limit)
        self.report_path = report_path


    def _report(self):
        if self.report_path is None:
            self.report_path = os.path.join(os.getcwd(), "results")

        # create report directory if needed
        if not os.path.isdir(self.report_path):
            os.mkdir(self.report_path)

        # create major bucket directory in working directory if needed
        major_dir = os.path.join(self.report_path, self._major)
        if not os.path.isdir(major_dir):
            os.mkdir(major_dir)

        # dump test cases and the contained files to working directory
        for test_number, test_case in enumerate(self._test_cases):
            dump_path = os.path.join(major_dir, "%s-%d" % (self._prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)

        # move logs into bucket directory
        shutil.move(self._log_path, os.path.join(major_dir, "_".join([self._prefix, "logs"])))


class FuzzManagerReporter(Reporter):
    # this is where Collector looks for the '.fuzzmanagerconf' (see Collector.py)
    FM_CONFIG = os.path.join(os.path.expanduser("~"), ".fuzzmanagerconf")
    # max number of times to report a non-frequent signature to FuzzManager
    MAX_REPORTS = 10


    def __init__(self, target_binary, log_limit=0):
        Reporter.__init__(self, log_limit)
        self.target_binary = target_binary


    @staticmethod
    def sanity_check(bin_file):
        if _fm_import_error is not None:
            raise _fm_import_error # pylint: disable=raising-bad-type
        if not os.path.isfile(FuzzManagerReporter.FM_CONFIG):
            raise IOError("Missing: %s" % FuzzManagerReporter.FM_CONFIG)
        if not os.path.isfile("".join([bin_file, ".fuzzmanagerconf"])):
            raise IOError("Missing: %s" % "".join([bin_file, ".fuzzmanagerconf"]))
        ProgramConfiguration.fromBinary(bin_file)


    def _create_crash_info(self):
        aux_data = None
        if "aux" in self._map:
            with open(os.path.join(self._log_path, self._map["aux"]), "r") as log_fp:
                aux_data = log_fp.read().splitlines()
        with open(os.path.join(self._log_path, self._map["stderr"]), "r") as err_fp:
            with open(os.path.join(self._log_path, self._map["stdout"]), "r") as out_fp:
                return CrashInfo.fromRawCrashData(
                    out_fp.read().splitlines(),
                    err_fp.read().splitlines(),
                    ProgramConfiguration.fromBinary(self.target_binary),
                    auxCrashData=aux_data)


    def _report(self):
        # prepare data for submission as CrashInfo
        crash_info = self._create_crash_info()

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
            if cache_metadata["_grizzly_seen_count"] >= self.MAX_REPORTS:
                # we will still report this one, but no more
                cache_metadata['frequent'] = True
            metadata_file = cache_sig_file.replace(".signature", ".metadata")
            with open(metadata_file, "w") as meta_fp:
                json.dump(cache_metadata, meta_fp)

        # dump test cases and the contained files to working directory
        test_case_meta = []
        for test_number, test_case in enumerate(self._test_cases):
            test_case_meta.append([test_case.corpman_name, test_case.input_fname])
            dump_path = os.path.join(self._log_path, "%s-%d" % (self._prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)
        crash_info.configuration.addMetadata({"grizzly_input": repr(test_case_meta)})

        # grab screen log
        if os.getenv("WINDOW") is not None:
            screen_log = ".".join(["screenlog", os.getenv("WINDOW")])
            if os.path.isfile(screen_log):
                target_log = os.path.join(self._log_path, "screenlog.txt")
                shutil.copyfile(screen_log, target_log)
                self.tail(target_log, 10240)  # limit to last 10K

        # add results to a zip file
        zip_name = ".".join([self._prefix, "zip"])
        with zipfile.ZipFile(zip_name, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_fp:
            # add test files
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
