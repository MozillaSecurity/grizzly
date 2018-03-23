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


    @staticmethod
    def select_logs(log_path):
        logs = {"aux": None, "stderr": None, "stdout": None}

        if not os.path.isdir(log_path):
            raise IOError("log_path does not exist %r" % log_path)
        log_files = os.listdir(log_path)
        if not log_files:
            raise IOError("No logs found in %r" % log_path)

        # pattern to identify the ASan crash triggered when the parent process goes away
        re_e10s_forced = re.compile(r"""
            ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
            #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
            """, re.DOTALL | re.VERBOSE)

        # this is a list of *San error reports to prioritize
        # ASan reports not included below (deprioritized):
        # stack-overflow, BUS, failed to allocate
        interesting_sanitizer_tokens = (
            "use-after-", "-buffer-overflow on", ": SEGV on ", "access-violation on ",
            "negative-size-param", "attempting free on ", "memcpy-param-overlap")

        # look for sanitizer (ASan, UBSan, etc...) logs
        log_size = 0
        for fname in [log_file for log_file in log_files if "asan" in log_file]:
            # grab first chunk of log to help triage
            with open(os.path.join(log_path, fname), "r") as log_fp:
                log_data = log_fp.read(4096)

            # look for interesting crash info in the log
            if "==ERROR:" in log_data:
                # check for e10s forced crash
                if re_e10s_forced.search(log_data) is not None:
                    continue
                logs["aux"] = fname
                if any(x in log_data for x in interesting_sanitizer_tokens):
                    break  # this is the likely cause of the crash
                continue  # probably the most interesting but lets keep looking

            # UBSan error
            if ": runtime error: " in log_data:
                logs["aux"] = fname

            # TODO: add check for empty LSan logs
            # catch all (choose the one with the most info for now)
            if logs["aux"] is None or os.stat(os.path.join(log_path, fname)).st_size > log_size:
                logs["aux"] = fname
                log_size = os.stat(os.path.join(log_path, fname)).st_size

        # prefer ASan logs over minidump logs
        if logs["aux"] is None:
            re_dump_req = re.compile(r"\d+\|0\|.+?\|google_breakpad::ExceptionHandler::WriteMinidump")
            for fname in [log_file for log_file in log_files if "minidump" in log_file]:
                with open(os.path.join(log_path, fname), "r") as log_fp:
                    log_data = log_fp.read(4096)
                    # this will select log that contains "Crash|SIGSEGV|" or
                    # the desired "DUMP_REQUESTED" log
                    if "Crash|DUMP_REQUESTED|" not in log_data or re_dump_req.search(log_data):
                        logs["aux"] = fname
                        break

        # look for ffpuppet worker logs, worker logs should be used if nothing else is available
        if logs["aux"] is None:
            for fname in [log_file for log_file in log_files if "ffp_worker" in log_file]:
                if logs["aux"] is not None:
                    # we only expect one log here...
                    log.warning("aux log previously selected: %s, overwriting!", logs["aux"])
                logs["aux"] = fname

        for fname in log_files:
            if "stderr" in fname:
                logs["stderr"] = fname
                continue
            if "stdout" in fname:
                logs["stdout"] = fname
                continue

        return logs


    def _process_logs(self):
        self._map = self.select_logs(self._log_path)
        # look through logs one by one until we find a stack
        for scan_log in (self._map["aux"], self._map["stderr"], self._map["stdout"]):
            if scan_log is None:
                continue
            with open(os.path.join(self._log_path, scan_log), "rb") as log_fp:
                stack = stack_hasher.Stack.from_text(log_fp.read().decode("utf-8", errors="ignore"))
            # calculate hashes
            if stack.frames:
                self._minor = stack.minor
                self._major = stack.major
                break
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
        # read in the log files and create a CrashInfo object
        aux_data = None
        if "aux" in self._map and self._map["aux"] is not None:
            with open(os.path.join(self._log_path, self._map["aux"]), "rb") as log_fp:
                aux_data = log_fp.read().decode("utf-8", errors="ignore").splitlines()
        stderr_file = os.path.join(self._log_path, self._map["stderr"])
        stdout_file = os.path.join(self._log_path, self._map["stdout"])
        with open(stderr_file, "rb") as err_fp, open(stdout_file, "rb") as out_fp:
            return CrashInfo.fromRawCrashData(
                out_fp.read().decode("utf-8", errors="ignore").splitlines(),
                err_fp.read().decode("utf-8", errors="ignore").splitlines(),
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
                if cache_metadata["frequent"]:
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
                cache_metadata["frequent"] = True
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
