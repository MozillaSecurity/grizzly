# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from abc import ABCMeta, abstractmethod
from hashlib import sha1
from json import dump
from logging import getLogger, WARNING
from platform import machine, system
from os import listdir, getcwd, getenv, makedirs, mkdir, SEEK_END, stat, unlink, walk
from os.path import basename, expanduser, isdir, isfile, join as pathjoin, realpath, relpath
from re import compile as re_compile, DOTALL, VERBOSE
from shutil import copyfile, copyfileobj, move, rmtree
from tarfile import open as tar_open
from tempfile import mkstemp
from time import strftime
from zipfile import ZipFile, ZIP_DEFLATED

from fasteners.process_lock import InterProcessLock
from psutil import disk_usage

# import FuzzManager utilities
from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo

# check if boto is available for S3FuzzManager reporter
try:
    from boto3 import resource
    from botocore.exceptions import ClientError
    _boto_import_error = None  # pylint: disable=invalid-name
    getLogger("botocore").setLevel(WARNING)
    getLogger("boto3").setLevel(WARNING)
    getLogger("s3transfer").setLevel(WARNING)
except ImportError as err:
    _boto_import_error = err  # pylint: disable=invalid-name

from .stack_hasher import Stack
from .utils import grz_tmp

__all__ = ("FilesystemReporter", "FuzzManagerReporter", "Report", "S3FuzzManagerReporter")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

log = getLogger("grizzly")  # pylint: disable=invalid-name


class Report(object):
    DEFAULT_MAJOR = "NO_STACK"
    DEFAULT_MINOR = "0"
    MAX_LOG_SIZE = 1048576  # 1MB

    __slots__ = ("_crash_info", "log_aux", "log_err", "log_out", "path", "prefix", "stack")

    def __init__(self, log_path, log_map, size_limit=MAX_LOG_SIZE):
        self._crash_info = None
        self.log_aux = log_map.get("aux") if log_map is not None else None
        self.log_err = log_map.get("stderr") if log_map is not None else None
        self.log_out = log_map.get("stdout") if log_map is not None else None
        self.path = log_path

        # tail logs if needed
        if size_limit < 1:
            log.warning("No limit set on report log size!")
        elif isdir(log_path):
            for fname in listdir(log_path):
                log_file_path = pathjoin(log_path, fname)
                if isfile(log_file_path):
                    Report.tail(log_file_path, size_limit)

        # look through logs one by one until we find a stack
        # NOTE: order matters aux->stderr->stdout
        for scan_log in (self.log_aux, self.log_err, self.log_out):
            if scan_log is None:
                continue
            with open(pathjoin(log_path, scan_log), "rb") as log_fp:
                stack = Stack.from_text(log_fp.read().decode("utf-8", errors="ignore"))
            if stack.frames:
                self.prefix = "%s_%s" % (stack.minor[:8], strftime("%Y-%m-%d_%H-%M-%S"))
                self.stack = stack
                break
        else:
            self.stack = None
            self.prefix = "%s_%s" % (self.DEFAULT_MINOR, strftime("%Y-%m-%d_%H-%M-%S"))

    def cleanup(self):
        if isdir(self.path):
            rmtree(self.path)

    @staticmethod
    def crash_hash(crash_info):
        """Create CrashInfo object from logs.

        Args:
            crash_info (CrashInfo): Binary file being tested.

        Returns:
            str: Hash of the raw signature of the crash.
        """
        max_frames = Report.crash_signature_max_frames(crash_info, 5)
        sig = Report.crash_signature(crash_info, max_frames)
        return sha1(sig.rawSignature.encode("utf-8")).hexdigest()[:16]

    def crash_info(self, target_binary):
        """Create CrashInfo object from logs.

        Args:
            target_binary (str): Binary file being tested.

        Returns:
            CrashInfo: CrashInfo based on Result log data.
        """
        if self._crash_info is None:
            # read in the log files and create a CrashInfo object
            aux_data = None
            if self.log_aux is not None:
                with open(pathjoin(self.path, self.log_aux), "rb") as log_fp:
                    aux_data = log_fp.read().decode("utf-8", errors="ignore").splitlines()
            stderr_file = pathjoin(self.path, self.log_err)
            stdout_file = pathjoin(self.path, self.log_out)
            # create ProgramConfiguration that can be reported to a FM server
            if isfile("%s.fuzzmanagerconf" % (target_binary,)):
                # attempt to use "<target_binary>.fuzzmanagerconf"
                fm_cfg = ProgramConfiguration.fromBinary(target_binary)
            else:
                log.debug("'%s.fuzzmanagerconf' does not exist", target_binary)
                fm_cfg = None
            if fm_cfg is None:
                log.debug("creating ProgramConfiguration")
                cpu = machine().lower()
                fm_cfg = ProgramConfiguration(
                    basename(target_binary),
                    "x86_64" if cpu == "amd64" else cpu,
                    system())
            with open(stderr_file, "rb") as err_fp, open(stdout_file, "rb") as out_fp:
                self._crash_info = CrashInfo.fromRawCrashData(
                    out_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    err_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    fm_cfg,
                    auxCrashData=aux_data)
        return self._crash_info

    @staticmethod
    def crash_signature(crash_info, max_frames=5):
        return crash_info.createCrashSignature(
            maxFrames=Report.crash_signature_max_frames(crash_info, max_frames))

    @staticmethod
    def crash_signature_max_frames(crash_info, suggested_frames=8):
        if set(crash_info.backtrace) & {
                "std::panicking::rust_panic",
                "std::panicking::rust_panic_with_hook",
        }:
            # rust panic adds 5-6 frames of noise at the top of the stack
            suggested_frames += 6
        return suggested_frames

    @classmethod
    def from_path(cls, path, size_limit=MAX_LOG_SIZE):
        """Create Report from a directory containing logs.

        Args:
            path (str): Directory containing log files.
            size_limit (int): Maximum size in bytes of a log file.

        Returns:
            Report: Result object based on log data.
        """
        return cls(path, Report.select_logs(path), size_limit=size_limit)

    @property
    def major(self):
        if self.stack and self.stack.major is not None:
            return self.stack.major
        return self.DEFAULT_MAJOR

    @property
    def minor(self):
        if self.stack and self.stack.minor is not None:
            return self.stack.minor
        return self.DEFAULT_MINOR

    @property
    def preferred(self):
        return self.log_aux if self.log_aux is not None else self.log_err

    @staticmethod
    def select_logs(log_path):
        if not isdir(log_path):
            raise IOError("log_path does not exist %r" % log_path)
        log_files = listdir(log_path)
        if not log_files:
            raise IOError("No logs found in %r" % log_path)
        logs = {"aux": None, "stderr": None, "stdout": None}

        # order by creation date because the oldest log is likely the cause of the issue
        log_files.sort(key=lambda x: stat(pathjoin(log_path, x)).st_mtime)

        # pattern to identify the ASan crash triggered when the parent process goes away
        re_e10s_forced = re_compile(r"""
            ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
            #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
            """, DOTALL | VERBOSE)

        # this is a list of *San error reports to prioritize
        # ASan reports not included below (deprioritized):
        # stack-overflow, BUS, failed to allocate, detected memory leaks
        interesting_sanitizer_tokens = (
            "use-after-", "-buffer-overflow on", ": SEGV on ", "access-violation on ",
            "negative-size-param", "attempting free on ", "-param-overlap")

        # look for sanitizer (ASan, UBSan, etc...) logs
        for fname in (log_file for log_file in log_files if "asan" in log_file):
            # grab first chunk of log to help triage
            with open(pathjoin(log_path, fname), "r") as log_fp:
                log_data = log_fp.read(4096)

            # look for interesting crash info in the log
            if "==ERROR:" in log_data:
                # check for e10s forced crash
                if re_e10s_forced.search(log_data) is not None:
                    continue
                # make sure there is something that looks like a stack frame in the log
                if "#0 " in log_data:
                    logs["aux"] = fname
                    if any(x in log_data for x in interesting_sanitizer_tokens):
                        break  # this is the likely cause of the crash
                    continue  # probably the most interesting but lets keep looking

            # UBSan error (non-ASan builds)
            if ": runtime error: " in log_data:
                logs["aux"] = fname

            # catch all (choose the one with info for now)
            if logs["aux"] is None and stat(pathjoin(log_path, fname)).st_size:
                logs["aux"] = fname

        # look for Valgrind logs
        if logs["aux"] is None:
            for fname in (log_file for log_file in log_files if "valgrind" in log_file):
                if stat(pathjoin(log_path, fname)).st_size:
                    logs["aux"] = fname
                    break

        # prefer ASan logs over minidump logs
        if logs["aux"] is None:
            re_dump_req = re_compile(r"\d+\|0\|.+?\|google_breakpad::ExceptionHandler::WriteMinidump")
            for fname in (log_file for log_file in log_files if "minidump" in log_file):
                with open(pathjoin(log_path, fname), "r") as log_fp:
                    log_data = log_fp.read(4096)
                    # this will select log that contains "Crash|SIGSEGV|" or
                    # the desired "DUMP_REQUESTED" log
                    # TODO: review this it may be too strict
                    # see https://searchfox.org/mozilla-central/source/accessible/ipc/DocAccessibleParent.cpp#452
                    if "Crash|DUMP_REQUESTED|" not in log_data or re_dump_req.search(log_data):
                        logs["aux"] = fname
                        break

        # look for ffpuppet worker logs, worker logs should be used if nothing else is available
        if logs["aux"] is None:
            for fname in (log_file for log_file in log_files if "ffp_worker" in log_file):
                if logs["aux"] is not None:
                    # we only expect one log here...
                    log.warning("aux log previously selected: %s, overwriting!", logs["aux"])
                logs["aux"] = fname

        for fname in log_files:
            if "stderr" in fname:
                logs["stderr"] = fname
            elif "stdout" in fname:
                logs["stdout"] = fname

        return logs

    @staticmethod
    def tail(in_file, size_limit):
        assert size_limit > 0
        if stat(in_file).st_size <= size_limit:
            return
        with open(in_file, "rb") as in_fp:
            in_fp.seek(0, SEEK_END)
            dump_pos = max((in_fp.tell() - size_limit), 0)
            in_fp.seek(dump_pos)
            out_fd, out_file = mkstemp(prefix="taillog_", dir=grz_tmp())
            with open(out_fd, "wb") as out_fp:
                out_fp.write(b"[LOG TAILED]\n")
                copyfileobj(in_fp, out_fp, 0x10000)  # 64KB chunks
        unlink(in_file)
        move(out_file, in_file)


class Reporter(metaclass=ABCMeta):
    @abstractmethod
    def _process_report(self, report):
        pass

    @abstractmethod
    def _reset(self):
        pass

    @abstractmethod
    def _submit_report(self, report, test_cases):
        pass

    def submit(self, test_cases, log_path=None, report=None):
        """Submit report containing results. Either `log_path` or `report` must
        be specified.

        Args:
            test_cases (iterable): A collection of testcases, ordered newest to oldest,
                                   the newest being the mostly likely to trigger
                                   the result (crash, assert... etc).
            log_path (str): Path to logs from the Target. A Report will
                            be created from this.
            report (Report): Report to submit.

        Returns:
            None
        """
        if log_path is not None:
            assert report is None, "Only 'log_path' or 'report' can be specified!"
            if not isdir(log_path):
                raise IOError("No such directory %r" % log_path)
            report = Report.from_path(log_path)
        elif report is not None:
            assert isinstance(report, Report)
        else:
            raise AssertionError("Either 'log_path' or 'report' must be specified!")
        self._process_report(report)
        self._submit_report(report, test_cases)
        if report is not None:
            report.cleanup()
        self._reset()


class FilesystemReporter(Reporter):
    DISK_SPACE_ABORT = 512 * 1024 * 1024  # 512 MB

    def __init__(self, report_path=None, major_bucket=True):
        self.major_bucket = major_bucket
        self.report_path = pathjoin(getcwd(), "results") if report_path is None else report_path

    def _process_report(self, report):
        pass

    def _reset(self):
        pass

    def _submit_report(self, report, test_cases):
        # create major bucket directory in working directory if needed
        if self.major_bucket:
            dest_path = pathjoin(self.report_path, report.major[:16])
        else:
            dest_path = self.report_path
        if not isdir(dest_path):
            makedirs(dest_path)
        # dump test cases and the contained files to working directory
        for test_number, test_case in enumerate(test_cases):
            dump_path = pathjoin(dest_path, "%s-%d" % (report.prefix, test_number))
            if not isdir(dump_path):
                mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)
        # move logs into bucket directory
        log_path = pathjoin(dest_path, "%s_%s" % (report.prefix, "logs"))
        if isdir(log_path):
            log.warning("Report log path exists %r", log_path)
        move(report.path, log_path)
        # avoid filling the disk
        free_space = disk_usage(log_path).free
        if free_space < self.DISK_SPACE_ABORT:
            raise RuntimeError("Running low on disk space (%0.1fMB)" % (free_space / 1048576.0,))


class FuzzManagerReporter(Reporter):
    FM_CONFIG = pathjoin(expanduser("~"), ".fuzzmanagerconf")
    # max number of times to report a non-frequent signature to FuzzManager
    MAX_REPORTS = 10

    # testcase quality values
    QUAL_REDUCED_RESULT = 0  # the final reduced testcase
    QUAL_REDUCED_ORIGINAL = 1  # the original used for successful reduction
    QUAL_REPRODUCIBLE = 4  # the testcase was reproducible
    QUAL_UNREDUCED = 5  # haven't attempted reduction yet (1st attempt, generic reducer)
    QUAL_REQUEST_SPECIFIC = 6  # platform specific reduction requested (2nd attempt)
    QUAL_NO_TESTCASE = 7  # no testcase was detected (could be the "testcase" is not a testcase)
    QUAL_REDUCER_BROKE = 8  # the testcase was reproducible, but broke during reduction
    QUAL_REDUCER_ERROR = 9  # reducer error
    QUAL_NOT_REPRODUCIBLE = 10  # could not reproduce the testcase

    def __init__(self, target_binary, tool=None):
        self._extra_metadata = {}
        self.force_report = False
        self.quality = self.QUAL_UNREDUCED
        self.target_binary = target_binary
        self.tool = tool  # optional tool name

    @staticmethod
    def create_crash_info(report, target_binary):
        # TODO: this is here to preserve the old way of operation (used by reducer)
        return report.crash_info(target_binary)

    def _reset(self):
        self._extra_metadata = {}

    @staticmethod
    def sanity_check(bin_file):
        """Perform FuzzManager sanity check.

        Args:
            bin_file (str): Binary file being tested.

        Returns:
            None
        """
        if not isfile(FuzzManagerReporter.FM_CONFIG):
            raise IOError("Missing: %s" % FuzzManagerReporter.FM_CONFIG)
        if not isfile("".join([bin_file, ".fuzzmanagerconf"])):
            raise IOError("Missing: %s.fuzzmanagerconf" % (bin_file,))
        ProgramConfiguration.fromBinary(bin_file)

    @classmethod
    def quality_name(cls, value):
        for name in dir(cls):
            if name.startswith("QUAL_") and getattr(cls, name) == value:
                return name
        return "unknown quality (%r)" % (value,)

    def _process_report(self, report):
        self._process_rr_trace(report)

    def _process_rr_trace(self, report):
        # don't report large files to FuzzManager
        trace_path = pathjoin(report.path, "rr-traces")
        if isdir(trace_path):
            log.info("Ignored rr trace")
            self._extra_metadata["rr-trace"] = "ignored"
            # remove traces so they are not uploaded to FM (because they are huge)
            # use S3FuzzManagerReporter instead
            rmtree(trace_path)

    @staticmethod
    def _ignored(report):
        # This is here to prevent reporting stack-less crashes
        # that were caused by system OOM or bogus other crashes
        log_file = pathjoin(report.path, report.preferred)
        with open(log_file, "rb") as log_fp:
            log_data = log_fp.read().decode("utf-8", errors="ignore")
        mem_errs = (
            "ERROR: Failed to mmap",
            ": AddressSanitizer failed to allocate")
        for msg in mem_errs:
            if msg in log_data and "#0 " not in log_data:
                return True
        if log_data.startswith("VEX temporary storage exhausted."):
            # ignore Valgrind crashes
            return True
        return False

    def _submit_report(self, report, test_cases):
        # prepare data for submission as CrashInfo
        crash_info = report.crash_info(self.target_binary)
        assert crash_info is not None

        # search for a cached signature match and if the signature
        # is already in the cache and marked as frequent, don't bother submitting
        with InterProcessLock(pathjoin(grz_tmp(), "fm_sigcache.lock")):
            collector = Collector()
            cache_sig_file, cache_metadata = collector.search(crash_info)
            if cache_metadata is not None:
                if cache_metadata["frequent"]:
                    log.info("Frequent crash matched existing signature: %s",
                             cache_metadata["shortDescription"])
                    if not self.force_report:
                        return
                elif "bug__id" in cache_metadata:
                    log.info("Crash matched existing signature (bug %s): %s",
                             cache_metadata["bug__id"],
                             cache_metadata["shortDescription"])
                    # we will still report this one, but no more
                    cache_metadata["frequent"] = True
                # there is already a signature, initialize count
                cache_metadata.setdefault("_grizzly_seen_count", 0)
            else:
                # there is no signature, create one locally so we can count
                # the number of times we've seen it
                max_frames = Report.crash_signature_max_frames(crash_info)
                cache_sig_file = collector.generate(crash_info, numFrames=max_frames)
                cache_metadata = {
                    "_grizzly_seen_count": 0,
                    "frequent": False,
                    "shortDescription": crash_info.createShortSignature()}
            if cache_sig_file is None:
                if self._ignored(report):
                    log.info("Report is unsupported and is in ignore list")
                    return
                log.warning("Report is unsupported by FM, saved to %r", report.path)
                # TODO: we should check if stackhasher failed too
                raise RuntimeError("Failed to create FM signature")
            # limit the number of times we report per cycle
            cache_metadata["_grizzly_seen_count"] += 1
            if cache_metadata["_grizzly_seen_count"] >= self.MAX_REPORTS:
                # we will still report this one, but no more
                cache_metadata["frequent"] = True
            metadata_file = cache_sig_file.replace(".signature", ".metadata")
            with open(metadata_file, "w") as meta_fp:
                dump(cache_metadata, meta_fp)

        # dump test cases and the contained files to working directory
        test_case_meta = []
        for test_number, test_case in enumerate(test_cases):
            test_case_meta.append([test_case.adapter_name, test_case.input_fname])
            dump_path = pathjoin(report.path, "%s-%d" % (report.prefix, test_number))
            if not isdir(dump_path):
                mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)
        crash_info.configuration.addMetadata({"grizzly_input": repr(test_case_meta)})
        if test_cases:
            environ_string = " ".join("=".join(kv) for kv in test_cases[0].env_vars.items())
            crash_info.configuration.addMetadata({"recorded_envvars": environ_string})
        else:
            self.quality = self.QUAL_NO_TESTCASE
        crash_info.configuration.addMetadata(self._extra_metadata)

        # grab screen log
        if getenv("WINDOW") is not None:
            screen_log = ".".join(["screenlog", getenv("WINDOW")])
            if isfile(screen_log):
                target_log = pathjoin(report.path, "screenlog.txt")
                copyfile(screen_log, target_log)
                Report.tail(target_log, 10240)  # limit to last 10K

        # add results to a zip file
        zip_name = "%s.zip" % (report.prefix,)
        with ZipFile(zip_name, mode="w", compression=ZIP_DEFLATED) as zip_fp:
            # add test files
            for dir_name, _, dir_files in walk(report.path):
                arc_path = relpath(dir_name, report.path)
                for file_name in dir_files:
                    zip_fp.write(
                        pathjoin(dir_name, file_name),
                        arcname=pathjoin(arc_path, file_name))

        # override tool name if specified
        if self.tool is not None:
            collector.tool = self.tool

        # announce shortDescription if crash is not in a bucket
        if cache_metadata["_grizzly_seen_count"] == 1 and not cache_metadata["frequent"]:
            log.info("Submitting new crash %r", cache_metadata["shortDescription"])
        # submit results to the FuzzManager server
        new_entry = collector.submit(crash_info, testCase=zip_name, testCaseQuality=self.quality)
        log.info("Logged %d with quality %d", new_entry["id"], self.quality)

        # remove zipfile
        if isfile(zip_name):
            unlink(zip_name)


class S3FuzzManagerReporter(FuzzManagerReporter):
    @staticmethod
    def compress_rr_trace(src, dest):
        # resolve symlink to latest trace available
        latest_trace = realpath(pathjoin(src, "latest-trace"))
        assert isdir(latest_trace), "missing latest-trace directory"
        rr_arc = pathjoin(dest, "rr.tar.bz2")
        log.debug("creating %r from %r", rr_arc, latest_trace)
        with tar_open(rr_arc, "w:bz2") as arc_fp:
            arc_fp.add(latest_trace, arcname=basename(latest_trace))
        # remove path containing uncompressed traces
        rmtree(src)
        return rr_arc

    def _process_report(self, report):
        self._process_rr_trace(report)

    def _process_rr_trace(self, report):
        trace_path = pathjoin(report.path, "rr-traces")
        if not isdir(trace_path):
            return None
        s3_bucket = getenv("GRZ_S3_BUCKET")
        assert s3_bucket is not None
        # check for existing minor hash in S3
        s3 = resource("s3")
        s3_key = "rr-%s.tar.bz2" % (report.minor,)
        s3_url = "http://%s.s3.amazonaws.com/%s" % (s3_bucket, s3_key)
        try:
            s3.Object(s3_bucket, s3_key).load()  # HEAD, doesn't fetch the whole object
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "404":
                # The object does not exist.
                pass
            else:
                # Something else has gone wrong.
                raise
        else:
            # The object already exists.
            log.info("RR trace exists at %s", s3_url)
            self._extra_metadata["rr-trace"] = s3_url
            # remove traces so they are not reported to FM
            rmtree(trace_path)
            return s3_url

        # Upload to S3
        rr_arc = self.compress_rr_trace(trace_path, report.path)
        s3.meta.client.upload_file(rr_arc, s3_bucket, s3_key, ExtraArgs={"ACL": "public-read"})
        unlink(rr_arc)
        self._extra_metadata["rr-trace"] = s3_url
        return s3_url

    @staticmethod
    def sanity_check(bin_file):
        if getenv("GRZ_S3_BUCKET") is None:
            raise EnvironmentError("'GRZ_S3_BUCKET' is not set in environment")
        if _boto_import_error is not None:
            raise _boto_import_error  # pylint: disable=raising-bad-type
        FuzzManagerReporter.sanity_check(bin_file)
