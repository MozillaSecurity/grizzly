# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import abc
import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import time
import zipfile

import psutil
import six

# check if required FuzzManager modules are available
try:
    from Collector.Collector import Collector
    from FTB.ProgramConfiguration import ProgramConfiguration
    from FTB.Signatures.CrashInfo import CrashInfo
    import fasteners
    _fm_import_error = None  # pylint: disable=invalid-name
except ImportError as err:
    _fm_import_error = err  # pylint: disable=invalid-name

# check if boto is available for S3FuzzManager reporter
try:
    import boto3
    import botocore
    _boto_import_error = None  # pylint: disable=invalid-name
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("s3transfer").setLevel(logging.WARNING)
except ImportError as err:
    _boto_import_error = err  # pylint: disable=invalid-name

from .stack_hasher import Stack

__all__ = ("FilesystemReporter", "FuzzManagerReporter", "S3FuzzManagerReporter")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


class Report(object):
    DEFAULT_MAJOR = "NO_STACK"
    DEFAULT_MINOR = "0"
    MAX_LOG_SIZE = 1048576  # 1MB

    def __init__(self, log_path, log_map, size_limit=MAX_LOG_SIZE):
        self.log_aux = log_map.get("aux") if log_map is not None else None
        self.log_err = log_map.get("stderr") if log_map is not None else None
        self.log_out = log_map.get("stdout") if log_map is not None else None
        self.path = log_path

        # tail logs if needed
        if size_limit < 1:
            log.warning("No limit set on report log size!")
        elif os.path.isdir(log_path):
            for fname in os.listdir(log_path):
                log_file_path = os.path.join(log_path, fname)
                if os.path.isfile(log_file_path):
                    Report.tail(log_file_path, size_limit)

        # look through logs one by one until we find a stack
        # NOTE: order matters aux->stderr->stdout
        for scan_log in (self.log_aux, self.log_err, self.log_out):
            if scan_log is None:
                continue
            with open(os.path.join(log_path, scan_log), "rb") as log_fp:
                stack = Stack.from_text(log_fp.read().decode("utf-8", errors="ignore"))
            if stack.frames:
                self.prefix = "%s_%s" % (stack.minor[:8], time.strftime("%Y-%m-%d_%H-%M-%S"))
                self.stack = stack
                break
        else:
            self.stack = None
            self.prefix = "%s_%s" % (self.DEFAULT_MINOR, time.strftime("%Y-%m-%d_%H-%M-%S"))

    def cleanup(self):
        if os.path.isdir(self.path):
            shutil.rmtree(self.path)

    @classmethod
    def from_path(cls, path, size_limit=MAX_LOG_SIZE):
        return cls(path, Report.select_logs(path), size_limit=size_limit)

    @property
    def major(self):
        try:
            if self.stack.major is not None:
                return self.stack.major
        except AttributeError:
            pass
        return self.DEFAULT_MAJOR

    @property
    def minor(self):
        try:
            if self.stack.minor is not None:
                return self.stack.minor
        except AttributeError:
            pass
        return self.DEFAULT_MINOR

    @property
    def preferred(self):
        return self.log_aux if self.log_aux is not None else self.log_err

    @staticmethod
    def select_logs(log_path):
        if not os.path.isdir(log_path):
            raise IOError("log_path does not exist %r" % log_path)
        log_files = os.listdir(log_path)
        if not log_files:
            raise IOError("No logs found in %r" % log_path)
        logs = {"aux": None, "stderr": None, "stdout": None}

        # order by creation date because the oldest log is likely the cause of the issue
        log_files.sort(key=lambda x: os.stat(os.path.join(log_path, x)).st_mtime)

        # pattern to identify the ASan crash triggered when the parent process goes away
        re_e10s_forced = re.compile(r"""
            ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
            #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
            """, re.DOTALL | re.VERBOSE)

        # this is a list of *San error reports to prioritize
        # ASan reports not included below (deprioritized):
        # stack-overflow, BUS, failed to allocate, detected memory leaks
        interesting_sanitizer_tokens = (
            "use-after-", "-buffer-overflow on", ": SEGV on ", "access-violation on ",
            "negative-size-param", "attempting free on ", "-param-overlap")

        # look for sanitizer (ASan, UBSan, etc...) logs
        for fname in (log_file for log_file in log_files if "asan" in log_file):
            # grab first chunk of log to help triage
            with open(os.path.join(log_path, fname), "r") as log_fp:
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
            if logs["aux"] is None and os.stat(os.path.join(log_path, fname)).st_size:
                logs["aux"] = fname

        # look for Valgrind logs
        if logs["aux"] is None:
            for fname in (log_file for log_file in log_files if "valgrind" in log_file):
                if os.stat(os.path.join(log_path, fname)).st_size:
                    logs["aux"] = fname
                    break

        # prefer ASan logs over minidump logs
        if logs["aux"] is None:
            re_dump_req = re.compile(r"\d+\|0\|.+?\|google_breakpad::ExceptionHandler::WriteMinidump")
            for fname in (log_file for log_file in log_files if "minidump" in log_file):
                with open(os.path.join(log_path, fname), "r") as log_fp:
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
        if os.stat(in_file).st_size <= size_limit:
            return
        with open(in_file, "rb") as in_fp:
            in_fp.seek(0, os.SEEK_END)
            dump_pos = max((in_fp.tell() - size_limit), 0)
            in_fp.seek(dump_pos)
            out_fd, out_file = tempfile.mkstemp()
            os.close(out_fd)
            with open(out_file, "wb") as out_fp:
                out_fp.write(b"[LOG TAILED]\n")
                shutil.copyfileobj(in_fp, out_fp, 0x10000)  # 64KB chunks
        os.remove(in_file)
        shutil.move(out_file, in_file)


@six.add_metaclass(abc.ABCMeta)
class Reporter(object):
    @abc.abstractmethod
    def _pre_submit(self, report):
        pass

    @abc.abstractmethod
    def _reset(self):
        pass

    @abc.abstractmethod
    def _submit(self, report, test_cases):
        pass

    def submit(self, log_path, test_cases):
        """
        Submit report containing results.

        @type log_path: String
        @param log_path: Path to logs from the Target.

        @type test_cases: list
        @param test_cases: A list of testcases, ordered newest to oldest,
                           the newest being the mostly likely to trigger
                           the result (crash, assert... etc)

        @rtype: None
        @return: None
        """
        if not os.path.isdir(log_path):
            raise IOError("No such directory %r" % log_path)
        report = Report.from_path(log_path)
        self._pre_submit(report)
        self._submit(report, test_cases)
        if report is not None:
            report.cleanup()
        self._reset()


class FilesystemReporter(Reporter):
    DISK_SPACE_ABORT = 512 * 1024 * 1024  # 512 MB

    def __init__(self, report_path=None):
        self.report_path = os.path.join(os.getcwd(), "results") if report_path is None else report_path

    @staticmethod
    def compress_rr_trace(src, dest):
        # resolve symlink to latest trace available
        latest_trace = os.path.realpath(os.path.join(src, "latest-trace"))
        assert os.path.isdir(latest_trace), "missing latest-trace directory"
        rr_arc = os.path.join(dest, "rr.tar.bz2")
        log.debug("creating %r from %r", rr_arc, latest_trace)
        with tarfile.open(rr_arc, "w:bz2") as arc_fp:
            arc_fp.add(latest_trace, arcname=os.path.basename(latest_trace))
        # remove path containing uncompressed traces
        shutil.rmtree(src)
        return rr_arc

    def _pre_submit(self, report):
        trace_path = os.path.join(report.path, "rr-traces")
        if os.path.isdir(trace_path):
            self.compress_rr_trace(trace_path, report.path)

    def _reset(self):
        pass

    def _submit(self, report, test_cases):
        # create major bucket directory in working directory if needed
        major_dir = os.path.join(self.report_path, report.major)
        if not os.path.isdir(major_dir):
            os.makedirs(major_dir)

        # dump test cases and the contained files to working directory
        for test_number, test_case in enumerate(test_cases):
            dump_path = os.path.join(major_dir, "%s-%d" % (report.prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)

        # move logs into bucket directory
        target_dir = os.path.join(major_dir, "%s_%s" % (report.prefix, "logs"))
        if os.path.isdir(target_dir):
            log.warning("Report log path exists %r", target_dir)
        shutil.move(report.path, target_dir)

        # avoid filling the disk
        free_space = psutil.disk_usage(target_dir).free
        if free_space < self.DISK_SPACE_ABORT:
            raise RuntimeError("Running low on disk space (%0.1fMB)" % (free_space / 1048576.0,))


class FuzzManagerReporter(Reporter):
    # this is where Collector looks for the '.fuzzmanagerconf' (see Collector.py)
    FM_CONFIG = os.path.join(os.path.expanduser("~"), ".fuzzmanagerconf")
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
        # read in the log files and create a CrashInfo object
        aux_data = None
        if report.log_aux is not None:
            with open(os.path.join(report.path, report.log_aux), "rb") as log_fp:
                aux_data = log_fp.read().decode("utf-8", errors="ignore").splitlines()
        stderr_file = os.path.join(report.path, report.log_err)
        stdout_file = os.path.join(report.path, report.log_out)
        with open(stderr_file, "rb") as err_fp, open(stdout_file, "rb") as out_fp:
            return CrashInfo.fromRawCrashData(
                out_fp.read().decode("utf-8", errors="ignore").splitlines(),
                err_fp.read().decode("utf-8", errors="ignore").splitlines(),
                ProgramConfiguration.fromBinary(target_binary),
                auxCrashData=aux_data)

    def _reset(self):
        self._extra_metadata = {}

    @classmethod
    def sanity_check(cls, bin_file):
        if _fm_import_error is not None:
            raise _fm_import_error  # pylint: disable=raising-bad-type
        if not os.path.isfile(cls.FM_CONFIG):
            raise IOError("Missing: %s" % cls.FM_CONFIG)
        if not os.path.isfile("".join([bin_file, ".fuzzmanagerconf"])):
            raise IOError("Missing: %s" % "".join([bin_file, ".fuzzmanagerconf"]))
        ProgramConfiguration.fromBinary(bin_file)

    @classmethod
    def quality_name(cls, value):
        for name in dir(cls):
            if name.startswith("QUAL_") and getattr(cls, name) == value:
                return name
        return "unknown quality (%r)" % (value,)

    @staticmethod
    def signature_max_frames(crash_info, suggested_frames=8):
        if set(crash_info.backtrace) & {
                "std::panicking::rust_panic",
                "std::panicking::rust_panic_with_hook",
        }:
            # rust panic adds 5-6 frames of noise at the top of the stack
            suggested_frames += 6
        return suggested_frames

    def _pre_submit(self, report):
        self._process_rr_trace(report)

    def _process_rr_trace(self, report):
        # don't report large files to FuzzManager
        trace_path = os.path.join(report.path, "rr-traces")
        if os.path.isdir(trace_path):
            log.info("Ignored rr trace")
            self._extra_metadata["rr-trace"] = "ignored"
            # remove traces so they are not uploaded to FM (because they are huge)
            # use S3FuzzManagerReporter instead
            shutil.rmtree(trace_path)

    @staticmethod
    def _ignored(report):
        # This is here to prevent reporting stack-less crashes
        # that were caused by system OOM or bogus other crashes
        log_file = os.path.join(report.path, report.preferred)
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

    def _submit(self, report, test_cases):
        # prepare data for submission as CrashInfo
        crash_info = self.create_crash_info(report, self.target_binary)

        # search for a cached signature match and if the signature
        # is already in the cache and marked as frequent, don't bother submitting
        with fasteners.process_lock.InterProcessLock(os.path.join(tempfile.gettempdir(), "fm_sigcache.lock")):
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
                max_frames = self.signature_max_frames(crash_info)
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
                raise RuntimeError("Failed to create FM signature")
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
        for test_number, test_case in enumerate(test_cases):
            test_case_meta.append([test_case.adapter_name, test_case.input_fname])
            dump_path = os.path.join(report.path, "%s-%d" % (report.prefix, test_number))
            if not os.path.isdir(dump_path):
                os.mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)
        crash_info.configuration.addMetadata({"grizzly_input": repr(test_case_meta)})
        if test_cases:
            crash_info.configuration.addMetadata(
                {"recorded_envvars": " ".join(test_cases[0].env_vars)})
        else:
            self.quality = self.QUAL_NO_TESTCASE
        crash_info.configuration.addMetadata(self._extra_metadata)

        # grab screen log
        if os.getenv("WINDOW") is not None:
            screen_log = ".".join(["screenlog", os.getenv("WINDOW")])
            if os.path.isfile(screen_log):
                target_log = os.path.join(report.path, "screenlog.txt")
                shutil.copyfile(screen_log, target_log)
                Report.tail(target_log, 10240)  # limit to last 10K

        # add results to a zip file
        zip_name = "%s.zip" % (report.prefix,)
        with zipfile.ZipFile(zip_name, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_fp:
            # add test files
            for dir_name, _, dir_files in os.walk(report.path):
                arc_path = os.path.relpath(dir_name, report.path)
                for file_name in dir_files:
                    zip_fp.write(
                        os.path.join(dir_name, file_name),
                        arcname=os.path.join(arc_path, file_name))

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
        if os.path.isfile(zip_name):
            os.remove(zip_name)


class S3FuzzManagerReporter(FuzzManagerReporter):
    def _pre_submit(self, report):
        self._process_rr_trace(report)

    def _process_rr_trace(self, report):
        trace_path = os.path.join(report.path, "rr-traces")
        if not os.path.isdir(trace_path):
            return None
        s3_bucket = os.getenv("GRZ_S3_BUCKET")
        assert s3_bucket is not None
        # check for existing minor hash in S3
        s3 = boto3.resource("s3")
        s3_key = "rr-%s.tar.bz2" % (report.minor,)
        s3_url = "http://%s.s3.amazonaws.com/%s" % (s3_bucket, s3_key)
        try:
            s3.Object(s3_bucket, s3_key).load()  # HEAD, doesn't fetch the whole object
        except botocore.exceptions.ClientError as exc:
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
            shutil.rmtree(trace_path)
            return s3_url

        # Upload to S3
        rr_arc = FilesystemReporter.compress_rr_trace(trace_path, report.path)
        s3.meta.client.upload_file(rr_arc, s3_bucket, s3_key, ExtraArgs={"ACL": "public-read"})
        os.unlink(rr_arc)
        self._extra_metadata["rr-trace"] = s3_url
        return s3_url

    @staticmethod
    def sanity_check(bin_file):
        if os.getenv("GRZ_S3_BUCKET") is None:
            raise EnvironmentError("'GRZ_S3_BUCKET' is not set in environment")
        if _boto_import_error is not None:
            raise _boto_import_error  # pylint: disable=raising-bad-type
        FuzzManagerReporter.sanity_check(bin_file)
