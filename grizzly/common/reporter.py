# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from abc import ABCMeta, abstractmethod
from collections import namedtuple
from hashlib import sha1
from json import dump, dumps, loads
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

LOG = getLogger(__name__)

# NOTE: order matters, aux -> stderr -> stdout
LogMap = namedtuple("LogMap", "aux stderr stdout")


class Report:
    DEFAULT_MAJOR = "NO_STACK"
    DEFAULT_MINOR = "0"
    MAX_LOG_SIZE = 1048576  # 1MB

    __slots__ = ("_crash_info", "_logs", "_signature", "_target_binary", "path", "prefix", "stack")

    def __init__(self, log_path, target_binary, size_limit=MAX_LOG_SIZE):
        assert isinstance(log_path, str) and isdir(log_path)
        assert isinstance(target_binary, str)
        self._crash_info = None
        self._logs = self.select_logs(log_path)
        assert self._logs is not None
        self._signature = None
        self._target_binary = target_binary
        self.path = log_path
        # tail files in log_path if needed
        if size_limit < 1:
            LOG.warning("No limit set on report log size!")
        else:
            for fname in listdir(log_path):
                log_file_path = pathjoin(log_path, fname)
                if isfile(log_file_path):
                    Report.tail(log_file_path, size_limit)
        # look through logs one by one until we find a stack
        for log_file in (x for x in self._logs if x is not None):
            with open(log_file, "rb") as log_fp:
                stack = Stack.from_text(log_fp.read().decode("utf-8", errors="ignore"))
            if stack.frames:
                self.prefix = "%s_%s" % (stack.minor[:8], strftime("%Y-%m-%d_%H-%M-%S"))
                self.stack = stack
                break
        else:
            self.prefix = "%s_%s" % (self.DEFAULT_MINOR, strftime("%Y-%m-%d_%H-%M-%S"))
            self.stack = None

    @staticmethod
    def calc_hash(signature):
        """Create unique hash from a signature.

        Args:
            None

        Returns:
            str: Hash of the raw signature.
        """
        return sha1(signature.rawSignature.encode("utf-8")).hexdigest()[:16]

    def cleanup(self):
        """Remove Report data from filesystem.

        Args:
            None

        Returns:
            None
        """
        if self.path and isdir(self.path):
            rmtree(self.path)
        self.path = None

    @property
    def crash_hash(self):
        """Create unique hash from a signature.

        Args:
            None

        Returns:
            str: Hash of the raw signature of the crash.
        """
        return self.calc_hash(self.crash_signature)

    @property
    def crash_info(self):
        """Create CrashInfo object from logs.

        Args:
            None

        Returns:
            CrashInfo: CrashInfo based on log data.
        """
        if self._crash_info is None:
            assert self.path is not None
            # read in the log files and create a CrashInfo object
            if self._logs.aux is not None:
                with open(self._logs.aux, "rb") as log_fp:
                    aux_data = log_fp.read().decode("utf-8", errors="ignore").splitlines()
            else:
                aux_data = None
            # create ProgramConfiguration that can be reported to a FM server
            if isfile("%s.fuzzmanagerconf" % (self._target_binary,)):
                # attempt to use "<target_binary>.fuzzmanagerconf"
                fm_cfg = ProgramConfiguration.fromBinary(self._target_binary)
            else:
                LOG.debug("'%s.fuzzmanagerconf' does not exist", self._target_binary)
                fm_cfg = None
            if fm_cfg is None:
                LOG.debug("creating ProgramConfiguration")
                cpu = machine().lower()
                fm_cfg = ProgramConfiguration(
                    basename(self._target_binary),
                    "x86_64" if cpu == "amd64" else cpu,
                    system())
            with open(self._logs.stderr, "rb") as err_fp, open(self._logs.stdout, "rb") as out_fp:
                self._crash_info = CrashInfo.fromRawCrashData(
                    out_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    err_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    fm_cfg,
                    auxCrashData=aux_data)
        return self._crash_info

    @property
    def crash_signature(self):
        """Create CrashSignature object from CrashInfo.

        Args:
            None

        Returns:
            CrashSignature: CrashSignature based on log data.
        """
        if self._signature is None:
            self._signature = self.crash_info.createCrashSignature(
                maxFrames=self.crash_signature_max_frames(self.crash_info))
        return self._signature

    @staticmethod
    def crash_signature_max_frames(crash_info, suggested_frames=8):
        if set(crash_info.backtrace) & {
                "std::panicking::rust_panic",
                "std::panicking::rust_panic_with_hook",
        }:
            # rust panic adds 5-6 frames of noise at the top of the stack
            suggested_frames += 6
        return suggested_frames

    @property
    def major(self):
        """The inclusive bucketing hash based on the stack trace
        data found in logs.

        Args:
            None

        Returns:
            str: major hash string.
        """
        if self.stack and self.stack.major is not None:
            return self.stack.major
        return self.DEFAULT_MAJOR

    @property
    def minor(self):
        """The specific bucketing hash based on the stack trace
        data found in logs.

        Args:
            None

        Returns:
            str: minor hash string.
        """
        if self.stack and self.stack.minor is not None:
            return self.stack.minor
        return self.DEFAULT_MINOR

    @property
    def preferred(self):
        """Log file containing most relevant data.

        Args:
            None

        Returns:
            str: Name of log.
        """
        return self._logs.aux or self._logs.stderr

    @staticmethod
    def select_logs(log_path):
        """Scan log_path for file containing stderr, stdout and other (aux)
        data and build a LogMap.

        Args:
            log_path (str): Path to scan for log files.

        Returns:
            LogMap: A LogMap pointing to files or None if log_path is empty.
        """
        # scan path for files
        to_scan = list()
        for entry in listdir(log_path):
            full_path = pathjoin(log_path, entry)
            if isfile(full_path):
                to_scan.append(full_path)
        if not to_scan:
            LOG.warning("No files found in %r", log_path)
            return None

        # order by creation date because the oldest log is likely the cause of the issue
        to_scan.sort(key=lambda x: stat(x).st_mtime)

        # pattern to identify the ASan crash triggered when the parent process goes away
        # TODO: this may no longer be required
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

        log_aux = None
        # look for sanitizer (ASan, UBSan, etc...) logs
        for fname in (x for x in to_scan if "asan" in x):
            # grab first chunk of log to help triage
            with open(fname, "r") as log_fp:
                log_data = log_fp.read(65536)
            # look for interesting crash info in the log
            if "==ERROR:" in log_data:
                # check for e10s forced crash
                if re_e10s_forced.search(log_data) is not None:
                    continue
                # make sure there is something that looks like a stack frame in the log
                if "#0 " in log_data:
                    log_aux = fname
                    if any(x in log_data for x in interesting_sanitizer_tokens):
                        break  # this is the likely cause of the crash
                    continue  # probably the most interesting but lets keep looking
            if log_aux is None:
                # UBSan error (non-ASan builds)
                if ": runtime error: " in log_data:
                    log_aux = fname
                # catch all (choose the one with info for now)
                elif log_data:
                    log_aux = fname

        # look for Valgrind logs
        if log_aux is None:
            for fname in (x for x in to_scan if "valgrind" in x):
                if stat(fname).st_size:
                    log_aux = fname
                    break

        # prefer ASan logs over minidump logs
        if log_aux is None:
            re_dump_req = re_compile(r"\d+\|0\|.+?\|google_breakpad::ExceptionHandler::WriteMinidump")
            for fname in (x for x in to_scan if "minidump" in x):
                with open(fname, "r") as log_fp:
                    log_data = log_fp.read(65536)
                    # this will select log that contains "Crash|SIGSEGV|" or
                    # the desired "DUMP_REQUESTED" log
                    # TODO: review this it may be too strict
                    # see https://searchfox.org/mozilla-central/source/accessible/ipc/DocAccessibleParent.cpp#452
                    if "Crash|DUMP_REQUESTED|" not in log_data or re_dump_req.search(log_data):
                        log_aux = fname
                        break

        # look for ffpuppet worker logs, worker logs should be used if nothing else is available
        if log_aux is None:
            for fname in (x for x in to_scan if "ffp_worker" in x):
                if log_aux is not None:
                    # we only expect one log here...
                    LOG.warning("aux log previously selected: %s, overwriting!", log_aux)
                log_aux = fname

        # look for stderr and stdout log files
        log_err = None
        log_out = None
        for fname in to_scan:
            if "stderr" in fname:
                log_err = fname
            elif "stdout" in fname:
                log_out = fname

        result = LogMap(log_aux, log_err, log_out)
        if not any(result):
            LOG.warning("No logs found in %r", log_path)
        return result

    @staticmethod
    def tail(in_file, size_limit):
        """Tail the given file. This is destructive.

        Args:
            in_file (str): Path to file to work with.
            size_limit (int): Maximum size of file after tail operation.

        Returns:
            None
        """
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
    def _post_submit(self):
        pass

    @abstractmethod
    def _pre_submit(self, report):
        pass

    @abstractmethod
    def _submit_report(self, report, test_cases):
        pass

    def submit(self, test_cases, report):
        """Submit report containing results.

        Args:
            test_cases (iterable): A collection of testcases, ordered newest to oldest,
                                   the newest being the mostly likely to trigger
                                   the result (crash, assert... etc).
            report (Report): Report to submit.

        Returns:
            *: implementation specific result indicating where the report was created
        """
        assert isinstance(report, Report)
        assert report.path is not None
        self._pre_submit(report)
        result = self._submit_report(report, test_cases)
        if report is not None:
            report.cleanup()
        self._post_submit()
        return result


class FilesystemReporter(Reporter):
    DISK_SPACE_ABORT = 512 * 1024 * 1024  # 512 MB

    __slots__ = ("major_bucket", "report_path")

    def __init__(self, report_path, major_bucket=True):
        self.major_bucket = major_bucket
        assert isinstance(report_path, str) and report_path
        self.report_path = report_path

    def _pre_submit(self, report):
        pass

    def _post_submit(self):
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
            LOG.warning("Report log path exists %r", log_path)
        move(report.path, log_path)
        # avoid filling the disk
        free_space = disk_usage(log_path).free
        if free_space < self.DISK_SPACE_ABORT:
            raise RuntimeError("Running low on disk space (%0.1fMB)" % (free_space / 1048576.0,))
        return dest_path


class FuzzManagerReporter(Reporter):
    FM_CONFIG = pathjoin(expanduser("~"), ".fuzzmanagerconf")
    # max number of times to report a non-frequent signature to FuzzManager
    MAX_REPORTS = 10

    # testcase quality values
    QUAL_REDUCED_RESULT = 0  # the final reduced testcase
    QUAL_REDUCED_ORIGINAL = 1  # the original used for successful reduction
    QUAL_REDUCING = 4  # the testcase is currently being reduced
    QUAL_UNREDUCED = 5  # haven't attempted reduction yet (1st attempt, generic reducer)
    QUAL_REQUEST_SPECIFIC = 6  # platform specific reduction requested (2nd attempt)
    QUAL_NO_TESTCASE = 7  # no testcase was detected (could be the "testcase" is not a testcase)
    QUAL_REDUCER_BROKE = 8  # the testcase was reproducible, but broke during reduction
    QUAL_REDUCER_ERROR = 9  # reducer error
    QUAL_NOT_REPRODUCIBLE = 10  # could not reproduce the testcase

    def __init__(self, tool=None):
        self._extra_metadata = {}
        self.force_report = False
        self.quality = self.QUAL_UNREDUCED
        self.tool = tool  # optional tool name

    def _post_submit(self):
        self._extra_metadata.clear()

    @staticmethod
    def sanity_check(bin_file):
        """Perform FuzzManager sanity check.

        Args:
            bin_file (str): Binary file being tested.

        Returns:
            None
        """
        if not isfile(FuzzManagerReporter.FM_CONFIG):
            raise IOError("Missing: %s" % (FuzzManagerReporter.FM_CONFIG,))
        if not isfile("".join([bin_file, ".fuzzmanagerconf"])):
            raise IOError("Missing: %s.fuzzmanagerconf" % (bin_file,))
        ProgramConfiguration.fromBinary(bin_file)

    def add_extra_metadata(self, key, value):
        """Add extra metadata to be reported with any CrashEntrys reported.

        Arguments:
            key (str): key for this data in the metadata dict
            value (object): JSON serializable object to be included in the FM crash metadata.
                            The object will be deep-copied.

        Returns:
            None
        """
        assert isinstance(key, str)
        assert key not in self._extra_metadata
        # this not only does a deep copy, but also ensures that value is JSON serializable
        self._extra_metadata[key] = loads(dumps(value))

    @classmethod
    def quality_name(cls, value):
        for name in dir(cls):
            if name.startswith("QUAL_") and getattr(cls, name) == value:
                return name
        return "unknown quality (%r)" % (value,)

    def _pre_submit(self, report):
        self._process_rr_trace(report)

    def _process_rr_trace(self, report):
        # don't report large files to FuzzManager
        trace_path = pathjoin(report.path, "rr-traces")
        if isdir(trace_path):
            LOG.info("Ignored rr trace")
            self.add_extra_metadata("rr-trace",  "ignored")
            # remove traces so they are not uploaded to FM (because they are huge)
            # use S3FuzzManagerReporter instead
            rmtree(trace_path)

    @staticmethod
    def _ignored(report):
        # This is here to prevent reporting stack-less crashes
        # that were caused by system OOM or bogus other crashes
        with open(report.preferred, "rb") as log_fp:
            log_data = log_fp.read().decode("utf-8", errors="ignore")
        mem_errs = (
            "ERROR: Failed to mmap",
            ": AddressSanitizer failed to allocate")
        # ignore sanitizer OOMs missing stack
        for msg in mem_errs:
            if msg in log_data and "#0 " not in log_data:
                return True
        # ignore Valgrind crashes
        if log_data.startswith("VEX temporary storage exhausted."):
            return True
        return False

    def _submit_report(self, report, test_cases):
        # search for a cached signature match and if the signature
        # is already in the cache and marked as frequent, don't bother submitting
        with InterProcessLock(pathjoin(grz_tmp(), "fm_sigcache.lock")):
            collector = Collector()
            cache_sig_file, cache_metadata = collector.search(report.crash_info)
            if cache_metadata is not None:
                if cache_metadata["frequent"]:
                    LOG.info("Frequent crash matched existing signature: %s",
                             cache_metadata["shortDescription"])
                    if not self.force_report:
                        return None
                elif "bug__id" in cache_metadata:
                    LOG.info("Crash matched existing signature (bug %s): %s",
                             cache_metadata["bug__id"],
                             cache_metadata["shortDescription"])
                    # we will still report this one, but no more
                    cache_metadata["frequent"] = True
                # there is already a signature, initialize count
                cache_metadata.setdefault("_grizzly_seen_count", 0)
            else:
                # there is no signature, create one locally so we can count
                # the number of times we've seen it
                max_frames = report.crash_signature_max_frames(report.crash_info)
                cache_sig_file = collector.generate(report.crash_info, numFrames=max_frames)
                cache_metadata = {
                    "_grizzly_seen_count": 0,
                    "frequent": False,
                    "shortDescription": report.crash_info.createShortSignature()}
            if cache_sig_file is None:
                if self._ignored(report):
                    LOG.info("Report is unsupported and is in ignore list")
                    return None
                LOG.warning("Report is unsupported by FM, saved to %r", report.path)
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
        report.crash_info.configuration.addMetadata({"grizzly_input": repr(test_case_meta)})
        if test_cases:
            environ_string = " ".join("=".join(kv) for kv in test_cases[0].env_vars.items())
            report.crash_info.configuration.addMetadata({"recorded_envvars": environ_string})
        else:
            self.quality = self.QUAL_NO_TESTCASE
        report.crash_info.configuration.addMetadata(self._extra_metadata)

        # grab screen log (used in automation)
        if getenv("WINDOW") is not None:
            screen_log = pathjoin(getcwd(), ".".join(["screenlog", getenv("WINDOW")]))
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
            LOG.info("Submitting new crash %r", cache_metadata["shortDescription"])
        # submit results to the FuzzManager server
        new_entry = collector.submit(report.crash_info, testCase=zip_name, testCaseQuality=self.quality)
        LOG.info("Logged %d with quality %d", new_entry["id"], self.quality)

        # remove zipfile
        if isfile(zip_name):
            unlink(zip_name)

        return new_entry["id"]


class S3FuzzManagerReporter(FuzzManagerReporter):
    @staticmethod
    def compress_rr_trace(src, dest):
        # resolve symlink to latest trace available
        latest_trace = realpath(pathjoin(src, "latest-trace"))
        assert isdir(latest_trace), "missing latest-trace directory"
        rr_arc = pathjoin(dest, "rr.tar.bz2")
        LOG.debug("creating %r from %r", rr_arc, latest_trace)
        with tar_open(rr_arc, "w:bz2") as arc_fp:
            arc_fp.add(latest_trace, arcname=basename(latest_trace))
        # remove path containing uncompressed traces
        rmtree(src)
        return rr_arc

    def _pre_submit(self, report):
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
            else:  # pragma: no cover
                # Something else has gone wrong.
                raise
        else:
            # The object already exists.
            LOG.info("rr trace exists at %r", s3_url)
            self.add_extra_metadata("rr-trace", s3_url)
            # remove traces so they are not reported to FM
            rmtree(trace_path)
            return s3_url

        # Upload to S3
        rr_arc = self.compress_rr_trace(trace_path, report.path)
        s3.meta.client.upload_file(rr_arc, s3_bucket, s3_key, ExtraArgs={"ACL": "public-read"})
        unlink(rr_arc)
        self.add_extra_metadata("rr-trace", s3_url)
        return s3_url

    @staticmethod
    def sanity_check(bin_file):
        if getenv("GRZ_S3_BUCKET") is None:
            raise EnvironmentError("'GRZ_S3_BUCKET' is not set in environment")
        if _boto_import_error is not None:
            raise _boto_import_error  # pylint: disable=raising-bad-type
        FuzzManagerReporter.sanity_check(bin_file)
