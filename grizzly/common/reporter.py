# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from abc import ABCMeta, abstractmethod
from collections import namedtuple
from hashlib import sha1
from json import dump, dumps, loads
from logging import WARNING, getLogger
from os import SEEK_END, getcwd, getenv, makedirs, mkdir, scandir, stat, unlink, walk
from os.path import basename, expanduser, isdir, isfile
from os.path import join as pathjoin
from os.path import realpath, relpath
from platform import machine, system
from re import DOTALL, VERBOSE
from re import compile as re_compile
from shutil import copyfile, copyfileobj, move, rmtree
from tarfile import open as tar_open
from tempfile import mkstemp
from time import strftime
from zipfile import ZIP_DEFLATED, ZipFile

# import FuzzManager utilities
from Collector.Collector import Collector
from fasteners.process_lock import InterProcessLock
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo
from psutil import disk_usage

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

__all__ = (
    "FilesystemReporter",
    "FuzzManagerReporter",
    "Report",
    "S3FuzzManagerReporter",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)

# NOTE: order matters, aux -> stderr -> stdout
LogMap = namedtuple("LogMap", "aux stderr stdout")


class Report:
    DEFAULT_MAJOR = "NO_STACK"
    DEFAULT_MINOR = "0"
    HANG_STACK_HEIGHT = 10
    MAX_LOG_SIZE = 1048576  # 1MB

    __slots__ = (
        "_crash_info",
        "_logs",
        "_signature",
        "_target_binary",
        "is_hang",
        "path",
        "prefix",
        "stack",
    )

    def __init__(self, log_path, target_binary, is_hang=False, size_limit=MAX_LOG_SIZE):
        assert isinstance(log_path, str)
        assert isinstance(target_binary, str)
        self._crash_info = None
        self._logs = self.select_logs(log_path)
        assert self._logs is not None
        self._signature = None
        self._target_binary = target_binary
        self.is_hang = is_hang
        self.path = log_path
        # tail files in log_path if needed
        if size_limit < 1:
            LOG.warning("No limit set on report log size!")
        else:
            with scandir(path=log_path) as contents:
                for log in contents:
                    if log.is_file() and log.stat().st_size > size_limit:
                        Report.tail(log.path, size_limit)
        # look through logs one by one until we find a stack
        for log_file in (x for x in self._logs if x is not None):
            with open(log_file, "rb") as log_fp:
                stack = Stack.from_text(log_fp.read().decode("utf-8", errors="ignore"))
            if stack.frames:
                # limit the hash calculations to the first n frames if a hang
                # was detected to attempt to help local bucketing
                stack.height_limit = self.HANG_STACK_HEIGHT if is_hang else None
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
                    aux_data = (
                        log_fp.read().decode("utf-8", errors="ignore").splitlines()
                    )
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
                    system(),
                )
            with open(self._logs.stderr, "rb") as err_fp, open(
                self._logs.stdout, "rb"
            ) as out_fp:
                self._crash_info = CrashInfo.fromRawCrashData(
                    out_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    err_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    fm_cfg,
                    auxCrashData=aux_data,
                )
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
                maxFrames=self.crash_signature_max_frames(self.crash_info)
            )
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

    @staticmethod
    def _find_ffpuppet_worker(logs):
        """Search through list of log files for a ffpuppet worker log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
        """
        found = None
        for fname in (x for x in logs if "ffp_worker" in x):
            if found is not None:
                # we only expect one log here...
                LOG.warning("overwriting previously selected %r", found)
            found = fname
        return found

    @staticmethod
    def _find_minidump(logs):
        """Search through list of log files for a minidump log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
        """
        re_dump_req = re_compile(
            r"\d+\|0\|.+?\|google_breakpad::ExceptionHandler::WriteMinidump"
        )
        for fname in (x for x in logs if "minidump" in x):
            with open(fname, "r") as log_fp:
                data = log_fp.read(65536)
                # this will select log that contains "Crash|SIGSEGV|" or
                # the desired "DUMP_REQUESTED" log
                # TODO: review this it may be too strict
                # see mozilla-central/source/accessible/ipc/DocAccessibleParent.cpp#452
                if "Crash|DUMP_REQUESTED|" not in data or re_dump_req.search(data):
                    return fname
        return None

    @staticmethod
    def _find_sanitizer(logs):
        """Search through list of log files for a sanitizer (ASan, UBSan, etc...) log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
        """
        # pattern to identify the ASan crash triggered when the parent process goes away
        # TODO: this may no longer be required
        re_e10s_forced = re_compile(
            r"""
            ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
            #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
            """,
            DOTALL | VERBOSE,
        )
        # this is a list of Sanitizer error reports to prioritize
        # Sanitizer reports not included below are deprioritized
        prioritize_tokens = (
            "use-after-",
            "-buffer-overflow on",
            ": SEGV on ",
            "access-violation on ",
            "attempting free on ",
            "negative-size-param",
            "-param-overlap",
        )
        found = None
        for fname in (x for x in logs if "asan" in x):
            with open(fname, "r") as log_fp:
                data = log_fp.read(65536)
            # look for interesting crash info in the log
            if "==ERROR:" in data:
                # check for e10s forced crash
                if re_e10s_forced.search(data) is not None:
                    continue
                # make sure there is something that looks like a stack frame
                if "#0 " in data:
                    found = fname
                    if any(x in data for x in prioritize_tokens):
                        # this is the likely cause of the crash
                        break
            if found is None:
                # UBSan error (non-ASan builds)
                if ": runtime error: " in data:
                    found = fname
                # catch all (choose the one with info for now)
                elif data:
                    found = fname
        return found

    @staticmethod
    def _find_valgrind(logs):
        """Search through list of log files for a Valgrind worker log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
        """
        for fname in (x for x in logs if "valgrind" in x):
            if stat(fname).st_size:
                return fname
        return None

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

    @classmethod
    def select_logs(cls, path):
        """Scan path for file containing stderr, stdout and other (aux)
        data and build a LogMap.

        Args:
            path (str): Path to scan for log files.

        Returns:
            LogMap: A LogMap pointing to log files or None if path is empty.
        """
        to_scan = None
        with scandir(path=path) as contents:
            files = (x for x in contents if x.is_file())
            # order by date hopefully the oldest log is the cause of the issue
            to_scan = [x.path for x in sorted(files, key=lambda x: x.stat().st_mtime)]
        if not to_scan:
            LOG.warning("No files found in %r", path)
            return None
        # look for file to use as aux log
        log_aux = cls._find_sanitizer(to_scan)
        if log_aux is None:
            log_aux = cls._find_valgrind(to_scan)
        if log_aux is None:
            log_aux = cls._find_minidump(to_scan)
        if log_aux is None:
            log_aux = cls._find_ffpuppet_worker(to_scan)
        # look for stderr and stdout log files
        log_err = None
        log_out = None
        for fname in to_scan:
            if "stderr" in fname:
                log_err = fname
            elif "stdout" in fname:
                log_out = fname
        result = LogMap(log_aux, log_err, log_out)
        return result if any(result) else None

    @staticmethod
    def tail(in_file, size_limit):
        """Tail the given file. WARNING: This is destructive!

        Args:
            in_file (str): Path to file to work with.
            size_limit (int): Maximum size of file after tail operation.

        Returns:
            None
        """
        assert size_limit > 0
        with open(in_file, "rb") as in_fp:
            in_fp.seek(0, SEEK_END)
            end = in_fp.tell()
            if end <= size_limit:
                return
            dump_pos = end - size_limit
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
        self.min_space = FilesystemReporter.DISK_SPACE_ABORT
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
        if free_space < self.min_space:
            raise RuntimeError(
                "Running low on disk space (%0.1fMB)" % (free_space / 1048576.0,)
            )
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
    QUAL_NO_TESTCASE = 7  # testcase not detected ("testcase" not a testcase?)
    QUAL_REDUCER_BROKE = 8  # the testcase was reproducible, but broke during reduction
    QUAL_REDUCER_ERROR = 9  # reducer error
    QUAL_NOT_REPRODUCIBLE = 10  # could not reproduce the testcase

    def __init__(self, tool=None):
        self._extra_metadata = {}
        self.force_report = False
        self.max_reports = FuzzManagerReporter.MAX_REPORTS
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
            value (object): JSON serializable object to be included in the FM crash
                            metadata. The object will be deep-copied.

        Returns:
            None
        """
        assert isinstance(key, str)
        assert key not in self._extra_metadata
        # deep copy and ensure that value is JSON serializable
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
            self.add_extra_metadata("rr-trace", "ignored")
            # remove traces so they are not uploaded to FM (because they are huge)
            # use S3FuzzManagerReporter instead
            rmtree(trace_path)

    @staticmethod
    def _ignored(report):
        # This is here to prevent reporting stack-less crashes
        # that were caused by system OOM or bogus other crashes
        with open(report.preferred, "rb") as log_fp:
            log_data = log_fp.read().decode("utf-8", errors="ignore")
        mem_errs = ("ERROR: Failed to mmap", ": AddressSanitizer failed to allocate")
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
                    LOG.info(
                        "Frequent crash matched existing signature: %s",
                        cache_metadata["shortDescription"],
                    )
                    if not self.force_report:
                        return None
                elif "bug__id" in cache_metadata:
                    LOG.info(
                        "Crash matched existing signature (bug %s): %s",
                        cache_metadata["bug__id"],
                        cache_metadata["shortDescription"],
                    )
                    # we will still report this one, but no more
                    cache_metadata["frequent"] = True
                # there is already a signature, initialize count
                cache_metadata.setdefault("_grizzly_seen_count", 0)
            else:
                # there is no signature, create one locally so we can count
                # the number of times we've seen it
                max_frames = report.crash_signature_max_frames(report.crash_info)
                cache_sig_file = collector.generate(
                    report.crash_info, numFrames=max_frames
                )
                cache_metadata = {
                    "_grizzly_seen_count": 0,
                    "frequent": False,
                    "shortDescription": report.crash_info.createShortSignature(),
                }
            if cache_sig_file is None:
                if self._ignored(report):
                    LOG.info("Report is unsupported and is in ignore list")
                    return None
                LOG.warning("Report is unsupported by FM, saved to %r", report.path)
                # TODO: we should check if stackhasher failed too
                raise RuntimeError("Failed to create FM signature")
            # limit the number of times we report per cycle
            cache_metadata["_grizzly_seen_count"] += 1
            if cache_metadata["_grizzly_seen_count"] >= self.max_reports:
                # we will still report this one, but no more
                cache_metadata["frequent"] = True
            metadata_file = cache_sig_file.replace(".signature", ".metadata")
            with open(metadata_file, "w") as meta_fp:
                dump(cache_metadata, meta_fp)

        if report.is_hang:
            self.add_extra_metadata("is_hang", True)

        # dump test cases and the contained files to working directory
        test_case_meta = []
        for test_number, test_case in enumerate(test_cases):
            test_case_meta.append([test_case.adapter_name, test_case.input_fname])
            dump_path = pathjoin(report.path, "%s-%d" % (report.prefix, test_number))
            if not isdir(dump_path):
                mkdir(dump_path)
            test_case.dump(dump_path, include_details=True)
        report.crash_info.configuration.addMetadata(
            {"grizzly_input": repr(test_case_meta)}
        )
        if test_cases:
            environ_string = " ".join(
                "=".join(kv) for kv in test_cases[0].env_vars.items()
            )
            report.crash_info.configuration.addMetadata(
                {"recorded_envvars": environ_string}
            )
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
                        arcname=pathjoin(arc_path, file_name),
                    )

        # override tool name if specified
        if self.tool is not None:
            collector.tool = self.tool

        # announce shortDescription if crash is not in a bucket
        if (
            cache_metadata["_grizzly_seen_count"] == 1
            and not cache_metadata["frequent"]
        ):
            LOG.info("Submitting new crash %r", cache_metadata["shortDescription"])
        # submit results to the FuzzManager server
        new_entry = collector.submit(
            report.crash_info, testCase=zip_name, testCaseQuality=self.quality
        )
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
        s3_res = resource("s3")
        s3_key = "rr-%s.tar.bz2" % (report.minor,)
        s3_url = "http://%s.s3.amazonaws.com/%s" % (s3_bucket, s3_key)
        try:
            # HEAD, doesn't fetch the whole object
            s3_res.Object(s3_bucket, s3_key).load()
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
        s3_res.meta.client.upload_file(
            rr_arc, s3_bucket, s3_key, ExtraArgs={"ACL": "public-read"}
        )
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
