# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod
from enum import IntEnum, unique
from json import dumps, loads
from logging import WARNING, getLogger
from os import getenv
from pathlib import Path
from shutil import copyfile, move, rmtree
from tarfile import open as tar_open
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

# import FuzzManager utilities
from Collector.Collector import Collector
from fasteners.process_lock import InterProcessLock
from FTB.ProgramConfiguration import ProgramConfiguration
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

from .report import Report
from .utils import grz_tmp

__all__ = (
    "FilesystemReporter",
    "FuzzManagerReporter",
    "Quality",
    "S3FuzzManagerReporter",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


@unique
class Quality(IntEnum):
    """testcase quality values"""

    # final reduced testcase
    REDUCED = 0
    # original used for reduction (a reduced version exists)
    ORIGINAL = 1
    # used to manually mark a report as unreducible
    IGNORED = 3
    # the testcase is currently being reduced
    REDUCING = 4
    # haven't attempted reduction yet (1st attempt, generic reducer)
    UNREDUCED = 5
    # platform specific reduction requested (2nd attempt)
    REQUEST_SPECIFIC = 6
    # testcase not detected ("testcase" not a testcase?)
    NO_TESTCASE = 7
    # the testcase was reproducible, but broke during reduction
    REDUCER_BROKE = 8
    # reducer error
    REDUCER_ERROR = 9
    # could not reproduce the testcase
    NOT_REPRODUCIBLE = 10


class Reporter(metaclass=ABCMeta):
    __slots__ = ("display_logs",)

    def __init__(self):
        self.display_logs = getenv("GRZ_DISPLAY_REPORT") == "1"

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
        # output report contents to console
        if self.display_logs:
            if not report.is_hang:
                with open(report.preferred, "rb") as log_fp:
                    LOG.info(
                        "=== BEGIN REPORT ===\n%s",
                        log_fp.read().decode("utf-8", errors="ignore"),
                    )
            else:
                LOG.info("=== BEGIN REPORT ===\nBrowser hang detected")
            LOG.info("=== END REPORT ===")
        result = self._submit_report(report, test_cases)
        if report is not None:
            report.cleanup()
        self._post_submit()
        return result


class FilesystemReporter(Reporter):
    DISK_SPACE_ABORT = 512 * 1024 * 1024  # 512 MB

    __slots__ = ("major_bucket", "min_space", "report_path")

    def __init__(self, report_path, major_bucket=True):
        super().__init__()
        self.major_bucket = major_bucket
        self.min_space = FilesystemReporter.DISK_SPACE_ABORT
        self.report_path = Path(report_path)

    def _pre_submit(self, report):
        pass

    def _post_submit(self):
        pass

    def _submit_report(self, report, test_cases):
        # create major bucket directory in working directory if needed
        if self.major_bucket:
            dest = self.report_path / report.major[:16]
        else:
            dest = self.report_path
        dest.mkdir(parents=True, exist_ok=True)
        # dump test cases and the contained files to working directory
        for test_number, test_case in enumerate(test_cases):
            dump_path = dest / ("%s-%d" % (report.prefix, test_number))
            dump_path.mkdir(exist_ok=True)
            test_case.dump(dump_path, include_details=True)
        # move logs into bucket directory
        log_path = dest / ("%s_%s" % (report.prefix, "logs"))
        if log_path.is_dir():
            LOG.warning("Report log path exists %r", str(log_path))
        move(str(report.path), str(log_path))
        # avoid filling the disk
        free_space = disk_usage(str(log_path)).free
        if free_space < self.min_space:
            raise RuntimeError(
                "Running low on disk space (%0.1fMB)" % (free_space / 1048576.0,)
            )
        return dest


class FuzzManagerReporter(Reporter):
    FM_CONFIG = Path.home() / ".fuzzmanagerconf"

    __slots__ = ("_extra_metadata", "force_report", "quality", "tool")

    def __init__(self, tool=None):
        super().__init__()
        self._extra_metadata = {}
        self.force_report = False
        self.quality = Quality.UNREDUCED
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
        if not FuzzManagerReporter.FM_CONFIG.is_file():
            raise IOError("Missing: %s" % (FuzzManagerReporter.FM_CONFIG,))
        if not Path("".join([bin_file, ".fuzzmanagerconf"])).is_file():
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

    def _pre_submit(self, report):
        self._process_rr_trace(report)

    def _process_rr_trace(self, report):
        # don't report large files to FuzzManager
        trace_path = report.path / "rr-traces"
        if trace_path.is_dir():
            LOG.info("Ignored rr trace")
            self.add_extra_metadata("rr-trace", "ignored")
            # remove traces so they are not uploaded to FM (because they are huge)
            # use S3FuzzManagerReporter instead
            rmtree(str(trace_path))

    @staticmethod
    def _ignored(report):
        # This is here to prevent reporting stack-less crashes
        # that were caused by system OOM
        with open(report.preferred, "rb") as log_fp:
            log_data = log_fp.read().decode("utf-8", errors="ignore")
        # ignore sanitizer OOMs missing stack
        if report.stack is None:
            mem_errs = (
                "ERROR: Failed to mmap",
                # NOTE: max_allocation_size_mb can trigger a similar message
                ": AddressSanitizer failed to allocate",
                "Sanitizer: internal allocator is out of memory trying to allocate",
            )
            for msg in mem_errs:
                if msg in log_data:
                    return True
        # ignore Valgrind crashes
        if log_data.startswith("VEX temporary storage exhausted."):
            return True
        return False

    def _submit_report(self, report, test_cases):
        collector = Collector()

        if not self.force_report:
            # search for a cached signature match
            with InterProcessLock(str(Path(grz_tmp()) / "fm_sigcache.lock")):
                _, cache_metadata = collector.search(report.crash_info)

            # check if signature has been marked as frequent in FM
            if cache_metadata is not None and cache_metadata["frequent"]:
                LOG.info(
                    "Frequent crash matched existing signature: %s",
                    cache_metadata["shortDescription"],
                )
                return None

        if self._ignored(report):
            LOG.info("Report is in ignore list")
            return None

        if report.is_hang:
            self.add_extra_metadata("is_hang", True)

        # dump test cases and the contained files to working directory
        test_case_meta = []
        for test_number, test_case in enumerate(test_cases):
            test_case_meta.append([test_case.adapter_name, test_case.input_fname])
            dump_path = report.path / ("%s-%d" % (report.prefix, test_number))
            dump_path.mkdir(exist_ok=True)
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
            self.quality = Quality.NO_TESTCASE
        report.crash_info.configuration.addMetadata(self._extra_metadata)

        # TODO: this should likely move to ffpuppet
        # grab screen log (used in automation)
        if getenv("WINDOW") is not None:
            screen_log = Path.cwd() / ("screenlog.%s" % (getenv("WINDOW"),))
            if screen_log.is_file():
                target_log = report.path / "screenlog.txt"
                copyfile(str(screen_log), str(target_log))
                Report.tail(target_log, 10240)  # limit to last 10K

        with TemporaryDirectory(prefix="fm-zip", dir=grz_tmp()) as tmp_dir:
            # add results to a zip file
            zip_name = Path(tmp_dir) / ("%s.zip" % (report.prefix,))
            with ZipFile(zip_name, mode="w", compression=ZIP_DEFLATED) as zip_fp:
                # add test files
                for entry in report.path.rglob("*"):
                    if entry.is_file():
                        zip_fp.write(
                            str(entry), arcname=str(entry.relative_to(report.path))
                        )
            # override tool name if specified
            if self.tool is not None:
                collector.tool = self.tool

            # submit results to the FuzzManager server
            new_entry = collector.submit(
                report.crash_info, testCase=zip_name, testCaseQuality=self.quality.value
            )
        LOG.info("Logged %d (%s)", new_entry["id"], self.quality.name)

        return new_entry["id"]


class S3FuzzManagerReporter(FuzzManagerReporter):
    @staticmethod
    def compress_rr_trace(src, dest):
        # resolve symlink to latest trace available
        latest_trace = (src / "latest-trace").resolve(strict=True)
        assert latest_trace.is_dir(), "missing latest-trace directory"
        rr_arc = dest / "rr.tar.bz2"
        LOG.debug("creating %r from %r", rr_arc, latest_trace)
        with tar_open(rr_arc, "w:bz2") as arc_fp:
            arc_fp.add(str(latest_trace), arcname=latest_trace.name)
        # remove path containing uncompressed traces
        rmtree(str(src))
        return rr_arc

    def _pre_submit(self, report):
        self._process_rr_trace(report)

    def _process_rr_trace(self, report):
        trace_path = report.path / "rr-traces"
        if not trace_path.is_dir():
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
            rmtree(str(trace_path))
            return s3_url

        # Upload to S3
        rr_arc = self.compress_rr_trace(trace_path, report.path)
        s3_res.meta.client.upload_file(
            str(rr_arc), s3_bucket, s3_key, ExtraArgs={"ACL": "public-read"}
        )
        rr_arc.unlink()
        self.add_extra_metadata("rr-trace", s3_url)
        return s3_url

    @staticmethod
    def sanity_check(bin_file):
        if getenv("GRZ_S3_BUCKET") is None:
            raise EnvironmentError("'GRZ_S3_BUCKET' is not set in environment")
        if _boto_import_error is not None:
            raise _boto_import_error  # pylint: disable=raising-bad-type
        FuzzManagerReporter.sanity_check(bin_file)
