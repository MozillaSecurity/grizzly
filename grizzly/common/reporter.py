# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod
from enum import IntEnum, unique
from json import dumps, loads
from logging import getLogger
from os import getenv
from pathlib import Path
from shutil import copyfile, move, rmtree
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

# import FuzzManager utilities
from Collector.Collector import Collector
from fasteners.process_lock import InterProcessLock
from FTB.ProgramConfiguration import ProgramConfiguration
from psutil import disk_usage

from .report import Report
from .utils import grz_tmp

__all__ = ("FilesystemReporter", "FuzzManagerReporter", "Quality")
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
            test_cases (iterable): A collection of testcases, ordered oldest to newest,
                                   the newest being the mostly likely to trigger
                                   the result (crash, assert... etc).
            report (Report): Report to submit.

        Returns:
            *: implementation specific result indicating where the report was created
        """
        assert isinstance(report, Report)
        assert report.path is not None
        assert (
            not test_cases or test_cases[0].timestamp <= test_cases[-1].timestamp
        ), "tests must be ordered oldest to newest"
        self._pre_submit(report)
        # output report contents to console
        if self.display_logs:
            if not report.is_hang:
                LOG.info(
                    "=== BEGIN REPORT ===\n%s",
                    report.preferred.read_text("utf-8", errors="ignore"),
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

    __slots__ = ("major_bucket", "min_space", "report_path", "report_prefix")

    def __init__(self, report_path, major_bucket=True):
        super().__init__()
        self.major_bucket = major_bucket
        self.min_space = FilesystemReporter.DISK_SPACE_ABORT
        self.report_path = Path(report_path)
        self.report_prefix = None

    def _pre_submit(self, report):
        self.report_prefix = report.prefix

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
        for test_number, test_case in enumerate(reversed(test_cases)):
            dump_path = dest / f"{self.report_prefix}-{test_number}"
            dump_path.mkdir(exist_ok=True)
            test_case.dump(dump_path, include_details=True)
        # move logs into bucket directory
        log_path = dest / f"{self.report_prefix}_logs"
        if log_path.is_dir():
            LOG.warning("Report log path exists '%s'", log_path)
        move(report.path, log_path)
        # avoid filling the disk
        free_space = disk_usage(str(log_path)).free
        if free_space < self.min_space:
            raise RuntimeError(f"Low disk space: {free_space / 1_048_576:0.1f}MBs")
        return dest


class FailedLaunchReporter(FilesystemReporter):
    """Save launch failure reports to disk."""

    def __init__(self, display=False):
        super().__init__(grz_tmp("launch_failures"), major_bucket=False)
        self.display_logs = display
        if not display:
            LOG.info("Display logs with --display-launch-failures")

    def _post_submit(self):
        super()._post_submit()
        LOG.info(
            "Logs for %r can be found here '%s'", self.report_prefix, self.report_path
        )


class FuzzManagerReporter(Reporter):
    FM_CONFIG = Path.home() / ".fuzzmanagerconf"

    __slots__ = ("_extra_metadata", "force_report", "quality", "tool")

    def __init__(self, tool):
        super().__init__()
        assert isinstance(tool, str)
        self._extra_metadata = {}
        self.force_report = False
        self.quality = Quality.UNREDUCED
        # remove whitespace and use only lowercase
        self.tool = "-".join(tool.lower().split())
        assert self.tool, "tool value cannot be empty"

    def _post_submit(self):
        self._extra_metadata.clear()

    @staticmethod
    def sanity_check(bin_file):
        """Perform FuzzManager sanity check.

        Args:
            bin_file (Path): Binary file being tested.

        Returns:
            None
        """
        if not FuzzManagerReporter.FM_CONFIG.is_file():
            raise OSError(f"Missing: {FuzzManagerReporter.FM_CONFIG}")
        if not Path(f"{bin_file}.fuzzmanagerconf").is_file():
            raise OSError(f"Missing: {bin_file}.fuzzmanagerconf")
        ProgramConfiguration.fromBinary(str(bin_file))

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
            rmtree(trace_path)

    @staticmethod
    def _ignored(report):
        # This is here to prevent reporting stack-less crashes
        # that were caused by system OOM
        log_data = report.preferred.read_text("utf-8", errors="ignore")
        # ignore sanitizer OOMs missing stack
        if report.stack is None:
            mem_errs = (
                "ERROR: Failed to mmap",
                # NOTE: max_allocation_size_mb can trigger a similar message
                ": AddressSanitizer failed to allocate",
                "Sanitizer: internal allocator is out of memory trying to allocate",
            )
            # scan log data for memory error strings
            if any(msg in log_data for msg in mem_errs):
                return True
        # ignore Valgrind crashes
        return log_data.startswith("VEX temporary storage exhausted.")

    def _submit_report(self, report, test_cases):
        collector = Collector(tool=self.tool)

        if not self.force_report:
            if collector.sigCacheDir and Path(collector.sigCacheDir).is_dir():
                # search for a cached signature match
                with InterProcessLock(str(grz_tmp() / "fm_sigcache.lock")):
                    _, cache_metadata = collector.search(report.crash_info)
                # check if signature has been marked as frequent in FM
                if cache_metadata and cache_metadata["frequent"]:
                    LOG.info(
                        "Frequent crash matched existing signature: %s",
                        cache_metadata["shortDescription"],
                    )
                    return None
            else:
                LOG.debug("sigCacheDir does not exist (%r)", collector.sigCacheDir)

        if self._ignored(report):
            LOG.info("Report is in ignore list")
            return None

        if report.is_hang:
            self.add_extra_metadata("is_hang", True)

        # dump test cases and the contained files to working directory
        test_case_meta = []
        for test_number, test_case in enumerate(reversed(test_cases)):
            test_case_meta.append([test_case.adapter_name, test_case.input_fname])
            dump_path = report.path / f"{report.prefix}-{test_number}"
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
            screen_log = Path.cwd() / f"screenlog.{getenv('WINDOW')}"
            if screen_log.is_file():
                target_log = report.path / "screenlog.txt"
                copyfile(screen_log, target_log)
                Report.tail(target_log, 10240)  # limit to last 10K

        with TemporaryDirectory(prefix="fm-zip", dir=grz_tmp()) as tmp_dir:
            # add results to a zip file
            zip_name = Path(tmp_dir) / f"{report.prefix}.zip"
            with ZipFile(zip_name, mode="w", compression=ZIP_DEFLATED) as zip_fp:
                # add test files
                for entry in report.path.rglob("*"):
                    if entry.is_file():
                        zip_fp.write(entry, arcname=entry.relative_to(report.path))

            # submit results to the FuzzManager server
            new_entry = collector.submit(
                report.crash_info, testCase=zip_name, testCaseQuality=self.quality.value
            )
        LOG.info(
            "Reported: %d, %s, %s",
            new_entry["id"],
            self.quality.name,
            collector.tool,
        )

        return new_entry["id"]
