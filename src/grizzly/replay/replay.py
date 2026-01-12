# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from dataclasses import dataclass
from logging import getLogger
from pathlib import Path
from tempfile import mkdtemp
from typing import TYPE_CHECKING, cast

from sapphire import ServerMap

from ..common.frontend import ConfigError, Exit
from ..common.report import Report
from ..common.reporter import FilesystemReporter, FuzzManagerReporter
from ..common.runner import Runner, RunResult
from ..common.status import SimpleStatus
from ..common.utils import HARNESS_FILE, grz_tmp
from ..target import Result, Target

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from FTB.Signatures.CrashInfo import CrashSignature

    from sapphire import Sapphire

    from ..common.storage import TestCase
    from ..services import WebServices

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


@dataclass(eq=False, slots=True)
class ReplayResult:
    """Contains information related to the replay of testcases.

    Attributes:
        report: Report containing logs.
        durations: Number of seconds spent running each testcase.
        expected: Signature match.
        count: Number of times detected.
    """

    report: Report
    durations: list[float]
    expected: bool
    count: int = 1


class ReplayManager:
    __slots__ = (
        "_any_crash",
        "_harness",
        "_relaunch",
        "_signature",
        "_unpacked",
        "ignore",
        "server",
        "status",
        "target",
    )

    def __init__(
        self,
        ignore: Iterable[str],
        server: Sapphire,
        target: Target,
        any_crash: bool = False,
        relaunch: int = 1,
        signature: CrashSignature | None = None,
        use_harness: bool = True,
    ) -> None:
        # target must relaunch every iteration when not using harness
        assert use_harness or relaunch == 1
        self.ignore = ignore
        self.server = server
        self.status: SimpleStatus | None = None
        self.target = target
        self._any_crash = any_crash
        self._harness = HARNESS_FILE.read_bytes() if use_harness else None
        self._relaunch = relaunch
        self._signature = signature

    def __enter__(self) -> ReplayManager:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    @property
    def signature(self) -> CrashSignature | None:
        return self._signature

    @staticmethod
    def check_match(
        signature: CrashSignature, report: Report, expect_hang: bool, check_failed: bool
    ) -> bool:
        """Check if report matches signature.

        Args:
            signature: Signature to match.
            report: Report to check against signature.
            expect_hang: Indicates if a hang is expected.
            check_failed: Check if report signature creation failed.

        Returns:
            True if report matches signature otherwise False.
        """
        if signature is None:
            if check_failed and not report.is_hang:
                # treat failed signature creation as a match
                return report.crash_signature is None
            # treat 'None' signature as a bucket if it's not a hang
            return not report.is_hang
        if expect_hang and not report.is_hang:
            # avoid catching other crashes with forgiving hang signatures
            return False
        # Fuzzmanager is missing type hints, use cast()
        return cast("bool", signature.matches(report.crash_info))

    def cleanup(self) -> None:
        """Remove temporary files from disk.

        Args:
            None

        Returns:
            None
        """
        # TODO: Do we need this anymore?

    @staticmethod
    def expect_hang(
        ignore: list[str], signature: CrashSignature, tests: list[TestCase]
    ) -> bool:
        """Check if any test is expected to trigger a hang. If a hang is expected
        a sanity check is performed. A ConfigError is raised if a configuration
        issue is detected.

        Args:
            ignore: Failure types to ignore.
            signature: Signature to use for bucketing.
            tests: Testcases to check.

        Returns:
            True if a hang is expected otherwise False.
        """
        is_hang = any(x.hang for x in tests)
        if is_hang:
            if signature is None:
                raise ConfigError("Hangs require a signature to replay", Exit.ERROR)
            if "timeout" in ignore:
                raise ConfigError(
                    "Cannot ignore 'timeout' when detecting hangs", Exit.ERROR
                )
        return is_hang

    @staticmethod
    def lookup_tool(tests: list[TestCase]) -> str | None:
        """Lookup tool name from test cases. Find the adapter name used by the given
        test cases.

        Args:
            tests: TestCase to scan.

        Returns:
            TestCase adapter name or None.
        """
        adapter_name = {x.adapter_name for x in tests if x.adapter_name}
        if adapter_name:
            return f"grizzly-{adapter_name.pop()}"
        return None

    @staticmethod
    def report_to_filesystem(
        dst: Path, results: list[ReplayResult], tests: list[TestCase]
    ) -> None:
        """Use FilesystemReporter to write reports and testcase to disk in a
        known location.

        Args:
            dst: Location to write data.
            results: ReplayResult to output.
            tests: Testcases to output.

        Returns:
            None
        """
        others = tuple(x.report for x in results if not x.expected)
        if others:
            reporter = FilesystemReporter(dst / "other_reports", major_bucket=False)
            for report in others:
                reporter.submit(tests, report)
        expected = tuple(x.report for x in results if x.expected)
        if expected:
            reporter = FilesystemReporter(dst / "reports", major_bucket=False)
            for report in expected:
                reporter.submit(tests, report)

    @staticmethod
    def report_to_fuzzmanager(
        results: list[ReplayResult], tests: list[TestCase], tool: str
    ) -> None:
        """Use FuzzManagerReporter to send reports to a FuzzManager server.

        Args:
            results: ReplayResult to output.
            tests: Testcases to output.
            tool: Name used by FuzzManager.

        Returns:
            None
        """
        reporter = FuzzManagerReporter(tool)
        for result in results:
            # always report expected results
            # avoid reporting unexpected frequent results
            reporter.submit(tests, result.report, force=result.expected)

    def run(
        self,
        testcases: list[TestCase],
        time_limit: int,
        repeat: int = 1,
        min_results: int = 1,
        exit_early: bool = True,
        expect_hang: bool = False,
        idle_delay: int = 0,
        idle_threshold: int = 0,
        launch_attempts: int = 3,
        on_iteration_cb: Callable[[], None] | None = None,
        post_launch_delay: int = -1,
        services: WebServices | None = None,
    ) -> list[ReplayResult]:
        """Run testcase replay.

        Args:
            testcases: One or more TestCases to run.
            time_limit: Maximum time in seconds a test should take to complete.
            repeat: Maximum number of times to run the TestCase.
            min_results: Minimum number of results needed before run can be considered
                         successful.
            expect_hang: Running testcases is expected to result in a hang.
            exit_early: If True the minimum required number of iterations are performed
                        to either meet `min_results` or determine that it is not
                        possible to do so. If False `repeat` number of iterations are
                        performed.
            idle_delay: Number of seconds to wait before polling for idle.
            idle_threshold: CPU usage threshold to mark the process as idle.
            launch_attempts: Number of attempts to launch the browser.
            on_iteration_cb: Called every time a single iteration is run.
            post_launch_delay: Number of seconds to wait before continuing after the
                               browser is launched. A negative number skips redirect.
            services: WebServices instance.

        Returns:
            ReplayResults that were found running provided testcases.
        """
        assert idle_delay >= 0
        assert idle_threshold >= 0
        assert launch_attempts > 0
        assert min_results > 0
        assert repeat > 0
        assert repeat >= min_results
        assert testcases
        assert time_limit > 0 or self._harness is None
        assert self._harness is not None or len(testcases) == 1
        assert not expect_hang or self._signature is not None

        self.status = SimpleStatus.start()

        server_map = ServerMap()
        if self._harness is None:
            server_map.set_redirect("grz_start", "grz_current_test", required=False)
        else:
            assert self._harness, "harness must contain data"

            def harness_fn(_: str) -> bytes:  # pragma: no cover
                assert self._harness
                return self._harness

            server_map.set_dynamic_response(
                "grz_harness",
                harness_fn,
                mime_type="text/html",
            )
            server_map.set_redirect("grz_start", "grz_harness", required=False)

        if services:
            services.map_locations(server_map)

        # track unprocessed results
        reports: dict[str, ReplayResult] = {}
        try:
            sig_hash = Report.calc_hash(self._signature) if self._signature else None
            # an attempt has been made to set self._signature
            sig_set = self._signature is not None
            test_count = len(testcases)
            relaunch = min(self._relaunch, repeat)
            runner = Runner(
                self.server,
                self.target,
                idle_threshold=idle_threshold,
                idle_delay=idle_delay,
                relaunch=relaunch * test_count,
            )
            # perform iterations
            for _ in range(repeat):
                self.status.iteration += 1
                if on_iteration_cb is not None:
                    on_iteration_cb()
                if self.target.closed:
                    location = runner.location(
                        "/grz_start",
                        self.server.port,
                        close_after=relaunch * test_count if self._harness else None,
                        post_launch_delay=post_launch_delay,
                        scheme=self.server.scheme,
                        time_limit=time_limit if self._harness else None,
                    )
                    runner.launch(location, max_retries=launch_attempts)
                    if post_launch_delay >= 0 and not runner.startup_failure:
                        runner.post_launch(delay=post_launch_delay)
                    # TODO: avoid running test case if runner.startup_failure is True
                # run tests
                durations: list[float] = []
                run_result: RunResult | None = None
                for test_idx in range(test_count):
                    if test_count > 1:
                        LOG.info(
                            "Running test, part %d/%d (%d/%d)...",
                            test_idx + 1,
                            test_count,
                            self.status.iteration,
                            repeat,
                        )
                    else:
                        LOG.info(
                            "Running test (%d/%d)...", self.status.iteration, repeat
                        )
                    # update redirects
                    if self._harness is not None:
                        next_idx = (test_idx + 1) % test_count
                        server_map.set_redirect(
                            "grz_next_test",
                            testcases[next_idx].entry_point,
                            required=True,
                        )
                    server_map.set_redirect(
                        "grz_current_test",
                        testcases[test_idx].entry_point,
                        required=False,
                    )
                    # run testcase
                    run_result = runner.run(
                        self.ignore,
                        server_map,
                        testcases[test_idx],
                        wait_for_callback=self._harness is None,
                    )
                    durations.append(run_result.duration)
                    if run_result.status != Result.NONE or not run_result.attempted:
                        break
                assert run_result is not None
                if not run_result.attempted:
                    LOG.warning("Test case was not served")
                    if run_result.timeout:
                        LOG.warning("Browser hung? Timeout too short? System too busy?")
                    elif runner.initial:
                        # TODO: what is the best action to take in this case?
                        LOG.warning("Delayed startup failure detected")
                # process run results
                if run_result.status == Result.FOUND:
                    report: Report | None = None
                    # processing the result may take a few minutes (rr)
                    # update console to show progress
                    LOG.info("Processing result...")
                    # TODO: use self.target.create_report here
                    log_path = Path(mkdtemp(prefix="logs_", dir=grz_tmp("logs")))
                    self.target.save_logs(log_path)
                    report = Report(
                        log_path,
                        self.target.binary,
                        is_hang=run_result.timeout,
                        unstable=runner.startup_failure,
                    )
                    # set active signature
                    if not self._any_crash and not run_result.timeout and not sig_set:
                        assert not expect_hang
                        assert self._signature is None
                        LOG.debug(
                            "no signature given, using short sig '%s'",
                            report.short_signature,
                        )
                        if runner.startup_failure:
                            LOG.warning(
                                "Using signature from startup failure! "
                                "Provide a signature to avoid this."
                            )
                        self._signature = report.crash_signature
                        sig_set = True
                        if self._signature is not None:
                            assert not sig_hash, "sig_hash should only be set once"
                            sig_hash = Report.calc_hash(self._signature)
                    # look for existing buckets (signature match)
                    expected = self._any_crash or self.check_match(
                        self._signature, report, expect_hang, sig_set
                    )
                    if expected:
                        if sig_hash is not None:
                            LOG.debug("using signature hash (%s) to bucket", sig_hash)
                            bucket_hash = sig_hash
                        else:
                            bucket_hash = report.crash_hash
                        self.status.results.count(bucket_hash, report.short_signature)
                    else:
                        bucket_hash = report.crash_hash
                        self.status.ignored += 1
                    LOG.info(
                        "%s: %s (%s:%s)",
                        "Result" if expected else "Result: Different signature",
                        report.short_signature,
                        report.major[:8],
                        report.minor[:8],
                    )
                    # bucket result
                    if bucket_hash not in reports:
                        reports[bucket_hash] = ReplayResult(report, durations, expected)
                        LOG.debug("now tracking %s", bucket_hash)
                        report = None  # don't remove report
                    else:
                        reports[bucket_hash].count += 1
                        if report.unstable and not reports[bucket_hash].report.unstable:
                            LOG.debug("updating report to unstable")
                            reports[bucket_hash].report.unstable = True
                        LOG.debug("already tracking %s", bucket_hash)
                    # purge untracked report
                    if report is not None:
                        report.cleanup()
                        report = None
                elif run_result.status == Result.IGNORED:
                    self.status.ignored += 1
                    if run_result.timeout:
                        LOG.info(
                            "Result: Ignored (%d); timeout, idle: %s",
                            self.status.ignored,
                            run_result.idle,
                        )
                    else:
                        LOG.info("Result: Ignored (%d)", self.status.ignored)

                if exit_early and self.status.iteration < repeat:
                    # check if failed to meet minimum number of results
                    if (
                        repeat - self.status.iteration + self.status.results.total
                        < min_results
                    ):
                        # failed to reproduce issue
                        LOG.debug("skipping remaining attempts")
                        LOG.debug(
                            "results (%d) < minimum (%d), after %d attempts",
                            self.status.results.total,
                            min_results,
                            self.status.iteration,
                        )
                        # NOTE: this can be tricky if the harness is used because it can
                        # skip the shutdown performed in the harness and runner, if this
                        # is an issue for now use relaunch=1
                        break
                    # check if complete (minimum number of results found)
                    if self.status.results.total >= min_results:
                        assert self.status.results.total == min_results
                        assert (
                            sum(x.count for x in reports.values() if x.expected)
                            >= min_results
                        )
                        LOG.debug(
                            "results == expected (%d), after %d attempts",
                            min_results,
                            self.status.iteration,
                        )
                        break

                # TODO: should we warn about large browser logs?

            # process results
            if self._any_crash:
                # all reports should be expected when self._any_crash=True
                assert all(x.expected for x in reports.values())
                success = sum(x.count for x in reports.values()) >= min_results
                if not success:
                    LOG.debug(
                        "%d (any_crash) less than minimum %d",
                        self.status.results.total,
                        min_results,
                    )
            else:
                # there should be at most one expected bucket
                assert sum(x.expected for x in reports.values()) <= 1
                success = any(
                    x.count >= min_results for x in reports.values() if x.expected
                )
            results: list[ReplayResult] = []
            for crash_hash, result in reports.items():
                # if min_results not met (success=False) cleanup expected reports
                if not success and result.expected:
                    if not self._any_crash:
                        LOG.debug(
                            "'%s' less than minimum (%d/%d)",
                            crash_hash,
                            result.count,
                            min_results,
                        )
                    result.report.cleanup()
                    continue
                results.append(result)

            # this should only be displayed when both conditions are met:
            # 1) runner does not close target (no delay was given before shutdown)
            # 2) result has not been successfully reproduced
            if (
                self._relaunch > 1
                and not self.target.closed
                and not any(x.expected for x in results)
            ):
                LOG.info("Perhaps try with --relaunch=1")
            # active reports have been moved to results
            # clear reports to avoid cleanup of active reports
            reports.clear()
            return results

        finally:
            # we don't want to cleanup but we are not checking results
            self.target.close(force_close=True)
            # remove unprocessed reports
            for result in reports.values():
                result.report.cleanup()
