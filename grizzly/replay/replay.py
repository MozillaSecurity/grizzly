# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from dataclasses import dataclass
from logging import getLogger
from pathlib import Path
from tempfile import mkdtemp
from typing import TYPE_CHECKING, Callable, cast

from FTB.Signatures.CrashInfo import CrashSignature

from sapphire import CertificateBundle, Sapphire, ServerMap

from ..common.plugins import load_plugin
from ..common.report import Report
from ..common.reporter import (
    FailedLaunchReporter,
    FilesystemReporter,
    FuzzManagerReporter,
)
from ..common.runner import Runner, RunResult
from ..common.status import SimpleStatus
from ..common.storage import TestCase, TestCaseLoadFailure
from ..common.utils import (
    HARNESS_FILE,
    ConfigError,
    Exit,
    configure_logging,
    display_time_limits,
    grz_tmp,
    package_version,
    time_limits,
)
from ..target import (
    AssetManager,
    Result,
    Target,
    TargetLaunchError,
    TargetLaunchTimeout,
)
from .args import ReplayArgs

if TYPE_CHECKING:
    from argparse import Namespace

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


@dataclass(eq=False)
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
        "ignore",
        "server",
        "status",
        "target",
        "_any_crash",
        "_harness",
        "_signature",
        "_relaunch",
        "_unpacked",
    )

    def __init__(
        self,
        ignore: set[str],
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
        return cast(bool, signature.matches(report.crash_info))

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

    @classmethod
    def load_testcases(
        cls,
        paths: list[Path],
        catalog: bool = False,
        entry_point: Path | None = None,
    ) -> tuple[list[TestCase], AssetManager | None, dict[str, str] | None]:
        """Load TestCases.

        Args:
            paths: Testcases to load.
            catalog: See TestCase.load().
            entry_point: See TestCase.load().

        Returns:
            Loaded TestCases, AssetManager and environment variables.
        """
        LOG.debug("loading the TestCases")
        tests: list[TestCase] = []
        for entry in paths:
            try:
                tests.append(
                    TestCase.load(entry, catalog=catalog, entry_point=entry_point)
                )
            except TestCaseLoadFailure as exc:  # noqa: PERF203
                LOG.warning("Failed to load: '%s' (%s)", entry, exc)
        if not tests:
            raise TestCaseLoadFailure("Failed to load TestCases")
        # load and remove assets and environment variables from test cases
        asset_mgr = None
        env_vars = None
        for test in tests:
            if asset_mgr is None and test.assets and test.assets_path:
                asset_mgr = AssetManager.load(test.assets, test.assets_path)
            if not env_vars and test.env_vars:
                env_vars = dict(test.env_vars)
            test.env_vars.clear()
            test.assets.clear()
            test.assets_path = None
        LOG.debug(
            "loaded TestCase(s): %d, assets: %r, env vars: %r",
            len(tests),
            asset_mgr is not None,
            env_vars is not None,
        )
        return tests, asset_mgr, env_vars

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
                reporter.submit(tests or [], report)
        expected = tuple(x.report for x in results if x.expected)
        if expected:
            reporter = FilesystemReporter(dst / "reports", major_bucket=False)
            for report in expected:
                reporter.submit(tests or [], report)

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
            assert isinstance(self._harness, bytes)
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
                            "no signature given, using short sig %r",
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
                            "Result: Ignored (%d); timeout, idle: %r",
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
                            "%r less than minimum (%d/%d)",
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

    @classmethod
    def main(cls, args: Namespace | None = None) -> int:
        """CLI for `grizzly.reduce`.

        Arguments:
            args: Result from `ReplayArgs.parse_args`.

        Returns:
            Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
        """
        args = args or ReplayArgs().parse_args()
        configure_logging(args.log_level)

        LOG.info("Starting Grizzly Replay")
        LOG.debug("grizzly-framework version: %s", package_version("grizzly-framework"))

        if args.headless:
            LOG.info("Running browser headless (%s)", args.headless)
        if args.ignore:
            LOG.info("Ignoring: %s", ", ".join(args.ignore))
        if args.pernosco:
            LOG.info("Running with RR (Pernosco mode)")
        elif args.rr:
            LOG.info("Running with RR")
        elif args.valgrind:
            LOG.info("Running with Valgrind. This will be SLOW!")

        signature = CrashSignature.fromFile(args.sig) if args.sig else None

        try:
            testcases, asset_mgr, env_vars = cls.load_testcases(
                args.input, entry_point=args.entry_point
            )
        except TestCaseLoadFailure as exc:
            LOG.error("Error: %s", str(exc))
            return Exit.ERROR

        if not args.tool:
            args.tool = cls.lookup_tool(testcases) or "grizzly-replay"

        certs = None
        results: list[ReplayResult] | None = None
        target: Target | None = None
        try:
            # check if hangs are expected
            expect_hang = cls.expect_hang(args.ignore, signature, testcases)
            # calculate test time limit and timeout
            time_limit, timeout = time_limits(
                args.time_limit, args.timeout, tests=testcases
            )
            display_time_limits(time_limit, timeout, args.no_harness)
            # calculate repeat and relaunch
            repeat = max(args.min_crashes, args.repeat)
            relaunch = min(args.relaunch, repeat)
            LOG.info(
                "Repeat: %d, Minimum crashes: %d, Relaunch %d",
                repeat,
                args.min_crashes,
                relaunch,
            )
            if not args.use_http:
                certs = CertificateBundle.create()
            LOG.debug("initializing the Target")
            target = load_plugin(args.platform, "grizzly_targets", Target)(
                args.binary,
                args.launch_timeout,
                args.log_limit,
                args.memory,
                certs=certs,
                headless=args.headless,
                pernosco=args.pernosco,
                rr=args.rr,
                valgrind=args.valgrind,
            )
            assert target
            if env_vars is not None:
                LOG.debug("adding environment loaded from test case")
                target.merge_environment(env_vars)

            # use asset manager created from test case content if available
            if asset_mgr:
                target.asset_mgr = asset_mgr
                # target is now responsible for `asset_mgr`
                asset_mgr = None
            # TODO: prioritize specified assets over included
            target.asset_mgr.add_batch(args.asset)
            target.process_assets()

            if certs and not target.https():
                LOG.warning("Target does not support HTTPS, using HTTP")
                certs.cleanup()
                certs = None

            LOG.debug("starting sapphire server")
            # launch HTTP server used to serve test cases
            with Sapphire(auto_close=1, timeout=timeout, certs=certs) as server:
                target.reverse(server.port, server.port)
                with cls(
                    set(args.ignore),
                    server,
                    target,
                    any_crash=args.any_crash,
                    relaunch=relaunch,
                    signature=signature,
                    use_harness=not args.no_harness,
                ) as replay:
                    results = replay.run(
                        testcases,
                        time_limit,
                        expect_hang=expect_hang,
                        idle_delay=args.idle_delay,
                        idle_threshold=args.idle_threshold,
                        launch_attempts=args.launch_attempts,
                        min_results=args.min_crashes,
                        post_launch_delay=args.post_launch_delay,
                        repeat=repeat,
                    )
            # handle results
            success = any(x.expected for x in results)
            if success:
                LOG.info("Results successfully reproduced")
            elif any(results):
                LOG.info("Results detected, signature does not match")
            else:
                LOG.info("No results detected")
            if results and (args.output or args.fuzzmanager):
                # add target assets to test cases
                if not target.asset_mgr.is_empty():
                    for test in testcases:
                        test.assets = dict(target.asset_mgr.assets)
                        test.assets_path = target.asset_mgr.path
                # add target environment variables
                if target.filtered_environ():
                    for test in testcases:
                        test.env_vars = target.filtered_environ()
                # report results
                if args.fuzzmanager:
                    cls.report_to_fuzzmanager(results, testcases, args.tool)
                else:
                    cls.report_to_filesystem(args.output, results, testcases)
            return Exit.SUCCESS if success else Exit.FAILURE

        except ConfigError as exc:
            LOG.error(str(exc))
            return exc.exit_code

        except KeyboardInterrupt:
            return Exit.ABORT

        except (TargetLaunchError, TargetLaunchTimeout) as exc:
            if isinstance(exc, TargetLaunchError) and exc.report:
                FailedLaunchReporter(args.display_launch_failures).submit(
                    [], exc.report
                )
            return Exit.LAUNCH_FAILURE

        finally:
            LOG.info("Shutting down...")
            if results:
                # cleanup unreported results
                for result in results:
                    result.report.cleanup()
            if target is not None:
                target.cleanup()
            if asset_mgr:
                asset_mgr.cleanup()
            if certs is not None:
                certs.cleanup()
            LOG.info("Done.")
