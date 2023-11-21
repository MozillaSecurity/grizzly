# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from logging import getLogger
from pathlib import Path
from tempfile import mkdtemp

from FTB.Signatures.CrashInfo import CrashSignature

from sapphire import Sapphire, ServerMap

from ..common.plugins import load as load_plugin
from ..common.reporter import (
    FailedLaunchReporter,
    FilesystemReporter,
    FuzzManagerReporter,
    Report,
)
from ..common.runner import Runner
from ..common.status import SimpleStatus
from ..common.storage import TestCase, TestCaseLoadFailure
from ..common.utils import (
    HARNESS_FILE,
    CertificateBundle,
    ConfigError,
    Exit,
    configure_logging,
    display_time_limits,
    grz_tmp,
    time_limits,
)
from ..target import (
    AssetManager,
    Result,
    Target,
    TargetLaunchError,
    TargetLaunchTimeout,
)

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class ReplayResult:
    __slots__ = ("count", "durations", "expected", "report", "served")

    def __init__(self, report, durations, expected):
        self.count = 1
        self.durations = durations
        self.expected = expected
        self.report = report


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
        ignore,
        server,
        target,
        any_crash=False,
        relaunch=1,
        signature=None,
        use_harness=True,
    ):
        # target must relaunch every iteration when not using harness
        assert use_harness or relaunch == 1
        self.ignore = ignore
        self.server = server
        self.status = None
        self.target = target
        self._any_crash = any_crash
        self._harness = HARNESS_FILE.read_bytes() if use_harness else None
        self._relaunch = relaunch
        self._signature = signature

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    @property
    def signature(self):
        return self._signature

    @staticmethod
    def check_match(signature, report, expect_hang, check_failed):
        """Check if report matches signature.

        Args:
            signature (CrashSignature): Signature to match.
            report (Report): Report to check matches signature.
            expect_hang (bool): A hang is expected.
            check_failed (bool): Check if report signature creation failed.

        Returns:
            bool: True if report matches signature otherwise False.
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
        return signature.matches(report.crash_info)

    def cleanup(self):
        """Remove temporary files from disk.

        Args:
            None

        Returns:
            None
        """
        # TODO: Do we need this anymore?

    @staticmethod
    def expect_hang(ignore, signature, tests):
        """Check if any test is expected to trigger a hang. If a hang is expected
        a sanity check is performed. A ConfigError is raised if a configuration
        issue is detected.

        Args:
            ignore (list(str)): Failure types to ignore.
            signature (CrashSignature): Signature to use for bucketing.
            tests list(TestCase): Testcases to check.

        Returns:
            bool: True if a hang is expected otherwise False.
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
    def load_testcases(cls, paths, catalog=False):
        """Load TestCases.

        Args:
            paths (list(Path)): Testcases to load.
            catalog (bool): See TestCase.load().
        Returns:
            tuple(list(TestCase), AssetManager, dict):
                Loaded TestCases, AssetManager and environment variables.
        """
        LOG.debug("loading the TestCases")
        tests = []
        for entry in paths:
            tests.append(TestCase.load(entry, catalog=catalog))
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
    def report_to_filesystem(path, results, tests=None):
        """Use FilesystemReporter to write reports and testcase to disk in a
        known location.

        Args:
            path (Path): Location to write data.
            results (iterable): ReplayResult to output.
            tests (iterable): Testcases to output.

        Returns:
            None
        """
        others = tuple(x.report for x in results if not x.expected)
        if others:
            reporter = FilesystemReporter(path / "other_reports", major_bucket=False)
            for report in others:
                reporter.submit(tests or [], report=report)
        expected = tuple(x.report for x in results if x.expected)
        if expected:
            reporter = FilesystemReporter(path / "reports", major_bucket=False)
            for result in expected:
                reporter.submit(tests or [], report=result)

    @staticmethod
    def report_to_fuzzmanager(results, tests, tool=None):
        """Use FuzzManagerReporter to send reports to a FuzzManager server.

        Args:
            results (iterable): ReplayResult to output.
            tests (iterable): Testcases to output.
            tool (str): Name used by FuzzManager.

        Returns:
            None
        """
        if not tool and tests and tests[0].adapter_name:
            tool = f"grizzly-{tests[0].adapter_name}"
        reporter = FuzzManagerReporter(tool or "grizzly-replay")
        for result in results:
            # always report expected results
            # avoid reporting unexpected frequent results
            reporter.submit(tests, result.report, force=result.expected)

    def run(
        self,
        testcases,
        time_limit,
        repeat=1,
        min_results=1,
        exit_early=True,
        expect_hang=False,
        idle_delay=0,
        idle_threshold=0,
        launch_attempts=3,
        on_iteration_cb=None,
        post_launch_delay=0,
    ):
        """Run testcase replay.

        Args:
            testcases (list(TestCase)): One or more TestCases to run.
            time_limit (int): Maximum time in seconds a test should take to complete.
            repeat (int): Maximum number of times to run the TestCase.
            min_results (int): Minimum number of results needed before run can
                               be considered successful.
            expect_hang (bool): Running testcases is expected to result in a hang.
            exit_early (bool): If True the minimum required number of iterations
                               are performed to either meet `min_results` or
                               determine that it is not possible to do so.
                               If False `repeat` number of iterations are
                               performed.
            idle_delay (int): Number of seconds to wait before polling for idle.
            idle_threshold (int): CPU usage threshold to mark the process as idle.
            launch_attempts (int): Number of attempts to launch the browser.
            on_iteration_cb (callable): Called every time a single iteration is run.
            post_launch_delay (int): Time in seconds before continuing after the
                                     browser is launched.

        Returns:
            list: ReplayResults that were found running testcases.
        """
        assert idle_delay >= 0
        assert idle_threshold >= 0
        assert launch_attempts > 0
        assert min_results > 0
        assert repeat > 0
        assert repeat >= min_results
        assert testcases
        assert time_limit > 0 or self._harness is None
        assert self._harness or self._harness is None
        assert self._harness is not None or len(testcases) == 1
        assert not expect_hang or self._signature is not None

        self.status = SimpleStatus.start()

        server_map = ServerMap()
        if self._harness is None:
            server_map.set_redirect("grz_start", "grz_current_test", required=False)
        else:
            server_map.set_dynamic_response(
                "grz_harness", lambda _: self._harness, mime_type="text/html"
            )
            server_map.set_redirect("grz_start", "grz_harness", required=False)

        # track unprocessed results
        reports = {}
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
                    runner.post_launch(delay=post_launch_delay)
                    # TODO: avoid running test case if runner.startup_failure is True
                # run tests
                durations = []
                run_result = None
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
                    if runner.initial:
                        if run_result.status == Result.FOUND:
                            # TODO: what is the best action to take in this case?
                            LOG.warning("Delayed startup failure detected")
                        else:
                            LOG.warning("Timeout too short? System too busy?")
                # process run results
                if run_result.status == Result.FOUND:
                    # processing the result may take a few minutes (rr)
                    # update console to show progress
                    LOG.info("Processing result...")
                    # TODO: use self.target.create_report here
                    log_path = Path(mkdtemp(prefix="logs_", dir=grz_tmp("logs")))
                    self.target.save_logs(log_path)
                    report = Report(
                        log_path, self.target.binary, is_hang=run_result.timeout
                    )
                    # check signatures
                    if run_result.timeout:
                        short_sig = "Potential hang detected"
                    elif report.crash_signature is not None:
                        short_sig = report.crash_info.createShortSignature()
                    else:
                        # FM crash signature creation failed
                        short_sig = "Signature creation failed"

                    # set active signature
                    if (
                        not runner.startup_failure
                        and not self._any_crash
                        and not run_result.timeout
                        and not sig_set
                    ):
                        assert not expect_hang
                        assert self._signature is None
                        LOG.debug("no signature given, using short sig %r", short_sig)
                        self._signature = report.crash_signature
                        sig_set = True
                        if self._signature is not None:
                            assert not sig_hash, "sig_hash should only be set once"
                            sig_hash = Report.calc_hash(self._signature)

                    # bucket result
                    if not runner.startup_failure and (
                        self._any_crash
                        or self.check_match(
                            self._signature, report, expect_hang, sig_set
                        )
                    ):
                        if sig_hash is not None:
                            LOG.debug("using signature hash (%s) to bucket", sig_hash)
                            bucket_hash = sig_hash
                        else:
                            bucket_hash = report.crash_hash
                        self.status.results.count(bucket_hash, short_sig)
                        LOG.info(
                            "Result: %s (%s:%s)",
                            short_sig,
                            report.major[:8],
                            report.minor[:8],
                        )
                        if bucket_hash not in reports:
                            reports[bucket_hash] = ReplayResult(report, durations, True)
                            LOG.debug("now tracking %s", bucket_hash)
                            report = None  # don't remove report
                        else:
                            reports[bucket_hash].count += 1
                            LOG.debug("already tracking %s", bucket_hash)
                    else:
                        LOG.info(
                            "Result: Different signature: %s (%s:%s)",
                            short_sig,
                            report.major[:8],
                            report.minor[:8],
                        )
                        self.status.ignored += 1
                        if report.crash_hash not in reports:
                            reports[report.crash_hash] = ReplayResult(
                                report, durations, False
                            )
                            LOG.debug("now tracking %s", report.crash_hash)
                            report = None  # don't remove report
                        else:
                            reports[report.crash_hash].count += 1
                            LOG.debug("already tracking %s", report.crash_hash)
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
                # add all results if min_results was reached
                if sum(x.count for x in reports.values() if x.expected) >= min_results:
                    results = list(reports.values())
                else:
                    # add only unexpected results since min_results was not reached
                    results = []
                    for report in reports.values():
                        if report.expected:
                            report.report.cleanup()
                        else:
                            results.append(report)
                    LOG.debug(
                        "%d (any_crash) less than minimum %d",
                        self.status.results.total,
                        min_results,
                    )
            else:
                # there should be at most one expected bucket
                assert sum(x.expected for x in reports.values()) <= 1
                # filter out unreliable expected results
                results = []
                for crash_hash, report in reports.items():
                    if report.expected and report.count < min_results:
                        LOG.debug(
                            "%r less than minimum (%d/%d)",
                            crash_hash,
                            report.count,
                            min_results,
                        )
                        report.report.cleanup()
                        continue
                    results.append(report)
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
            # we don't want to clean up but we are not checking results
            self.target.close(force_close=True)
            # remove unprocessed reports
            for report in reports.values():
                report.report.cleanup()

    @classmethod
    def main(cls, args):
        configure_logging(args.log_level)
        LOG.info("Starting Grizzly Replay")

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
            testcases, asset_mgr, env_vars = cls.load_testcases(args.input)
        except TestCaseLoadFailure as exc:
            LOG.error("Error: %s", str(exc))
            return Exit.ERROR

        certs = None
        results = None
        target = None
        try:
            if args.no_harness and len(testcases) > 1:
                # TODO: move this check to arg parsing
                LOG.error(
                    "'--no-harness' cannot be used with multiple testcases. "
                    "Perhaps '--test-index' can help."
                )
                return Exit.ARGS
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
                    args.ignore,
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
            if results and (args.logs or args.fuzzmanager):
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
                    cls.report_to_fuzzmanager(results, testcases, tool=args.tool)
                else:
                    cls.report_to_filesystem(
                        args.logs, results, testcases if args.include_test else None
                    )
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
            for testcase in testcases:
                testcase.cleanup()
            if asset_mgr:
                asset_mgr.cleanup()
            if certs is not None:
                certs.cleanup()
            LOG.info("Done.")
