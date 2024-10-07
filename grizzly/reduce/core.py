# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""`ReduceManager` finds the smallest testcase(s) to reproduce an issue."""
from __future__ import annotations

import json
import os
from itertools import chain
from locale import LC_ALL, setlocale
from logging import getLogger
from math import ceil, log
from pathlib import Path
from time import time
from typing import TYPE_CHECKING

from FTB.Signatures.CrashInfo import CrashSignature

from sapphire import CertificateBundle, Sapphire

from ..common.fuzzmanager import CrashEntry
from ..common.plugins import load_plugin
from ..common.reporter import (
    FailedLaunchReporter,
    FilesystemReporter,
    FuzzManagerReporter,
    Quality,
    Reporter,
)
from ..common.status import STATUS_DB_REDUCE, ReductionStatus
from ..common.status_reporter import ReductionStatusReporter
from ..common.storage import TestCase, TestCaseLoadFailure
from ..common.utils import (
    ConfigError,
    Exit,
    configure_logging,
    package_version,
    time_limits,
)
from ..replay import ReplayManager, ReplayResult
from ..target import AssetManager, Target, TargetLaunchError, TargetLaunchTimeout
from .args import ReduceArgs
from .exceptions import GrizzlyReduceBaseException, NotReproducible
from .strategies import STRATEGIES

if TYPE_CHECKING:
    from argparse import Namespace

__author__ = "Jesse Schwartzentruber"
__credits__ = ["Jesse Schwartzentruber", "Tyson Smith"]


LOG = getLogger(__name__)


class ReduceManager:
    """Manage reduction of one or more testcases to find the smallest testcase
    that reproduces a given issue.

    Attributes:
        ignore: Classes of results to ignore (see `--ignore`).
        server: Server instance to serve testcases.
        strategies: List of strategies to use for reducing testcases (in order).
        target: Target instance to run testcases.
        testcases: List of one or more Grizzly testcases to reduce.
    """

    ANALYSIS_ITERATIONS = 11  # number of iterations to analyze
    # --min-crashes value when analysis is used and reliability is less than perfect
    ANALYSIS_MIN_CRASHES = 1
    ANALYSIS_PERFECT_MIN_CRASHES = 1  # --min-crashes when reliability is perfect
    # probability that successful reduction will observe the crash
    ANALYSIS_TARGET_PROBABILITY = 0.95
    # to see the worst case, run the `repeat` calculation in run_reliability_analysis
    # using `crashes_percent = 1.0/ANALYSIS_ITERATIONS`

    IDLE_DELAY_MIN = 10
    IDLE_DELAY_DURATION_MULTIPLIER = 1.5
    ITER_TIMEOUT_MIN = 10
    ITER_TIMEOUT_DURATION_MULTIPLIER = 2

    def __init__(
        self,
        ignore: set[str],
        server: Sapphire,
        target: Target,
        testcases: list[TestCase],
        strategies: list[str],
        log_path: Path,
        any_crash: bool = False,
        expect_hang: bool = False,
        idle_delay: int = 0,
        idle_threshold: int = 0,
        reducer_crash_id: int | None = None,
        relaunch: int = 1,
        report_period: int | None = None,
        report_to_fuzzmanager: bool = False,
        signature: CrashSignature | None = None,
        signature_desc: str | None = None,
        static_timeout: bool = False,
        tool: str | None = None,
        use_analysis: bool = True,
        use_harness: bool = True,
    ):
        """Initialize reduction manager. Many arguments are common with `ReplayManager`.

        Args:
            ignore: Value for `self.ignore` attribute.
            server: Value for `self.server` attribute.
            target: Value for `self.target` attribute.
            testcases: Value for `self.testcases` attribute.
            strategies: Value for `self.strategies` attribute.
            log_path: Path to save results when reporting to filesystem.
            any_crash: Accept any crash when reducing, not just those matching
                       the specified or first observed signature.
            expect_hang: Attempt to reduce a test that triggers a hang.
            idle_delay: Number of seconds to wait before polling for idle.
            idle_threshold: CPU usage threshold to mark the process as idle.
            relaunch: Maximum number of iterations performed by Runner before
                      Target should be relaunched.
            report_period: Periodically report best results for long-running strategies.
            report_to_fuzzmanager: Report to FuzzManager rather than filesystem.
            signature: Signature for accepting crashes.
            signature_desc: Short description of the given signature.
            static_timeout: Use only specified timeouts (`--timeout` and
                            `--idle-delay`), even if testcase appears to need less time.
            tool: Override tool when reporting to FuzzManager.
            use_analysis: Analyse reliability of testcase before running each
                          reduction strategy.
            use_harness: Whether to allow use of harness when navigating
                         between testcases.
        """
        self.ignore = ignore
        self.server = server
        self.strategies = strategies
        self.target = target
        self.testcases = testcases
        self._any_crash = any_crash
        self._expect_hang = expect_hang
        self._idle_delay = idle_delay
        self._idle_threshold = idle_threshold
        self._log_path = log_path
        # these parameters may be overwritten during analysis, so keep a copy of them
        self._original_relaunch = relaunch
        self._original_use_harness = use_harness
        self._report_to_fuzzmanager = report_to_fuzzmanager
        self._report_periodically = report_period
        self._report_tool = tool or "grizzly-reducer"
        self._signature = signature
        self._signature_desc = signature_desc
        self._static_timeout = expect_hang or static_timeout
        self._status = ReductionStatus.start(
            STATUS_DB_REDUCE,
            strategies=strategies,
            testcase_size_cb=self.testcase_size,
            crash_id=reducer_crash_id,
            tool=tool,
        )
        self._use_analysis = use_analysis
        self._use_harness = use_harness

    def __enter__(self) -> ReduceManager:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        """Remove temporary files from disk.

        Args:
            None

        Returns:
            None
        """
        for test in self.testcases:
            test.cleanup()

    def update_timeout(self, results: list[ReplayResult]) -> None:
        """Tune idle/server timeout values based on actual duration of expected results.

        Expected durations will be updated if the actual duration is much lower.

        Timeouts are not updated in three cases:

            - `static_timeout=True` is passed to constructor (`--static-timeout`),
            - `any_crash=True` is passed to constructor (`--any-crash`),
            - Target is running under valgrind (`--valgrind`).

        Arguments:
            results: Observed results. Any given expected results may affect the idle
                     delay and sapphire timeout.

        Returns:
            None
        """
        # TODO: properly handle test duration and timeout
        assert self._static_timeout or not self._expect_hang
        if (
            self._static_timeout
            or self._any_crash
            or getattr(self.target, "use_valgrind", False)
        ):
            # the amount of time it can take to replay a test case can vary
            # when under Valgrind so do not update the timeout in that case

            # when any_crash is given, crashes may be completely unrelated (all are
            # expected), so lowering timeout or idle delay will only hide crashes
            return

        durations = list(
            chain.from_iterable(x.durations for x in results if x.expected)
        )
        if not durations:
            # no expected results
            return
        run_time = max(durations)

        # If `run_time * multiplier` is less than idle poll delay, update it
        LOG.debug("Run time %r", run_time)
        new_idle_delay = max(
            self.IDLE_DELAY_MIN,
            min(
                round(run_time * self.IDLE_DELAY_DURATION_MULTIPLIER), self._idle_delay
            ),
        )
        if new_idle_delay < self._idle_delay:
            LOG.info("Updating poll delay to: %r", new_idle_delay)
            self._idle_delay = new_idle_delay
        # If `run_time * multiplier` is less than iter_timeout, update it
        # in other words, decrease the timeout if this ran in less than half the timeout
        new_iter_timeout = max(
            self.ITER_TIMEOUT_MIN,
            min(
                round(run_time * self.ITER_TIMEOUT_DURATION_MULTIPLIER),
                self.server.timeout,
            ),
        )
        if new_iter_timeout < self.server.timeout:
            LOG.info("Updating max timeout to: %r", new_iter_timeout)
            self.server.timeout = new_iter_timeout

    def _on_replay_iteration(self) -> None:
        self._status.iterations += 1
        self._status.report()

    def run_reliability_analysis(self) -> tuple[int, int]:
        """Run several analysis passes of the current testcase to find `run` parameters.

        The number of repetitions and minimum number of crashes are calculated to
        maximize the chances of observing the expected crash.

        Arguments:
            None

        Returns:
            Values for `repeat` and `min_crashes` resulting from analysis.
        """
        self._status.report(force=True)
        harness_best = 0
        harness_last_crashes = 0
        harness_crashes = 0
        non_harness_crashes = 0

        # Reset parameters.
        # Use repeat=1 & relaunch=ITERATIONS because this is closer to how we will run
        #   post-analysis.
        # We're only using repeat=1 instead of repeat=ITERATIONS so we can get feedback
        #   on every call to interesting.

        # N.B. We only use `last_test_only` if `len(self.testcases) > 1` ..
        # if `self.testcases` only has 1 entry to begin with, we don't need
        # `last_test_only` to trim it
        for use_harness, last_test_only, relaunch in (
            # don't relaunch between iterations (be quick)
            (True, True, self.ANALYSIS_ITERATIONS),
            # relaunch between iterations regardless of testcase count (be thorough)
            (True, False, 1),
            # without the harness we only try the last testcase
            # relaunch between iterations is implied
            (False, True, 1),
        ):
            harness_best = max(harness_crashes, harness_last_crashes)
            if use_harness and (
                not self._original_use_harness
                or harness_last_crashes >= self.ANALYSIS_ITERATIONS / 2
            ):
                # Don't test with harness again if we already found enough crashes with
                # the harness (last_test_only) or if it was disabled by command-line.
                continue
            if not use_harness and harness_best >= self.ANALYSIS_ITERATIONS / 2:
                # Don't test without harness if harness found > 50% crashes
                continue

            with ReplayManager(
                self.ignore,
                self.server,
                self.target,
                any_crash=self._any_crash,
                relaunch=relaunch,
                signature=self._signature,
                use_harness=use_harness,
            ) as replay:
                LOG.info(
                    "Running for %d iterations to assess reliability %s harness.",
                    self.ANALYSIS_ITERATIONS,
                    "using" if use_harness else "without",
                )
                testcases = self.testcases
                if last_test_only and len(testcases) > 1:
                    if use_harness:
                        LOG.warning("Checking reliability with only the last testcase.")
                    else:
                        LOG.warning(
                            "Only the last testcase of %d given will be used to "
                            "assess reliability without harness.",
                            len(testcases),
                        )
                    testcases = [testcases[-1]]
                results = replay.run(
                    testcases,
                    self.server.timeout,
                    repeat=self.ANALYSIS_ITERATIONS,
                    min_results=1,
                    exit_early=False,
                    idle_delay=self._idle_delay,
                    idle_threshold=self._idle_threshold,
                    on_iteration_cb=self._on_replay_iteration,
                )
                try:
                    crashes = sum(x.count for x in results if x.expected)
                    if crashes and not self._any_crash and self._signature_desc is None:
                        first_expected = next((x for x in results if x.expected), None)
                        assert first_expected
                        self._signature_desc = first_expected.report.short_signature
                    self.report([x for x in results if not x.expected], testcases)
                    if use_harness:
                        if last_test_only:
                            harness_last_crashes = crashes
                        else:
                            harness_crashes = crashes
                    else:
                        non_harness_crashes = crashes
                finally:
                    for result in results:
                        result.report.cleanup()
                reliability = crashes / self.ANALYSIS_ITERATIONS
                desc = ("using" if use_harness else "without") + " harness"
                if last_test_only:
                    desc += "/last test only"
                else:
                    desc += "/all tests"
                LOG.info(
                    "Testcase was interesting %0.1f%% of %d attempts %s.",
                    100.0 * reliability,
                    self.ANALYSIS_ITERATIONS,
                    desc,
                )
                if use_harness and last_test_only:
                    key = "last test"
                elif use_harness:
                    key = "all tests"
                else:
                    key = "no harness"
                self._status.analysis[key] = reliability
                # ensure same signature is always used
                self._signature = replay.signature

        if not (harness_last_crashes or harness_crashes or non_harness_crashes):
            raise NotReproducible("Did not reproduce during analysis")

        # should we use the harness? go with harness unless no-harness crashed 50% more
        self._use_harness = not (
            non_harness_crashes > harness_best
            and (
                harness_best == 0
                or (non_harness_crashes - harness_best) / harness_best >= 0.5
            )
        )

        if len(self.testcases) > 1 and (
            not self._use_harness or harness_last_crashes >= harness_crashes
        ):
            LOG.warning(
                "Last testcase %s harness was selected, other %d "
                "testcases in the original will be ignored.",
                "with" if self._use_harness else "without",
                len(self.testcases) - 1,
            )
            while len(self.testcases) > 1:
                self.testcases.pop(0).cleanup()

        crashes_percent = (
            harness_best if self._use_harness else non_harness_crashes
        ) / self.ANALYSIS_ITERATIONS

        # adjust repeat/min-crashes depending on how reliable the testcase was
        if abs(crashes_percent - 1) < 0.01:
            min_crashes = self.ANALYSIS_PERFECT_MIN_CRASHES
        else:
            min_crashes = self.ANALYSIS_MIN_CRASHES
        # crashes_percent is max 99.9% to avoid domain errors
        repeat = int(
            ceil(
                log(
                    1 - self.ANALYSIS_TARGET_PROBABILITY,
                    1 - min(crashes_percent, 0.9999),
                )
            )
            * min_crashes
        )

        LOG.info("Analysis results:")
        if harness_best >= self.ANALYSIS_ITERATIONS / 2:
            LOG.info(
                "* testcase was better than 50% reliable with the harness "
                "(--no-harness not assessed)"
            )
        elif harness_best == non_harness_crashes:
            LOG.info("* testcase was equally reliable with/without the harness")
        elif not self._original_use_harness:
            LOG.info("* --no-harness was already set")
        else:
            LOG.info(
                "* testcase was %s reliable with the harness",
                "more" if harness_best > non_harness_crashes else "less",
            )
        return (repeat, min_crashes)

    def testcase_size(self) -> int:
        """Calculate the current testcase size.

        Returns:
            Current size of the testcase(s).
        """
        return sum(tc.data_size for tc in self.testcases)

    def run(
        self,
        repeat: int = 1,
        launch_attempts: int = 3,
        min_results: int = 1,
        post_launch_delay: int = 0,
    ) -> Exit:
        """Run testcase reduction.

        Args:
            repeat: Maximum number of times to run the TestCase.
            launch_attempts: Number of attempts to launch the browser.
            min_results: Minimum number of results needed before run can be considered
                         successful.
            post_launch_delay: Time in seconds before continuing after the browser
                               is launched.

        Returns:
            One of the Exit enum values.
        """
        any_success = False
        sig_given = self._signature is not None
        last_tried = None
        self._status.record("init")
        # record total stats overall so that any time missed by individual milestones
        # will still be included in the total
        with self._status.measure("final"):
            if self._use_analysis:
                with self._status.measure("analysis"):
                    (repeat, min_results) = self.run_reliability_analysis()
                any_success = True  # analysis ran and didn't raise
            # multi part test cases should always use relaunch == 1
            # since that can mean a delay is required
            if self._use_harness and len(self.testcases) == 1:
                relaunch = min(self._original_relaunch, repeat)
            else:
                relaunch = 1
            LOG.info(
                "Repeat: %d, Minimum crashes: %d, Relaunch %d",
                repeat,
                min_results,
                relaunch,
            )
            self._status.run_params["harness"] = self._use_harness
            self._status.run_params["min crashes"] = min_results
            self._status.run_params["relaunch"] = relaunch
            self._status.run_params["repeat"] = repeat

            for strategy_no, strategy_name in enumerate(self.strategies, start=1):
                self._status.current_strategy_idx = strategy_no
                LOG.info("")
                LOG.info(
                    "Using strategy %s (%d/%d)",
                    strategy_name,
                    strategy_no,
                    len(self.strategies),
                )
                replay = ReplayManager(
                    self.ignore,
                    self.server,
                    self.target,
                    any_crash=self._any_crash,
                    relaunch=relaunch,
                    signature=self._signature,
                    use_harness=self._use_harness,
                )
                strategy = STRATEGIES[strategy_name](self.testcases)
                if last_tried is not None:
                    strategy.update_tried(last_tried)
                    last_tried = None

                strategy_last_report = time()
                strategy_stats = self._status.measure(strategy.name)
                best_results: list[ReplayResult] = []
                other_results: dict[str, tuple[ReplayResult, list[TestCase]]] = {}
                try:
                    with replay, strategy, strategy_stats:
                        self._status.report(force=True)
                        for reduction in strategy:
                            keep_reduction = False
                            results: list[ReplayResult] = []
                            try:
                                # reduction is a new list of testcases to be replayed
                                results = replay.run(
                                    reduction,
                                    self.server.timeout,
                                    expect_hang=self._expect_hang,
                                    idle_delay=self._idle_delay,
                                    idle_threshold=self._idle_threshold,
                                    launch_attempts=launch_attempts,
                                    min_results=min_results,
                                    repeat=repeat,
                                    on_iteration_cb=self._on_replay_iteration,
                                    post_launch_delay=post_launch_delay,
                                )
                                self._status.attempts += 1
                                self.update_timeout(results)
                                # get the first expected result (if any),
                                #   and update the strategy
                                first_expected = next(
                                    (x for x in results if x.expected),
                                    None,
                                )
                                success = first_expected is not None
                                if success:
                                    self._status.successes += 1
                                    if (
                                        not self._any_crash
                                        and self._signature_desc is None
                                    ):
                                        assert first_expected is not None  # mypy bug
                                        sig = first_expected.report.short_signature
                                        self._signature_desc = sig
                                self._status.report()
                                strategy.update(success)
                                if strategy.name == "check" and not success:
                                    raise NotReproducible("Not reproducible at 'check'")
                                any_success = any_success or success
                                # if the reduction reproduced,
                                #   update self.testcases (new best)
                                if success:
                                    LOG.info("Reduction succeeded")
                                    for testcase in self.testcases:
                                        testcase.cleanup()
                                    # add target assets to test cases
                                    if not self.target.asset_mgr.is_empty():
                                        for test in reduction:
                                            test.assets = dict(
                                                self.target.asset_mgr.assets
                                            )
                                            test.assets_path = (
                                                self.target.asset_mgr.path
                                            )
                                    # add target environment variables
                                    if self.target.filtered_environ():
                                        for test in reduction:
                                            test.env_vars = (
                                                self.target.filtered_environ()
                                            )
                                    # clone results from strategy local copy
                                    self.testcases = [x.clone() for x in reduction]
                                    keep_reduction = True
                                    # cleanup old best results
                                    for result in best_results:
                                        result.report.cleanup()
                                    # filter expected results out into `best_results`
                                    best_results = [x for x in results if x.expected]
                                    results = [x for x in results if not x.expected]
                                else:
                                    LOG.info("Attempt failed")

                                # if the reduction found other crashes,
                                # save those for reporting later

                                # only save the smallest testcase that has found
                                # each result
                                for result in results:
                                    other_result_exists = (
                                        result.report.minor in other_results
                                    )

                                    is_smaller = False
                                    if other_result_exists:
                                        # we have a result already queued for this sig
                                        # check size to see which to keep
                                        reduction_size = sum(
                                            tc.data_size for tc in reduction
                                        )
                                        _, old_reduction = other_results[
                                            result.report.minor
                                        ]
                                        old_size = sum(
                                            tc.data_size for tc in old_reduction
                                        )
                                        is_smaller = reduction_size < old_size

                                    if not other_result_exists or is_smaller:
                                        if other_result_exists:
                                            # clean-up old result
                                            old_result, old_reduction = other_results[
                                                result.report.minor
                                            ]
                                            old_result.report.cleanup()
                                            for testcase in old_reduction:
                                                testcase.cleanup()
                                        # store this reduction for later reporting
                                        # as the other result
                                        other_results[result.report.minor] = (
                                            result,
                                            [x.clone() for x in reduction],
                                        )

                                now = time()
                                if (
                                    self._report_periodically
                                    and best_results
                                    and now - strategy_last_report
                                    > self._report_periodically
                                ):
                                    self.report(
                                        best_results,
                                        self.testcases,
                                        update_status=True,
                                    )
                                    for result in best_results:
                                        result.report.cleanup()
                                    best_results = []
                                    strategy_last_report = now
                                    LOG.info("Best results reported (periodic)")

                            finally:
                                # TODO: TS: I'm not sure this is required anymore
                                # reduction should only contain strategy local copies
                                if not keep_reduction:
                                    for testcase in reduction:
                                        testcase.cleanup()

                        # if self._signature was already set, this will do nothing
                        # otherwise, ensure the first found signature is used throughout
                        self._signature = replay.signature

                    if best_results:
                        self.report(best_results, self.testcases, update_status=True)
                    for result, reduction in other_results.values():
                        self.report([result], reduction)

                except KeyboardInterrupt:
                    if best_results:
                        self.report(best_results, self.testcases, update_status=True)
                        LOG.warning(
                            "Ctrl+C detected, best reduction so far reported as %r",
                            self._status.last_reports,
                        )
                    raise
                finally:
                    for result in best_results:
                        result.report.cleanup()
                    for result, reduction in other_results.values():
                        result.report.cleanup()
                        for testcase in reduction:
                            testcase.cleanup()

                # store "tried" cache to pass to next strategy
                last_tried = strategy.get_tried()

            # if we complete all strategies, mark the last reported crashes as reduced
            if self._report_to_fuzzmanager and self._status.last_reports:
                for crash_id in self._status.last_reports:
                    LOG.info(
                        "Updating crash %s to %s (Q%d)",
                        crash_id,
                        Quality.REDUCED.name,
                        Quality.REDUCED,
                    )
                    CrashEntry(int(crash_id)).testcase_quality = Quality.REDUCED.value

        # it's possible we made it this far without ever setting signature_desc.
        # this is only possible if --no-analysis is given
        # just give None instead of trying to format the CrashSignature
        self._status.signature_info["any"] = self._any_crash
        self._status.signature_info["description"] = str(self._signature_desc)
        self._status.signature_info["given"] = sig_given

        # log a summary of what was done.
        LOG.info(
            "Reduction summary:%s%s",
            os.linesep,
            ReductionStatusReporter([self._status]).summary(),
        )
        self._status.report(force=True)

        if any_success:
            return Exit.SUCCESS
        return Exit.FAILURE

    def report(
        self,
        results: list[ReplayResult],
        testcases: list[TestCase],
        update_status: bool = False,
    ) -> None:
        """Report results, either to FuzzManager or to filesystem.

        Arguments:
            results: Results observed during reduction.
            testcases: Testcases used to trigger results.
            update_status: Whether to update status "Latest Reports"
        """
        reporter: Reporter
        new_reports: list[str] = []
        status = self._status.copy()  # copy implicitly closes open counters
        for result in results:
            # write reduction stats for expected results
            if result.expected:
                (Path(result.report.path) / "reduce_stats.txt").write_text(
                    ReductionStatusReporter([status]).summary()
                )
            if self._report_to_fuzzmanager:
                reporter = FuzzManagerReporter(self._report_tool)
                status.add_to_reporter(reporter, expected=result.expected)
            else:
                report_dir = "reports" if result.expected else "other_reports"
                reporter = FilesystemReporter(
                    self._log_path / report_dir, major_bucket=False
                )
            submitted = reporter.submit(testcases, result.report, force=result.expected)
            if submitted is not None:
                if self._report_to_fuzzmanager:
                    new_reports.append(str(submitted))
                else:
                    new_reports.append(str(submitted.resolve()))
        # only write new reports if not empty, otherwise previous reports may be
        # overwritten with an empty list if later reports are ignored
        if update_status and new_reports:
            self._status.last_reports = new_reports

    @classmethod
    def main(cls, args: Namespace | None = None) -> int:
        """CLI for `grizzly.reduce`.

        Arguments:
            args: Result from `ReduceArgs.parse_args`.

        Returns:
            Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
        """
        # pylint: disable=too-many-return-statements
        args = args or ReduceArgs().parse_args()
        configure_logging(args.log_level)
        setlocale(LC_ALL, "")

        LOG.info("Starting Grizzly Reduce")
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

        asset_mgr: AssetManager | None = None
        certs = None
        signature = None
        signature_desc = None
        target: Target | None = None
        testcases: list[TestCase] = []

        try:
            try:
                testcases, asset_mgr, env_vars = ReplayManager.load_testcases(
                    args.input, catalog=True
                )
            except TestCaseLoadFailure as exc:
                LOG.error("Error: %s", str(exc))
                return Exit.ERROR

            if args.sig:
                signature = CrashSignature.fromFile(args.sig)
                meta = args.sig.with_suffix(".metadata")
                if meta.is_file():
                    meta = json.loads(meta.read_text())
                    signature_desc = meta["shortDescription"]

            if not args.tool:
                args.tool = ReplayManager.lookup_tool(testcases) or "grizzly-reduce"
                LOG.info("Setting default --tool=%s", args.tool)

            expect_hang = ReplayManager.expect_hang(args.ignore, signature, testcases)

            # check test time limit and timeout
            # TODO: add support for test time limit, use timeout in both cases for now
            _, timeout = time_limits(args.timeout, args.timeout, tests=testcases)
            args.repeat = max(args.min_crashes, args.repeat)
            relaunch = min(args.relaunch, args.repeat)

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
            # prioritize specified assets over included
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
                with ReduceManager(
                    set(args.ignore),
                    server,
                    target,
                    testcases,
                    args.strategies,
                    args.output,
                    any_crash=args.any_crash,
                    expect_hang=expect_hang,
                    idle_delay=args.idle_delay,
                    idle_threshold=args.idle_threshold,
                    reducer_crash_id=args.original_crash_id,
                    relaunch=relaunch,
                    report_period=args.report_period,
                    report_to_fuzzmanager=args.fuzzmanager,
                    signature=signature,
                    signature_desc=signature_desc,
                    static_timeout=args.static_timeout,
                    tool=args.tool,
                    use_analysis=not args.no_analysis,
                    use_harness=not args.no_harness,
                ) as mgr:
                    return_code = mgr.run(
                        repeat=args.repeat,
                        launch_attempts=args.launch_attempts,
                        min_results=args.min_crashes,
                        post_launch_delay=args.post_launch_delay,
                    )
            return return_code

        except ConfigError as exc:
            LOG.error(str(exc))
            return exc.exit_code

        except KeyboardInterrupt as exc:
            LOG.error("Exception: %r", exc)
            return Exit.ABORT

        except (TargetLaunchError, TargetLaunchTimeout) as exc:
            if isinstance(exc, TargetLaunchError) and exc.report:
                FailedLaunchReporter(args.display_launch_failures).submit(
                    [], exc.report
                )
            return Exit.LAUNCH_FAILURE

        except GrizzlyReduceBaseException as exc:
            LOG.error(exc.msg)
            return exc.code

        except Exception:  # pylint: disable=broad-except
            LOG.exception("Exception during reduction!")
            return Exit.ERROR

        finally:
            LOG.info("Shutting down...")
            if target is not None:
                target.cleanup()
            for testcase in testcases:
                testcase.cleanup()
            if asset_mgr:
                asset_mgr.cleanup()
            if certs is not None:
                certs.cleanup()
            LOG.info("Done.")
