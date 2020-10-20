# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Given a build and testcase, try to reduce it using a set of strategies.
"""
from itertools import chain
from logging import getLogger
from math import ceil, log
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp

from Collector.Collector import Collector
from FTB.Signatures.CrashInfo import CrashSignature
from sapphire import Sapphire

from ..common.reporter import FilesystemReporter, FuzzManagerReporter
from ..common.storage import TestCase, TestCaseLoadFailure, TestFile
from ..common.utils import grz_tmp
from ..main import configure_logging
from ..replay import ReplayManager, ReplayResult
from ..target import load as load_target, TargetLaunchError, TargetLaunchTimeout
from .strategies import STRATEGIES


__author__ = "Jesse Schwartzentruber"
__credits__ = ["Jesse Schwartzentruber", "Tyson Smith"]


LOG = getLogger(__name__)


def change_quality(crash_id, quality):
    """Update a FuzzManager crash entry quality.

    Args:
        crash_id (int): Crash ID on FuzzManager server
        quality (int): Quality constant defined in FuzzManagerReporter.QUAL_*

    Returns:
        None
    """
    LOG.info("Updating crash %d to quality %s", crash_id, FuzzManagerReporter.quality_name(quality))
    coll = Collector()

    url = "%s://%s:%d/crashmanager/rest/crashes/%d/" \
        % (coll.serverProtocol, coll.serverHost, coll.serverPort, crash_id)
    try:
        coll.patch(url, data={"testcase_quality": quality})
    except RuntimeError as exc:
        # let 404's go .. evidently the crash was deleted
        if str(exc) == "Unexpected HTTP response: 404":
            LOG.warning("Failed to update (404), does the crash still exist?")
        else:
            raise


class ReduceManager(object):
    ANALYSIS_ITERATIONS = 11  # number of iterations to analyze
    ANALYSIS_MIN_CRASHES = 2  # --min-crashes value when analysis is used
    ANALYSIS_TARGET_PROBABILITY = 0.95  # probability that successful reduction will observe the crash
    # to see the worst case, run the `repeat` calculation in run_reliability_analysis using
    # crashes_percent = 1.0/ANALYSIS_ITERATIONS

    IDLE_DELAY_MIN = 10
    IDLE_DELAY_DURATION_MULTIPLIER = 1.5
    ITER_TIMEOUT_MIN = 10
    ITER_TIMEOUT_DURATION_MULTIPLIER = 2

    """
    Args:
        idle_delay (int): Number of seconds to wait before polling for idle.
        idle_threshold (int): CPU usage threshold to mark the process as idle.
    """

    def __init__(self, ignore, server, target, testcases, strategies, log_path, tool=None,
                 report_to_fuzzmanager=False, any_crash=False, signature=None, use_harness=True,
                 use_analysis=True, static_timeout=False, idle_delay=0, idle_threshold=0):
        self.ignore = ignore
        self.server = server
        self.strategies = strategies
        self.target = target
        self.testcases = testcases
        self._any_crash = any_crash
        # only coerce `log_path` to `Path` if it's a string
        # this caution is only necessary in python3.5 where pytest uses pathlib2 rather than pathlib
        self._log_path = Path(log_path) if isinstance(log_path, str) else log_path
        # these parameters may be overwritten during analysis, so keep a copy of them
        self._original_relaunch = target.relaunch
        self._original_use_harness = use_harness
        self._report_to_fuzzmanager = report_to_fuzzmanager
        self._report_tool = tool
        self._signature = signature
        self._use_analysis = use_analysis
        self._use_harness = use_harness
        self._static_timeout = static_timeout
        self._idle_delay = idle_delay
        self._idle_threshold = idle_threshold

    def update_timeout(self, results):
        if self._static_timeout or self._any_crash or getattr(self.target, "use_valgrind", False):
            # the amount of time it can take to replay a test case can vary
            # when under Valgrind so do not update the timeout in that case

            # when any_crash is given, crashes may be completely unrelated (all are expected), so
            # lowering timeout or idle delay will only hide crashes
            return

        durations = list(chain.from_iterable(result.durations for result in results if result.expected))
        if not durations:
            # no expected results
            return
        run_time = max(durations)

        # If `run_time * multiplier` is less than idle poll delay, update it
        LOG.debug('Run time %r', run_time)
        new_idle_delay = max(self.IDLE_DELAY_MIN, min(run_time * self.IDLE_DELAY_DURATION_MULTIPLIER,
                                                      self._idle_delay))
        if new_idle_delay < self._idle_delay:
            LOG.info("Updating poll delay to: %r", new_idle_delay)
            self._idle_delay = new_idle_delay
        # If `run_time * multiplier` is less than iter_timeout, update it
        # in other words, decrease the timeout if this ran in less than half the timeout
        new_iter_timeout = max(self.ITER_TIMEOUT_MIN, min(run_time * self.ITER_TIMEOUT_DURATION_MULTIPLIER,
                                                          self.server.timeout))
        if new_iter_timeout < self.server.timeout:
            LOG.info("Updating max timeout to: %r", new_iter_timeout)
            self.server.timeout = new_iter_timeout

    def run_reliability_analysis(self):
        harness_crashes = 0
        non_harness_crashes = 0

        # Reset parameters.
        # Use repeat=1 & relaunch=ITERATIONS because this is closer to how we will run post-analysis.
        # We're only using repeat=1 instead of repeat=ITERATIONS so we can get feedback on every
        #   call to interesting.
        self.target.relaunch = self.ANALYSIS_ITERATIONS

        for use_harness in [True, False]:
            if use_harness and not self._original_use_harness:
                continue
            if not use_harness and harness_crashes == self.ANALYSIS_ITERATIONS:
                continue

            with ReplayManager(self.ignore, self.server, self.target, any_crash=self._any_crash,
                               signature=self._signature, use_harness=use_harness) as replay:
                LOG.info("Running for %d iterations to assess reliability %s harness.",
                         self.ANALYSIS_ITERATIONS, "using" if use_harness else "without")
                for _ in range(self.ANALYSIS_ITERATIONS):
                    try:
                        results = replay.run(self.testcases, repeat=1, min_results=1,
                                             idle_delay=self._idle_delay, idle_threshold=self._idle_threshold)
                    except (TargetLaunchError, TargetLaunchTimeout) as exc:
                        if isinstance(exc, TargetLaunchError) and exc.report:
                            self.report([ReplayResult(exc.report, None, [], False)], self.testcases)
                            exc.report.cleanup()
                        raise
                    self.update_timeout(results)
                    try:
                        success = any(result.expected for result in results)
                        LOG.info("result: %s", "interesting." if success else "not interesting.")
                        self.report([result for result in results if not result.expected], self.testcases)
                    finally:
                        for result in results:
                            result.report.cleanup()
                    if success and use_harness:
                        harness_crashes += 1
                    elif success:
                        non_harness_crashes += 1
                LOG.info("Testcase was interesting %0.1f%% of %d attempts %s harness.",
                         100.0 * harness_crashes / self.ANALYSIS_ITERATIONS, self.ANALYSIS_ITERATIONS,
                         "using" if use_harness else "without")
                # ensure same signature is always used
                self._signature = replay.signature

        if harness_crashes == 0 and non_harness_crashes == 0:
            raise RuntimeError("Did not reproduce during analysis")

        # should we use the harness? go with whichever crashed more
        self._use_harness = non_harness_crashes <= harness_crashes

        # this is max 99.9% to avoid domain errors in the calculation below
        crashes_percent = min(1.0 * max(non_harness_crashes, harness_crashes) / self.ANALYSIS_ITERATIONS,
                              0.999)

        # adjust repeat/min-crashes depending on how reliable the testcase was
        min_crashes = self.ANALYSIS_MIN_CRASHES
        repeat = int(ceil(log(1 - self.ANALYSIS_TARGET_PROBABILITY, 1 - crashes_percent))
                     * self.ANALYSIS_MIN_CRASHES)

        LOG.info("Analysis results:")
        if harness_crashes == self.ANALYSIS_ITERATIONS:
            LOG.info("* testcase was perfectly reliable with the harness (--no-harness not assessed)")
        elif harness_crashes == non_harness_crashes:
            LOG.info("* testcase was equally reliable with/without the harness")
        elif not self._original_use_harness:
            LOG.info("* --no-harness was already set")
        else:
            LOG.info("* testcase was %s reliable with the harness",
                     "more" if harness_crashes > non_harness_crashes else "less")
        return (repeat, min_crashes)

    def run(self, repeat=1, min_results=1):
        """Run testcase replay.

        Args:
            repeat (int): Maximum number of times to run the TestCase.
            min_results (int): Minimum number of results needed before run can
                               be considered successful.

        Returns:
            bool: Whether a crash was observed (whether or not reduction was successful).
        """
        any_success = False
        last_reports = None
        for strategy_no, strategy in enumerate(self.strategies):
            LOG.info("Using strategy %s (%d/%d)", strategy, strategy_no + 1, len(self.strategies))
            if self._use_analysis:
                repeat, min_results = self.run_reliability_analysis()
            self.target.relaunch = min(self._original_relaunch, repeat)
            LOG.info("Repeat: %d, Minimum crashes: %d, Relaunch %d",
                     repeat, min_results, self.target.relaunch)
            replay = ReplayManager(self.ignore, self.server, self.target, any_crash=self._any_crash,
                                   signature=self._signature, use_harness=self._use_harness)
            strategy = STRATEGIES[strategy](self.testcases)
            with replay, strategy:
                best_results = []
                attempt_no = 0
                try:
                    for reduction in strategy:
                        attempt_no += 1
                        LOG.info("Attempt #%d", attempt_no)
                        keep_reduction = False
                        results = []
                        try:
                            try:
                                # reduction is a new list of testcases to be replayed
                                results = replay.run(reduction, repeat=repeat, min_results=min_results,
                                                     idle_delay=self._idle_delay,
                                                     idle_threshold=self._idle_threshold)
                            except (TargetLaunchError, TargetLaunchTimeout) as exc:
                                if isinstance(exc, TargetLaunchError) and exc.report:
                                    self.report([ReplayResult(exc.report, None, [], False)], reduction)
                                    exc.report.cleanup()
                                raise
                            self.update_timeout(results)
                            # get the first expected result (if any), and update the strategy
                            first_expected = next((report for report in results if report.expected), None)
                            success = first_expected is not None
                            served = first_expected.served if success and not self._any_crash else None
                            strategy.update(success, served=served)
                            if strategy.name == "check":
                                if any_success and not success:
                                    raise RuntimeError("Reduction broke")
                            any_success = any_success or success
                            # if the reduction reproduced, update self.testcases (new best)
                            if success:
                                LOG.info("Attempt succeeded")
                                for testcase in self.testcases:
                                    testcase.cleanup()
                                self.testcases = reduction
                                keep_reduction = True
                                # cleanup old best results
                                for result in best_results:
                                    result.report.cleanup()
                                # filter expected results out into `best_results`
                                best_results = [result for result in results if result.expected]
                                results = [result for result in results if not result.expected]
                            else:
                                LOG.info("Attempt failed")
                            # if the reduction found other crashes, report those immediately
                            self.report(results, reduction)
                        finally:  # noqa pylint: disable=bare-except
                            if not keep_reduction:
                                for testcase in reduction:
                                    testcase.cleanup()
                            for result in results:
                                result.report.cleanup()
                    last_reports = self.report(best_results, self.testcases)
                except KeyboardInterrupt:
                    if best_results:
                        last_reports = self.report(best_results, self.testcases)
                        LOG.warning("Ctrl+C detected, best reduction so far reported as %r", last_reports)
                    raise
                finally:
                    for result in best_results:
                        result.report.cleanup()
                # if self._signature was already set, this will do nothing
                # otherwise, ensure the first found signature is used throughout
                self._signature = replay.signature
        # if we complete all strategies, mark the last reported crashes as reduced
        if self._report_to_fuzzmanager and last_reports:
            for crash_id in last_reports:
                change_quality(crash_id, FuzzManagerReporter.QUAL_REDUCED_RESULT)
        return any_success

    def report(self, results, tests):
        """Report results, either to fuzzmanager or to filesystem.
        """
        ret_values = []
        for result in results:
            if self._report_to_fuzzmanager:
                reporter = FuzzManagerReporter(self._report_tool)
                if result.expected:
                    reporter.force_report = True
            else:
                report_dir = "reports" if result.expected else "other_reports"
                reporter = FilesystemReporter(
                    report_path=str(self._log_path / report_dir),
                    major_bucket=False)
            # clone the tests so we can safely call purge_optional here for each report
            # (report.served may be different for non-expected or any-crash results)
            clones = [test.clone() for test in tests]
            try:
                if result.served is not None:
                    for clone, served in zip(clones, result.served):
                        clone.purge_optional(served)
                ret_values.append(reporter.submit(clones, report=result.report))
            finally:
                for clone in clones:
                    clone.cleanup()
        return ret_values

    @classmethod
    def main(cls, args):
        configure_logging(args.log_level)
        if args.fuzzmanager:
            FuzzManagerReporter.sanity_check(args.binary)

        LOG.info("Starting Grizzly Reduce")

        if args.ignore:
            LOG.info("Ignoring: %s", ", ".join(args.ignore))
        if args.xvfb:
            LOG.info("Running with Xvfb")
        if args.valgrind:
            LOG.info("Running with Valgrind. This will be SLOW!")
        if args.rr:
            LOG.info("Running with RR")

        if args.sig:
            signature = CrashSignature.fromFile(args.sig)
        else:
            signature = None

        LOG.debug("loading the TestCases")
        try:
            testcases = TestCase.load(args.input, args.prefs is None)
            if not testcases:
                raise TestCaseLoadFailure("Failed to load TestCases")
        except TestCaseLoadFailure as exc:
            LOG.error("Error: %s", str(exc))
            return 1

        target = None
        tmp_prefs = None
        try:
            if args.no_harness:
                LOG.debug("--no-harness specified relaunch set to 1")
                args.relaunch = 1
            args.repeat = max(args.min_crashes, args.repeat)
            relaunch = min(args.relaunch, args.repeat)
            LOG.debug("initializing the Target")
            target = load_target(args.platform)(
                args.binary,
                args.extension,
                args.launch_timeout,
                args.log_limit,
                args.memory,
                relaunch,
                rr=args.rr,
                valgrind=args.valgrind,
                xvfb=args.xvfb)
            # prioritize specified prefs.js file over included file
            if args.prefs is not None:
                for testcase in testcases:
                    testcase.add_meta(TestFile.from_file(args.prefs, "prefs.js"))
                LOG.info("Using specified prefs.js")
                target.prefs = args.prefs
            else:
                for testcase in testcases:
                    prefs_tf = testcase.get_file("prefs.js")
                    if prefs_tf:
                        tmp_prefs = Path(mkdtemp(prefix="prefs_", dir=grz_tmp("replay")))
                        prefs_tf.dump(str(tmp_prefs))
                        LOG.info("Using prefs.js from testcase")
                        target.prefs = str(tmp_prefs / "prefs.js")
                        break
            if testcases[0].env_vars.get("GRZ_FORCED_CLOSE") == "0":
                LOG.debug("setting target.forced_close=False")
                target.forced_close = False

            LOG.debug("starting sapphire server")
            # launch HTTP server used to serve test cases
            with Sapphire(auto_close=1, timeout=args.timeout) as server:
                target.reverse(server.port, server.port)
                mgr = ReduceManager(
                    args.ignore,
                    server,
                    target,
                    testcases,
                    args.strategies,
                    args.logs,
                    tool=args.tool,
                    report_to_fuzzmanager=args.fuzzmanager,
                    any_crash=args.any_crash,
                    signature=signature,
                    use_harness=not args.no_harness,
                    use_analysis=not args.no_analysis,
                    static_timeout=args.static_timeout,
                    idle_delay=args.idle_delay,
                    idle_threshold=args.idle_threshold)
                success = mgr.run(repeat=args.repeat, min_results=args.min_crashes)
            return 0 if success else 1

        except (KeyboardInterrupt, TargetLaunchError, TargetLaunchTimeout):
            return 1

        finally:
            LOG.warning("Shutting down...")
            if target is not None:
                target.cleanup()
            for testcase in testcases:
                testcase.cleanup()
            if tmp_prefs is not None:
                rmtree(str(tmp_prefs), ignore_errors=True)
            LOG.info("Done.")
