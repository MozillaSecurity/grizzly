# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from logging import getLogger
from os.path import dirname, join as pathjoin
from tempfile import mkdtemp
from time import sleep
from shutil import rmtree

from FTB.Signatures.CrashInfo import CrashSignature
from sapphire import Sapphire, ServerMap

from ..common.reporter import FilesystemReporter, FuzzManagerReporter, Report
from ..common.runner import Runner, RunResult
from ..common.status import Status
from ..common.storage import TestCase, TestCaseLoadFailure, TestFile
from ..common.utils import grz_tmp
from ..main import configure_logging
from ..target import load as load_target, TargetLaunchError, TargetLaunchTimeout

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class ReplayResult(object):
    __slots__ = ("count", "durations", "expected", "report", "served")

    def __init__(self, report, served, durations, expected):
        self.count = 1
        self.durations = durations
        self.expected = expected
        self.report = report
        self.served = served


class ReplayManager(object):
    HARNESS_FILE = pathjoin(dirname(__file__), "..", "common", "harness.html")

    __slots__ = ("ignore", "server", "status", "target", "_any_crash",
                 "_harness", "_signature", "_unpacked")

    def __init__(self, ignore, server, target, any_crash=False, signature=None, use_harness=True):
        self.ignore = ignore
        self.server = server
        self.status = None
        self.target = target
        self._any_crash = any_crash
        self._harness = None
        # TODO: make signature a property
        self._signature = signature
        if use_harness:
            with open(self.HARNESS_FILE, "rb") as in_fp:
                self._harness = in_fp.read()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def cleanup(self):
        """Remove temporary files from disk.

        Args:
            None

        Returns:
            None
        """
        if self.status is not None:
            self.status.cleanup()

    @staticmethod
    def report_to_filesystem(path, results, tests=None):
        """Use FilesystemReporter to write reports and testcase to disk in a
        known location.

        Args:
            path (str): Location to write data.
            results (iterable): ReplayResult to output.
            tests (iterable): Testcases to output.

        Returns:
            None
        """
        others = list(x.report for x in results if not x.expected)
        if others:
            reporter = FilesystemReporter(pathjoin(path, "other_reports"), major_bucket=False)
            for report in others:
                reporter.submit(tests or [], report=report)
        expected = list(x for x in results if x.expected)
        if expected:
            if tests and len(expected) == 1:
                # only purge optional is reporting a single testcase
                assert len(tests) >= len(expected[0].served)
                for test, served in zip(tests, expected[0].served):
                    LOG.debug("calling test.purge_optional() with %r", served)
                    test.purge_optional(served)
            reporter = FilesystemReporter(pathjoin(path, "reports"), major_bucket=False)
            for result in expected:
                reporter.submit(tests or [], report=result.report)

    def run(self, testcases, repeat=1, min_results=1, idle_delay=0, idle_threshold=0):
        """Run testcase replay.

        Args:
            testcases (list): One or more TestCases to run.
            repeat (int): Maximum number of times to run the TestCase.
            min_results (int): Minimum number of results needed before run can
                               be considered successful.
            idle_delay (int): Number of seconds to wait before polling for idle.
            idle_threshold (int): CPU usage threshold to mark the process as idle.

        Returns:
            list: ReplayResults that were found running testcases.
        """
        assert idle_delay >= 0
        assert idle_threshold >= 0
        assert min_results > 0
        assert repeat > 0
        assert repeat >= min_results
        assert testcases

        if self.status is not None:
            LOG.debug("clearing previous status data")
            self.status.cleanup()
        self.status = Status.start()

        server_map = ServerMap()
        if self._harness is not None:
            def _dyn_close():  # pragma: no cover
                if self.target.monitor.is_healthy():
                    # delay to help catch window close/shutdown related crashes
                    sleep(0.1)
                    self.target.close()
                return b"<h1>Close Browser</h1>"
            server_map.set_dynamic_response("grz_close_browser", _dyn_close, mime_type="text/html")
            server_map.set_dynamic_response("grz_harness", lambda: self._harness, mime_type="text/html")

        runner = Runner(self.server, self.target, idle_threshold=idle_threshold, idle_delay=idle_delay)
        # track unprocessed results
        reports = dict()
        # track unpacked testcases
        unpacked = list()
        try:
            sig_hash = Report.calc_hash(self._signature) if self._signature else None
            test_count = len(testcases)
            LOG.debug("unpacking testcases (%d)...", test_count)
            for test in testcases:
                dst_path = mkdtemp(prefix="tc_", dir=grz_tmp("serve"))
                unpacked.append(dst_path)
                test.dump(dst_path)
            # perform iterations
            for _ in range(repeat):
                self.status.iteration += 1
                if self.target.closed:
                    LOG.info("Launching target...")
                    if self._harness is None:
                        location = runner.location(
                            "/grz_current_test",
                            self.server.port)
                    else:
                        location = runner.location(
                            "/grz_harness",
                            self.server.port,
                            close_after=self.target.rl_reset * test_count,
                            forced_close=self.target.forced_close)
                    # The environment from the initial testcase is used because
                    # a sequence of testcases is expected to be run without
                    # relaunching the Target to match the functionality of
                    # Grizzly. If this is not the case each TestCase should
                    # be run individually.
                    runner.launch(location, env_mod=testcases[0].env_vars)
                self.target.step()
                LOG.info("Performing replay (%d/%d)...", self.status.iteration, repeat)
                # run tests
                durations = list()
                served = list()
                for test_idx in range(test_count):
                    LOG.debug("running test: %d of %d", test_idx + 1, test_count)
                    # update redirects
                    if self._harness is not None:
                        next_idx = (test_idx + 1) % test_count
                        server_map.set_redirect(
                            "grz_next_test",
                            testcases[next_idx].landing_page,
                            required=True)
                    server_map.set_redirect(
                        "grz_current_test",
                        testcases[test_idx].landing_page,
                        required=False)
                    # run testcase
                    run_result = runner.run(
                        self.ignore,
                        server_map,
                        testcases[test_idx],
                        test_path=unpacked[test_idx],
                        wait_for_callback=self._harness is None)
                    durations.append(run_result.duration)
                    served.append(run_result.served)
                    if run_result.status != RunResult.COMPLETE:
                        break
                # process run results
                if run_result.status == RunResult.FAILED:
                    log_path = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
                    self.target.save_logs(log_path)
                    report = Report(log_path, self.target.binary)
                    # check signatures
                    short_sig = report.crash_info.createShortSignature()
                    if not self._any_crash and self._signature is None and short_sig != "No crash detected":
                        LOG.debug("no signature given, using %r", short_sig)
                        self._signature = report.crash_signature
                    if short_sig == "No crash detected":
                        # TODO: verify report.major == "NO_STACK" otherwise FM failed to parse the logs
                        # TODO: change this to support hangs/timeouts, etc
                        LOG.info("Result: No crash detected")
                    elif self._any_crash or self._signature.matches(report.crash_info):
                        self.status.count_result(short_sig)
                        LOG.info("Result: %s (%s:%s)",
                                 short_sig, report.major[:8], report.minor[:8])
                        if sig_hash:
                            LOG.debug("using provided signature (hash) to bucket")
                            bucket_hash = sig_hash
                        else:
                            bucket_hash = report.crash_hash
                        if bucket_hash not in reports:
                            reports[bucket_hash] = ReplayResult(report, served, durations, True)
                            LOG.debug("now tracking %s", bucket_hash)
                            report = None  # don't remove report
                        else:
                            reports[bucket_hash].count += 1
                            LOG.debug("already tracking %s", bucket_hash)
                    else:
                        LOG.info("Result: Different signature: %s (%s:%s)",
                                 short_sig, report.major[:8], report.minor[:8])
                        self.status.ignored += 1
                        if report.crash_hash not in reports:
                            reports[report.crash_hash] = ReplayResult(report, served, durations, False)
                            LOG.debug("now tracking %s", report.crash_hash)
                            report = None  # don't remove report
                        else:
                            reports[report.crash_hash].count += 1
                            LOG.debug("already tracking %s", report.crash_hash)
                    # purge untracked report
                    if report is not None:
                        report.cleanup()
                        report = None
                elif run_result.status == RunResult.IGNORED:
                    self.status.ignored += 1
                    LOG.info("Result: Ignored (%d)", self.status.ignored)
                elif run_result.status == RunResult.ERROR:
                    LOG.error("ERROR: Test case was not served. Timeout too short?")
                    break

                # check status and exit early if possible
                if repeat - self.status.iteration + self.status.results < min_results:
                    if self.status.iteration < repeat:
                        LOG.debug("skipping remaining attempts")
                    # failed to reproduce issue
                    LOG.debug("results (%d) < minimum (%d), after %d attempts",
                              self.status.results, min_results, self.status.iteration)
                    break
                # check if complete (results found)
                if self.status.results >= min_results:
                    assert self.status.results == min_results
                    assert sum(x.count for x in reports.values() if x.expected) >= min_results
                    LOG.debug("results == expected (%d), after %d attempts",
                              min_results, self.status.iteration)
                    break

                # warn about large browser logs
                #self.status.log_size = self.target.log_size()
                #if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                #    LOG.warning("Large browser logs: %dMBs", (self.status.log_size / 0x100000))

                # trigger relaunch by closing the browser if needed
                self.target.check_relaunch()

            # process results
            results = list()
            if self._any_crash:
                assert all(x.expected for x in reports.values())
                if sum(x.count for x in reports.values()) >= min_results:
                    results = list(reports.values())
                else:
                    LOG.debug("%d (any_crash) less than minimum %d", self.status.results, min_results)
                    for report in reports.values():
                        report.report.cleanup()
            else:
                assert sum(x.expected for x in reports.values()) <= 1
                # filter out unreliable expected results
                for crash_hash, report in reports.items():
                    if report.expected and report.count < min_results:
                        LOG.debug("%r less than minimum (%d/%d)", crash_hash, report.count, min_results)
                        report.report.cleanup()
                        continue
                    results.append(report)
            # active reports have been moved to results
            # clear reports to avoid cleanup of active reports
            reports.clear()
            return results

        finally:
            # remove unpacked testcase data
            for tc_path in unpacked:
                rmtree(tc_path)
            self.target.close()
            # remove unprocessed reports
            for report in reports.values():
                report.report.cleanup()


    @classmethod
    def main(cls, args):
        configure_logging(args.log_level)
        if args.fuzzmanager:
            FuzzManagerReporter.sanity_check(args.binary)
            # TODO: add fuzzmanager support

        LOG.info("Starting Grizzly Replay")

        if args.ignore:
            LOG.info("Ignoring: %s", ", ".join(args.ignore))
        if args.xvfb:
            LOG.info("Running with Xvfb")
        if args.rr:
            LOG.info("Running with RR")
        elif args.valgrind:
            LOG.info("Running with Valgrind. This will be SLOW!")

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

        results = None
        target = None
        tmp_prefs = None
        try:
            if args.no_harness and len(testcases) > 1:
                LOG.error("'--no-harness' cannot be used with multiple testcases")
                return 1
            repeat = max(args.min_crashes, args.repeat)
            relaunch = min(args.relaunch, repeat)
            assert not args.no_harness or (args.no_harness and relaunch == 1)
            LOG.info("Repeat: %d, Minimum crashes: %d, Relaunch %d",
                     repeat, args.min_crashes, relaunch)
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
                        tmp_prefs = mkdtemp(prefix="prefs_", dir=grz_tmp("replay"))
                        prefs_tf.dump(tmp_prefs)
                        LOG.info("Using prefs.js from testcase")
                        target.prefs = pathjoin(tmp_prefs, "prefs.js")
                        break
            if testcases[0].env_vars.get("GRZ_FORCED_CLOSE") == "0":
                LOG.debug("setting target.forced_close=False")
                target.forced_close = False
            LOG.debug("starting sapphire server")
            # launch HTTP server used to serve test cases
            with Sapphire(auto_close=1, timeout=args.timeout) as server:
                target.reverse(server.port, server.port)
                with cls(
                    args.ignore,
                    server,
                    target,
                    any_crash=args.any_crash,
                    signature=signature,
                    use_harness=not args.no_harness
                ) as replay:
                    results = replay.run(
                        testcases,
                        idle_delay=args.idle_delay,
                        idle_threshold=args.idle_threshold,
                        min_results=args.min_crashes,
                        repeat=repeat)
            # handle results
            success = any(x.expected for x in results)
            if success:
                LOG.info("Result successfully reproduced")
            else:
                LOG.info("Failed to reproduce results")
            if args.logs and results:
                cls.report_to_filesystem(
                    args.logs,
                    results,
                    testcases if args.include_test else None)
            # TODO: add fuzzmanager reporting
            return 0 if success else 1

        except KeyboardInterrupt:
            return 1

        except (TargetLaunchError, TargetLaunchTimeout) as exc:
            LOG.error(str(exc))
            if isinstance(exc, TargetLaunchError) and exc.report:
                path = grz_tmp("launch_failures")
                LOG.error("Logs can be found here %r", path)
                reporter = FilesystemReporter(path, major_bucket=False)
                reporter.submit([], exc.report)
            return 1

        finally:
            LOG.warning("Shutting down...")
            if results:
                # cleanup unreported results
                for result in results:
                    result.report.cleanup()
            if target is not None:
                target.cleanup()
            for testcase in testcases:
                testcase.cleanup()
            if tmp_prefs is not None:
                rmtree(tmp_prefs, ignore_errors=True)
            LOG.info("Done.")
