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
from ..common.runner import Runner
from ..common.status import Status
from ..common.storage import TestCase, TestCaseLoadFailure, TestFile
from ..common.utils import grz_tmp
from ..main import configure_logging
from ..target import load as load_target, TargetLaunchError, TargetLaunchTimeout

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger("replay")


class ReplayManager(object):
    HARNESS_FILE = pathjoin(dirname(__file__), "..", "common", "harness.html")

    __slots__ = ("ignore", "server", "status", "target", "_any_crash",
                 "_harness", "_reports_expected", "_reports_other", "_runner",
                 "_signature", "_unpacked")

    def __init__(self, ignore, server, target, any_crash=False, signature=None, use_harness=True):
        self.ignore = ignore
        self.server = server
        self.status = None
        self.target = target
        self._any_crash = any_crash
        self._harness = None
        self._reports_expected = dict()
        self._reports_other = dict()
        self._runner = Runner(self.server, self.target)
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
        for report in self._reports_expected.values():
            report.cleanup()
        self._reports_expected.clear()
        for report in self._reports_other.values():
            report.cleanup()
        self._reports_other.clear()
        if self.status is not None:
            self.status.cleanup()

    @property
    def other_reports(self):
        """Reports from results that do not match:
            - the given signature
            - the initial result (if any-crash is not specified)

        Args:
            None

        Returns:
            iterable: Reports.
        """
        return self._reports_other.values()

    @property
    def reports(self):
        """Reports from results.

        Args:
            None

        Returns:
            iterable: Reports.
        """
        return self._reports_expected.values()

    @staticmethod
    def report_to_filesystem(path, reports, other_reports=None, tests=None):
        """Use FilesystemReporter to write reports and testcase to disk in a
        known location.

        Args:
            path (str): Location to write data.
            reports (iterable): Reports to output.
            other_reports (iterable): Reports to output.
            tests (iterable): Testcases to output.

        Returns:
            None
        """
        if reports:
            reporter = FilesystemReporter(
                report_path=pathjoin(path, "reports"),
                major_bucket=False)
            for report in reports:
                reporter.submit(tests, report=report)
        if other_reports:
            reporter = FilesystemReporter(
                report_path=pathjoin(path, "other_reports"),
                major_bucket=False)
            for report in other_reports:
                reporter.submit(tests, report=report)

    def run(self, testcases, repeat=1, min_results=1):
        """Run testcase replay.

        Args:
            testcases (list): One or more TestCases to run.
            repeat (int): Maximum number of times to run the TestCase.
            min_results (int): Minimum number of results needed before run can
                               be considered successful.

        Returns:
            bool: True if results were reproduced otherwise False.
        """
        assert repeat > 0
        assert min_results > 0
        assert min_results <= repeat

        self.status = Status.start()
        test_count = len(testcases)
        assert test_count > 0

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

        success = False
        unpacked = list()
        try:
            LOG.debug("unpacking testcases (%d)...", test_count)
            for test in testcases:
                dst_path = mkdtemp(prefix="tc_", dir=grz_tmp("serve"))
                test.dump(dst_path)
                unpacked.append(dst_path)
            # perform iterations
            for _ in range(repeat):
                self.status.iteration += 1
                if self.target.closed:
                    LOG.info("Launching target...")
                    if self._harness is None:
                        location = self._runner.location(
                            "/grz_current_test",
                            self.server.port)
                    else:
                        location = self._runner.location(
                            "/grz_harness",
                            self.server.port,
                            close_after=self.target.rl_reset * test_count,
                            forced_close=self.target.forced_close)
                    try:
                        # The environment from the initial testcase is used because
                        # a sequence of testcases is expected to be run without
                        # relaunching the Target to match the functionality of
                        # Grizzly. If this is not the case each TestCase should
                        # be run individually.
                        self._runner.launch(location, env_mod=testcases[0].env_vars)
                    except TargetLaunchError:
                        LOG.error("Target launch error. Check browser logs for details.")
                        log_path = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
                        self.target.save_logs(log_path)
                        self._reports_other["STARTUP"] = Report.from_path(log_path)
                        raise
                self.target.step()
                LOG.info("Performing replay (%d/%d)...", self.status.iteration, repeat)
                # run tests
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
                    self._runner.run(
                        self.ignore,
                        server_map,
                        testcases[test_idx],
                        test_path=unpacked[test_idx],
                        wait_for_callback=self._harness is None)
                    if self._runner.result != self._runner.COMPLETE:
                        break
                # process results
                if self._runner.result == self._runner.FAILED:
                    log_path = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
                    self.target.save_logs(log_path)
                    report = Report.from_path(log_path)
                    # check signatures
                    crash_info = report.crash_info(self.target.binary)
                    short_sig = crash_info.createShortSignature()
                    if not self._any_crash and self._signature is None and short_sig != "No crash detected":
                        # signature has not been specified use the first one created
                        self._signature = report.crash_signature(crash_info)
                    if short_sig == "No crash detected":
                        # TODO: verify report.major == "NO_STACK" otherwise FM failed to parse the logs
                        # TODO: change this to support hangs/timeouts, etc
                        LOG.info("Result: No crash detected")
                        crash_hash = None
                    elif self._any_crash or self._signature.matches(crash_info):
                        self.status.count_result(short_sig)
                        LOG.info("Result: %s (%s:%s)",
                                 short_sig, report.major[:8], report.minor[:8])
                        crash_hash = report.crash_hash(crash_info)
                        if crash_hash not in self._reports_expected:
                            LOG.debug("now tracking %s", crash_hash)
                            self._reports_expected[crash_hash] = report
                            report = None  # don't remove report
                        assert self._any_crash or len(self._reports_expected) == 1
                    else:
                        LOG.info("Result: Different signature: %s (%s:%s)",
                                 short_sig, report.major[:8], report.minor[:8])
                        self.status.ignored += 1
                        crash_hash = report.crash_hash(crash_info)
                        if crash_hash not in self._reports_other:
                            LOG.debug("now tracking %s", crash_hash)
                            self._reports_other[crash_hash] = report
                            report = None  # don't remove report
                    # purge untracked report
                    if report is not None:
                        if crash_hash is not None:
                            LOG.debug("already tracking %s", crash_hash)
                        report.cleanup()
                        report = None
                elif self._runner.result == self._runner.IGNORED:
                    self.status.ignored += 1
                    LOG.info("Result: Ignored (%d)", self.status.ignored)
                elif self._runner.result == self._runner.ERROR:
                    LOG.error("ERROR: Replay malfunction, test case was not served")
                    break

                # check status and exit early if possible
                if repeat - self.status.iteration + self.status.results < min_results:
                    if self.status.iteration < repeat:
                        LOG.debug("skipping remaining attempts")
                    # failed to reproduce issue
                    LOG.debug("results (%d) < expected (%s) after %d attempts",
                              self.status.results, min_results, self.status.iteration)
                    break
                if self.status.results >= min_results:
                    assert self.status.results == min_results
                    success = True
                    LOG.debug("results == expected (%s) after %d attempts",
                              min_results, self.status.iteration)
                    break

                # warn about large browser logs
                #self.status.log_size = self.target.log_size()
                #if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                #    LOG.warning("Large browser logs: %dMBs", (self.status.log_size / 0x100000))

                # trigger relaunch by closing the browser if needed
                self.target.check_relaunch()
        finally:
            for tc_path in unpacked:
                rmtree(tc_path)
        if success:
            LOG.info("Result successfully reproduced")
        else:
            LOG.info("Failed to reproduce results")
        self.target.close()
        return success

    @classmethod
    def main(cls, args):
        configure_logging(args.log_level)
        if args.fuzzmanager:
            FuzzManagerReporter.sanity_check(args.binary)

        LOG.info("Starting Grizzly Replay")

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

        replay = None
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
                replay = ReplayManager(
                    args.ignore,
                    server,
                    target,
                    any_crash=args.any_crash,
                    signature=signature,
                    use_harness=not args.no_harness)
                success = replay.run(testcases, repeat=repeat, min_results=args.min_crashes)
            if args.logs:
                replay.report_to_filesystem(
                    args.logs,
                    replay.reports,
                    replay.other_reports,
                    testcases if args.include_test else None)
            # TODO: add fuzzmanager reporting
            return 0 if success else 1

        except KeyboardInterrupt:
            return 1

        except (TargetLaunchError, TargetLaunchTimeout):
            if args.logs and replay is not None:
                replay.report_to_filesystem(
                    args.logs,
                    replay.reports,
                    replay.other_reports)
            return 1

        finally:
            LOG.warning("Shutting down...")
            if replay is not None:
                replay.cleanup()
            if target is not None:
                target.cleanup()
            for testcase in testcases:
                testcase.cleanup()
            if tmp_prefs is not None:
                rmtree(tmp_prefs, ignore_errors=True)
            LOG.info("Done.")
