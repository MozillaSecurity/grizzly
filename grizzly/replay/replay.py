# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import tempfile

from FTB.Signatures.CrashInfo import CrashSignature
from sapphire import Sapphire, ServerMap

from ..common import FilesystemReporter, FuzzManagerReporter, Report, Runner, \
    Status, TestCase, TestCaseLoadFailure, TestFile
from ..target import load as load_target, TargetLaunchError, TargetLaunchTimeout

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = logging.getLogger("replay")


class ReplayManager(object):
    HARNESS_FILE = os.path.join(os.path.dirname(__file__), "..", "common", "harness.html")

    def __init__(self, ignore, server, target, testcase, any_crash=False, signature=None, use_harness=True):
        self.ignore = ignore
        self.server = server
        self.status = None
        self.target = target
        self.testcase = testcase
        self._any_crash = any_crash
        self._harness = None
        self._reports_expected = dict()
        self._reports_other = dict()
        self._runner = Runner(self.server, self.target)
        self._signature = signature

        if use_harness:
            self._harness = TestFile.from_file(self.HARNESS_FILE, "harness.html")
            testcase.add_file(self._harness, required=False)

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
    def report_to_filesystem(path, reports, other_reports=None, test=None):
        """Use FilesystemReporter to write reports and testcase to disk in a
        known location.

        Args:
            path (str): Location to write data.
            reports (iterable): Reports to output.
            other_reports (iterable): Reports to output.
            test (TestCase): Testcase to output.

        Returns:
            None
        """
        assert test is None or isinstance(test, TestCase)
        tests = [test] if test else tuple()
        if reports:
            reporter = FilesystemReporter(
                report_path=os.path.join(path, "reports"),
                major_bucket=False)
            for report in reports:
                reporter.submit(tests, report=report)
        if other_reports:
            reporter = FilesystemReporter(
                report_path=os.path.join(path, "other_reports"),
                major_bucket=False)
            for report in other_reports:
                reporter.submit(tests, report=report)

    def run(self, repeat=1, min_results=1):
        """Run testcase replay.

        Args:
            repeat (int): Maximum number of times to run the test case.
            min_results (int): Minimum number of results needed before run can
                               be considered successful.

        Returns:
            bool: Results were reproduced.
        """
        assert repeat > 0
        assert min_results > 0
        assert min_results <= repeat
        self.status = Status.start()

        server_map = ServerMap()
        if self._harness is not None:
            def _dyn_close():  # pragma: no cover
                self.target.close()
                return b"<h1>Close Browser</h1>"
            server_map.set_dynamic_response("/close_browser", _dyn_close, mime_type="text/html")
            server_map.set_redirect("/first_test", self.testcase.landing_page, required=False)
            server_map.set_redirect("/next_test", self.testcase.landing_page, required=True)

        success = False
        for _ in range(repeat):
            self.status.iteration += 1
            if self.target.closed:
                LOG.info("Launching target...")
                if self._harness is None:
                    location = self._runner.location(self.testcase.landing_page, self.server.port)
                else:
                    location = self._runner.location(
                        self._harness.file_name,
                        self.server.port,
                        close_after=self.target.rl_reset,
                        forced_close=self.target.forced_close)
                try:
                    self._runner.launch(location, env_mod=self.testcase.env_vars)
                except TargetLaunchError:
                    LOG.error("Target launch error. Check browser logs for details.")
                    log_path = tempfile.mkdtemp(prefix="grzreplay_logs_")
                    self.target.save_logs(log_path, meta=True)
                    self._reports_other["STARTUP"] = Report.from_path(log_path)
                    raise
            self.target.step()
            LOG.info("Performing replay (%d/%d)...", self.status.iteration, repeat)
            # run test case
            self._runner.run(self.ignore, server_map, self.testcase, wait_for_callback=self._harness is None)
            # process results
            if self._runner.result == self._runner.FAILED:
                log_path = tempfile.mkdtemp(prefix="grzreplay_logs_")
                self.target.save_logs(log_path, meta=True)
                report = Report.from_path(log_path)
                # check signatures
                crash_info = report.crash_info(self.target.binary)
                short_sig = crash_info.createShortSignature()
                if not self._any_crash and self._signature is None and short_sig != "No crash detected":
                    # signature has not been specified use the first one created
                    self._signature = report.crash_signature(crash_info)
                if short_sig == "No crash detected":
                    # TODO: change this to support hangs/timeouts, etc
                    LOG.info("Result: No crash detected")
                    crash_hash = None
                elif self._any_crash or self._signature.matches(crash_info):
                    self.status.results += 1
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

        if success:
            LOG.info("Result successfully reproduced")
        else:
            LOG.info("Failed to reproduce results")
        self.target.close()
        return success

    @classmethod
    def main(cls, args):
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

        try:
            LOG.debug("loading the TestCase")
            testcase = TestCase.load_path(args.input)
            if os.path.isfile(args.input):
                testcase.add_meta(TestFile.from_file(args.prefs, "prefs.js"))
        except TestCaseLoadFailure as exc:
            LOG.error("Error: %s", str(exc))
            return 1

        replay = None
        target = None
        try:
            relaunch = min(args.relaunch, args.repeat)
            LOG.debug("initializing the Target")
            target = load_target(args.platform)(
                args.binary,
                args.extension,
                args.launch_timeout,
                args.log_limit,
                args.memory,
                args.prefs,
                relaunch,
                rr=args.rr,
                valgrind=args.valgrind,
                xvfb=args.xvfb)

            LOG.debug("starting sapphire server")
            # launch HTTP server used to serve test cases
            with Sapphire(auto_close=1, timeout=args.timeout) as server:
                target.reverse(server.port, server.port)
                if args.no_harness:
                    LOG.debug("--no-harness specified relaunch set to 1")
                    args.relaunch = 1
                args.repeat = max(args.min_crashes, args.repeat)
                LOG.info("Repeat: %d, Minimum crashes: %d, Relaunch %d",
                         args.repeat, args.min_crashes, relaunch)
                replay = ReplayManager(
                    args.ignore,
                    server,
                    target,
                    testcase,
                    any_crash=args.any_crash,
                    signature=signature,
                    use_harness=not args.no_harness)
                success = replay.run(repeat=args.repeat, min_results=args.min_crashes)
            if args.logs:
                replay.report_to_filesystem(
                    args.logs,
                    replay.reports,
                    replay.other_reports,
                    replay.testcase if args.include_test else None)
            return 0 if success else 1

        except KeyboardInterrupt:
            return 1

        except (TargetLaunchError, TargetLaunchTimeout):
            if args.logs:
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
            if testcase is not None:
                testcase.cleanup()
            LOG.info("Done.")
