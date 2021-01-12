# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from logging import getLogger
from os.path import isdir
from shutil import rmtree
from tempfile import mkdtemp
from time import time

from .common import grz_tmp, Report, Runner, RunResult, Status, TestFile


__all__ = ("SessionError", "LogOutputLimiter", "Session")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


LOG = getLogger(__name__)


class SessionError(Exception):
    """The base class for exceptions raised by Session"""


class LogOutputLimiter:
    __slots__ = ("_delay", "_iterations", "_launches", "_multiplier", "_time", "_verbose")

    def __init__(self, delay=300, delta_multiplier=2, verbose=False):
        self._delay = delay  # maximum time delay between output
        self._iterations = 1  # next iteration to trigger output
        self._launches = 1  # next launch to trigger output
        self._multiplier = delta_multiplier  # rate to decrease output (iterations)
        self._time = time()
        self._verbose = verbose  # always output

    def ready(self, cur_iter, launches):
        # calculate if a status line should be output
        if self._verbose:
            return True
        ready = False
        if cur_iter >= self._iterations:
            ready = True
            self._iterations *= self._multiplier
        elif launches >= self._launches:
            ready = True
        elif time() - self._delay >= self._time:
            ready = True
        if ready:
            self._time = time()
            self._launches = launches + 1
        return ready


class Session:
    DISPLAY_VERBOSE = 0  # display status every iteration
    DISPLAY_NORMAL = 1  # quickly reduce the amount of output
    EXIT_SUCCESS = 0
    EXIT_ERROR = 1  # unexpected error occurred (invalid input, unhanded exception, etc)
    EXIT_ARGS = 2  # invalid argument
    EXIT_ABORT = 3  # run aborted (ctrl+c, etc)
    EXIT_LAUNCH_FAILURE = 4  # unrelated Target failure (browser startup crash, etc)
    EXIT_FAILURE = 5  # expected results not reproduced (opposite of EXIT_SUCCESS)

    TARGET_LOG_SIZE_WARN = 0x1900000  # display warning when target log files exceed limit (25MB)

    __slots__ = ("_relaunch", "adapter", "coverage", "iomanager", "reporter", "server",
                 "status", "target")

    def __init__(self, adapter, iomanager, reporter, server, target,
                 coverage=False, relaunch=1):
        self._relaunch = relaunch
        self.adapter = adapter
        self.coverage = coverage
        self.iomanager = iomanager
        self.reporter = reporter
        self.server = server
        self.status = Status.start()
        self.target = target

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self.status.cleanup()

    def display_status(self, log_limiter):
        if self.adapter.remaining is not None:
            LOG.info(
                "[I%04d-L%02d-R%02d] %s",
                self.status.iteration,
                self.adapter.remaining,
                self.status.results,
                self.status.test_name)
        elif log_limiter.ready(self.status.iteration, self.target.monitor.launches):
            LOG.info("I%04d-R%02d ", self.status.iteration, self.status.results)

    def generate_testcase(self):
        LOG.debug("calling iomanager.create_testcase()")
        test = self.iomanager.create_testcase(self.adapter.NAME)
        LOG.debug("calling self.adapter.generate()")
        self.adapter.generate(test, self.iomanager.server_map)
        self.status.test_name = test.input_fname
        if self.target.prefs is not None:
            # TODO: this can likely be improved
            test.add_meta(TestFile.from_file(self.target.prefs, "prefs.js"))
        return test

    def report_result(self):
        # create working directory for target logs
        result_logs = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
        self.target.save_logs(result_logs)
        report = Report(result_logs, self.target.binary)
        short_sig = report.crash_info.createShortSignature()
        LOG.info("Result: %s (%s:%s)", short_sig, report.major[:8], report.minor[:8])
        # order test cases newest to oldest
        self.iomanager.tests.reverse()
        self.reporter.submit(self.iomanager.tests, report)
        if isdir(result_logs):
            rmtree(result_logs)
        self.status.count_result(short_sig)

    def run(self, ignore, iteration_limit=0, display_mode=DISPLAY_NORMAL):
        assert iteration_limit >= 0
        log_limiter = LogOutputLimiter(verbose=display_mode == self.DISPLAY_VERBOSE)
        # limit relaunch to max iterations if needed
        relaunch = min(self._relaunch, iteration_limit) or self._relaunch
        if self.adapter.remaining is not None:
            assert self.adapter.remaining > 0
            relaunch = min(relaunch, self.adapter.remaining)
        runner = Runner(self.server, self.target, relaunch=relaunch)
        while True:
            self.status.report()
            self.status.iteration += 1

            if self.target.closed:
                # (re-)launch target
                self.iomanager.purge_tests()
                self.adapter.pre_launch()
                if self.iomanager.harness is None:
                    # harness is not in use, open the test case
                    location = runner.location("/grz_current_test", self.server.port)
                else:
                    # harness is in use, open it and it will open the test case.
                    # use adapter.TEST_DURATION to allow the harness to attempt to
                    # close test cases when server timeout is greater.
                    location = runner.location(
                        "/grz_harness",
                        self.server.port,
                        close_after=relaunch,
                        timeout=self.adapter.TEST_DURATION)
                runner.launch(location, max_retries=3, retry_delay=0)

            # create and populate a test case
            current_test = self.generate_testcase()
            # display status
            self.display_status(log_limiter=log_limiter)

            # run test case
            result = runner.run(ignore, self.iomanager.server_map, current_test, coverage=self.coverage)
            current_test.duration = result.duration
            # adapter callbacks
            if result.timeout:
                LOG.debug("calling self.adapter.on_timeout()")
                self.adapter.on_timeout(current_test, result.served)
            else:
                LOG.debug("calling self.adapter.on_served()")
                self.adapter.on_served(current_test, result.served)
            # update test case
            if not result.attempted:
                LOG.debug("Ignoring test case since nothing was served")
                self.iomanager.tests.pop().cleanup()
                if not current_test.contains(current_test.landing_page):
                    LOG.warning("Test case is missing landing page")
                if result.initial:
                    # since this is the first iteration since the Target launched
                    # something is likely wrong with the Target or Adapter
                    err_logs = mkdtemp(prefix="error_", dir=grz_tmp("logs"))
                    self.target.save_logs(err_logs)
                    LOG.error("ERROR: Test case was not served. Timeout too short?")
                    LOG.error("Logs can be found here %r", err_logs)
                    raise SessionError("Please check Adapter and Target")
                LOG.warning("Test case was not served")
            elif self.adapter.IGNORE_UNSERVED:
                LOG.debug("removing unserved files from the test case")
                current_test.purge_optional(result.served)
            # process results
            if result.status == RunResult.FAILED:
                LOG.debug("result detected")
                self.report_result()
            elif result.status == RunResult.IGNORED:
                self.status.ignored += 1
                LOG.info("Ignored (%d)", self.status.ignored)

            if self.adapter.remaining is not None and self.adapter.remaining < 1:
                # all test cases have been replayed
                LOG.info("Replay Complete")
                break

            if iteration_limit and self.status.iteration >= iteration_limit:
                LOG.info("Hit iteration limit (%d)", iteration_limit)
                break

            # warn about large browser logs
            self.status.log_size = self.target.log_size()
            if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                LOG.warning("Large browser logs: %dMBs", (self.status.log_size / 0x100000))
