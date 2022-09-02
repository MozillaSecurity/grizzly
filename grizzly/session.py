# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from time import time

from .common.iomanager import IOManager
from .common.runner import Runner
from .common.status import Status
from .target import Result, TargetLaunchError

__all__ = ("SessionError", "LogOutputLimiter", "Session")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


LOG = getLogger(__name__)


class SessionError(Exception):
    """The base class for exceptions raised by Session"""


class LogOutputLimiter:
    __slots__ = (
        "_delay",
        "_iterations",
        "_launches",
        "_multiplier",
        "_time",
        "_verbose",
    )

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

    # display warning when target log files exceed limit (25MB)
    TARGET_LOG_SIZE_WARN = 0x1900000

    __slots__ = (
        "_coverage",
        "_relaunch",
        "_report_size",
        "adapter",
        "iomanager",
        "reporter",
        "server",
        "status",
        "target",
    )

    def __init__(
        self,
        adapter,
        reporter,
        server,
        target,
        coverage=False,
        enable_profiling=False,
        relaunch=1,
        report_limit=0,
        report_size=1,
    ):
        assert relaunch > 0
        assert report_limit >= 0
        assert report_size > 0
        self._coverage = coverage
        self._relaunch = relaunch
        self.adapter = adapter
        self.iomanager = IOManager(report_size=report_size)
        self.reporter = reporter
        self.server = server
        self.status = Status.start(
            enable_profiling=enable_profiling,
            report_limit=report_limit,
        )
        self.target = target

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self.iomanager is not None:
            self.iomanager.cleanup()

    def display_status(self, log_limiter):
        if self.adapter.remaining is not None:
            LOG.info(
                "[I%04d-L%02d-R%02d] %s",
                self.status.iteration,
                self.adapter.remaining,
                self.status.results.total,
                self.status.test_name,
            )
        elif log_limiter.ready(self.status.iteration, self.target.monitor.launches):
            LOG.info("I%04d-R%02d ", self.status.iteration, self.status.results.total)

    def generate_testcase(self, time_limit):
        LOG.debug("calling iomanager.create_testcase()")
        test = self.iomanager.create_testcase(self.adapter.name, time_limit)
        LOG.debug("calling self.adapter.generate()")
        with self.status.measure("generate"):
            self.adapter.generate(test, self.iomanager.server_map)
        self.status.test_name = test.input_fname
        return test

    def run(
        self,
        ignore,
        time_limit,
        input_path=None,
        iteration_limit=0,
        result_limit=0,
        runtime_limit=0,
        display_mode=DISPLAY_NORMAL,
        launch_attempts=3,
    ):
        assert iteration_limit >= 0
        assert launch_attempts > 0
        assert runtime_limit >= 0
        assert time_limit > 0

        LOG.debug("calling adapter.setup()")
        self.adapter.setup(input_path, self.iomanager.server_map)
        LOG.debug("configuring harness")
        harness = self.adapter.get_harness()
        if harness is None:
            self.iomanager.server_map.set_redirect(
                "grz_start", "grz_current_test", required=False
            )
        else:
            self.iomanager.server_map.set_dynamic_response(
                "grz_harness", lambda _: harness, mime_type="text/html", required=False
            )
            self.iomanager.server_map.set_redirect(
                "grz_start", "grz_harness", required=False
            )

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
            LOG.debug("- iteration %d -", self.status.iteration)

            if self.target.closed:
                # (re-)launch target
                self.iomanager.purge()
                self.adapter.pre_launch()
                if harness is None:
                    # harness is not in use, open the test case
                    location = runner.location("/grz_start", self.server.port)
                else:
                    # harness is in use, open it and it will open the test case.
                    location = runner.location(
                        "/grz_start",
                        self.server.port,
                        close_after=relaunch,
                        time_limit=time_limit,
                    )
                try:
                    with self.status.measure("launch"):
                        runner.launch(
                            location, max_retries=launch_attempts, retry_delay=0
                        )
                except TargetLaunchError as exc:
                    short_sig = exc.report.crash_info.createShortSignature()
                    LOG.info(
                        "Result: %s (%s:%s)",
                        short_sig,
                        exc.report.major[:8],
                        exc.report.minor[:8],
                    )
                    self.status.results.count(exc.report.crash_hash, short_sig)
                    self.reporter.submit([], exc.report)
                    exc.report.cleanup()
                    raise TargetLaunchError(str(exc), None) from None

            # create and populate a test case
            current_test = self.generate_testcase(time_limit)
            # display status
            self.display_status(log_limiter=log_limiter)
            # run test case
            with self.status.measure("execute"):
                result = runner.run(
                    ignore,
                    self.iomanager.server_map,
                    current_test,
                    coverage=self._coverage,
                )
            current_test.duration = result.duration
            current_test.assets = self.target.assets
            current_test.env_vars = self.target.filtered_environ()
            # adapter callbacks
            if result.timeout:
                current_test.hang = True
                LOG.debug("calling self.adapter.on_timeout()")
                self.adapter.on_timeout(current_test, result.served)
            else:
                LOG.debug("calling self.adapter.on_served()")
                self.adapter.on_served(current_test, result.served)
            if not result.attempted:
                LOG.warning("Test case was not served")
                LOG.debug("ignoring test case since nothing was served")
                if current_test.landing_page not in current_test.contents:
                    raise SessionError("Test case is missing landing page")
                if runner.initial:
                    # since this is the first iteration since the Target launched
                    # something is likely wrong with the Target or Adapter
                    if result.status == Result.FOUND:
                        LOG.warning("Delayed startup failure detected")
                    else:
                        LOG.warning("Timeout too short? System too busy?")
            else:
                if self.adapter.IGNORE_UNSERVED:
                    LOG.debug("removing unserved files from the test case")
                    current_test.purge_optional(result.served)
                self.iomanager.commit()
            # process results
            if result.status == Result.FOUND:
                LOG.debug("result detected")
                report = self.target.create_report(is_hang=result.timeout)
                if result.timeout:
                    # TODO: we cannot create a unique bucket hash for hangs atm
                    bucket_hash = "hang"
                    short_sig = "Potential hang detected"
                else:
                    bucket_hash = report.crash_hash
                    if report.crash_signature is not None:
                        short_sig = report.crash_info.createShortSignature()
                    else:
                        # FM crash signature creation failed
                        short_sig = "Signature creation failed"
                seen = self.status.results.count(bucket_hash, short_sig)
                LOG.info(
                    "Result: %s (%s:%s) - %d",
                    short_sig,
                    report.major[:8],
                    report.minor[:8],
                    seen,
                )
                if not self.status.results.is_frequent(bucket_hash):
                    self.reporter.submit(self.iomanager.tests, report)
                else:
                    # we should always submit the first instance of a result
                    assert seen > 1
                    LOG.info("Result is frequent, skipping submission")
                report.cleanup()
            elif result.status == Result.IGNORED:
                self.status.ignored += 1
                LOG.info("Ignored - %d", self.status.ignored)

            # ignore startup failure if it did not happen early on
            # to avoid aborting the fuzzing session unnecessarily
            if runner.startup_failure and self.status.iteration < 100:
                raise SessionError("Please check Adapter and Target")

            if self.adapter.remaining is not None and self.adapter.remaining < 1:
                # all test cases have been replayed
                LOG.info("Replay Complete")
                break

            if iteration_limit and self.status.iteration >= iteration_limit:
                LOG.info("Hit iteration limit (%d)", iteration_limit)
                break

            if result_limit and self.status.results.total >= result_limit:
                LOG.info("Hit result limit (%d)", result_limit)
                break

            if runtime_limit and self.status.runtime >= runtime_limit:
                LOG.info("Hit runtime limit (%ds)", runtime_limit)
                break

            # warn about large browser logs
            self.status.log_size = self.target.log_size()
            if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                LOG.warning(
                    "Large browser logs: %dMBs", (self.status.log_size / 0x100000)
                )

        # perform final status report
        self.status.report(force=True)
