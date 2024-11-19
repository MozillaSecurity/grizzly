# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from enum import IntEnum, unique
from logging import getLogger
from time import time
from typing import TYPE_CHECKING

from .common.iomanager import IOManager
from .common.runner import Runner
from .common.status import STATUS_DB_FUZZ, Status
from .target import Result, Target

if TYPE_CHECKING:
    from sapphire import Sapphire

    from .adapter import Adapter
    from .common.reporter import Reporter
    from .common.storage import TestCase

__all__ = ("SessionError", "LogOutputLimiter", "Session")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


LOG = getLogger(__name__)


class SessionError(Exception):
    """The base class for exceptions raised by Session"""


@unique
class LogRate(IntEnum):
    # quickly reduce the amount of output
    NORMAL = 0
    # display status every iteration
    VERBOSE = 1


class LogOutputLimiter:
    __slots__ = (
        "_delay",
        "_iterations",
        "_launches",
        "_multiplier",
        "_rate",
        "_time",
    )

    def __init__(
        self,
        delay: int = 300,
        delta_multiplier: int = 2,
        rate: LogRate = LogRate.NORMAL,
    ) -> None:
        self._delay = delay  # maximum time delay between output
        self._iterations = 1  # next iteration to trigger output
        self._launches = 1  # next launch to trigger output
        self._multiplier = delta_multiplier  # rate to decrease output (iterations)
        self._rate = rate
        self._time = time()

    def ready(self, cur_iter: int, launches: int) -> bool:
        # calculate if a status line should be output
        if self._rate == LogRate.VERBOSE:
            return True
        ready = False
        if cur_iter >= self._iterations:
            ready = True
            self._iterations *= self._multiplier
        elif launches >= self._launches or time() - self._delay >= self._time:
            ready = True
        if ready:
            self._time = time()
            self._launches = launches + 1
        return ready


class Session:
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
        adapter: Adapter,
        reporter: Reporter,
        server: Sapphire,
        target: Target,
        coverage: bool = False,
        enable_profiling: bool = False,
        relaunch: int = 1,
        report_limit: int = 0,
        report_size: int = 1,
    ) -> None:
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
            STATUS_DB_FUZZ,
            enable_profiling=enable_profiling,
            report_limit=report_limit,
        )
        self.target = target

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        # perform final status report
        self.status.report(force=True)
        self.iomanager.cleanup()

    def display_status(self, log_limiter: LogOutputLimiter) -> None:
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

    def generate_testcase(self) -> TestCase:
        LOG.debug("calling iomanager.create_testcase()")
        test = self.iomanager.create_testcase(self.adapter.name)
        LOG.debug("calling adapter.generate()")
        with self.status.measure("generate"):
            self.adapter.generate(test, self.iomanager.server_map)
        self.status.test_name = test.input_fname
        return test

    def run(
        self,
        ignore: set[str],
        time_limit: int,
        input_path: str | None = None,
        iteration_limit: int = 0,
        no_harness: bool = False,
        result_limit: int = 0,
        runtime_limit: int = 0,
        log_rate: LogRate = LogRate.NORMAL,
        launch_attempts: int = 3,
        post_launch_delay: int = 0,
    ) -> None:
        assert iteration_limit >= 0
        assert launch_attempts > 0
        assert runtime_limit >= 0
        assert time_limit > 0

        LOG.debug("calling adapter.setup()")
        self.adapter.setup(input_path, self.iomanager.server_map)
        LOG.debug("configuring harness (%r)", not no_harness)
        harness = None if no_harness else self.adapter.get_harness()
        LOG.debug("configuring redirects (w/harness: %s)", harness is not None)
        if harness is None:
            self.iomanager.server_map.set_redirect(
                "grz_start", "grz_current_test", required=False
            )
        else:
            assert harness
            self.iomanager.server_map.set_dynamic_response(
                "grz_harness", lambda _: harness, mime_type="text/html", required=False
            )
            self.iomanager.server_map.set_redirect(
                "grz_start", "grz_harness", required=False
            )

        log_limiter = LogOutputLimiter(rate=log_rate)
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
                location = runner.location(
                    "/grz_start",
                    self.server.port,
                    close_after=relaunch if harness else None,
                    post_launch_delay=post_launch_delay,
                    scheme=self.server.scheme,
                    time_limit=time_limit if harness else None,
                )
                with self.status.measure("launch"):
                    runner.launch(location, max_retries=launch_attempts, retry_delay=0)
                if post_launch_delay >= 0 and not runner.startup_failure:
                    runner.post_launch(delay=post_launch_delay)
                # TODO: avoid running test case if runner.startup_failure is True
                # especially if it is a hang!

            # create and populate a test case
            current_test = self.generate_testcase()
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
            # adapter callbacks
            if result.timeout:
                current_test.hang = True
                LOG.debug("calling adapter.on_timeout()")
                self.adapter.on_timeout(current_test, result.served)
            else:
                LOG.debug("calling adapter.on_served()")
                self.adapter.on_served(current_test, result.served)
            if not result.attempted:
                LOG.warning("Test case was not served")
                LOG.debug("ignoring test case since nothing was served")
                if current_test.entry_point not in current_test:
                    LOG.error("Check adapter, test case is missing entry point")
                    raise SessionError("Test case is missing entry point")
                if result.timeout:
                    LOG.warning("Browser hung? Timeout too short? System too busy?")
                elif runner.initial:
                    # since this is the first iteration since the Target launched
                    # something is likely wrong with the Target or Adapter
                    LOG.warning(
                        "Failure detected before running a test case, "
                        "browser build is potentially unstable"
                    )
            else:
                self.iomanager.commit()
            # process results
            if result.status == Result.FOUND:
                LOG.debug("result detected")
                report = self.target.create_report(
                    is_hang=result.timeout,
                    unstable=runner.startup_failure,
                )
                seen, initial = self.status.results.count(
                    report.crash_hash, report.short_signature
                )
                LOG.info(
                    "Result: %s (%s:%s) - %d",
                    report.short_signature,
                    report.major[:8],
                    report.minor[:8],
                    seen,
                )
                if initial or not self.status.results.is_frequent(report.crash_hash):
                    # add target info to test cases
                    for test in self.iomanager.tests:
                        test.assets = dict(self.target.asset_mgr.assets)
                        test.assets_path = self.target.asset_mgr.path
                        test.env_vars = self.target.filtered_environ()
                    self.reporter.submit(self.iomanager.tests, report, force=initial)
                else:
                    # we should always submit the first instance of a result
                    assert seen > 1
                    LOG.info("Result is frequent, skipping submission")
                report.cleanup()
            elif result.status == Result.IGNORED:
                self.status.ignored += 1
                if result.timeout:
                    LOG.info(
                        "Ignored - %d; timeout, idle: %r",
                        self.status.ignored,
                        result.idle,
                    )
                else:
                    LOG.info("Ignored - %d", self.status.ignored)

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
