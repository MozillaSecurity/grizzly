# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import tempfile
import time

from sapphire import Sapphire
from .common import Runner, Status, TestFile
from .target import TargetLaunchError


__all__ = ("LogOutputLimiter", "Session")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


class LogOutputLimiter(object):
    __slots__ = ("_delay", "_iterations", "_launches", "_multiplier", "_time", "_verbose")

    def __init__(self, delay=300, delta_multiplier=2, verbose=False):
        self._delay = delay  # maximum time delay between output
        self._iterations = 1  # next iteration to trigger output
        self._launches = 1  # next launch to trigger output
        self._multiplier = delta_multiplier  # rate to decrease output (iterations)
        self._time = time.time()
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
        elif time.time() - self._delay >= self._time:
            ready = True
        if ready:
            self._time = time.time()
            self._launches = launches + 1
        return ready


class Session(object):
    DISPLAY_VERBOSE = 0  # display status every iteration
    DISPLAY_NORMAL = 1  # quickly reduce the amount of output
    EXIT_SUCCESS = 0
    EXIT_ERROR = 1
    EXIT_ABORT = 3
    EXIT_LAUNCH_FAILURE = 7
    TARGET_LOG_SIZE_WARN = 0x1900000  # display warning when target log files exceed limit (25MB)

    def __init__(self, adapter, coverage, ignore, iomanager, reporter, target, display_mode=DISPLAY_NORMAL):
        self._lol = LogOutputLimiter(verbose=display_mode == self.DISPLAY_VERBOSE)
        self.adapter = adapter
        self.coverage = coverage
        self.ignore = ignore
        self.iomanager = iomanager
        self.reporter = reporter
        self.server = None
        self.status = Status.start()
        self.target = target

    def config_server(self, iteration_timeout):
        assert self.server is None
        log.debug("starting sapphire server")
        # set 'auto_close=1' so the client error pages (code 4XX) will
        # call 'window.close()' after a second.
        # launch http server used to serve test cases
        self.server = Sapphire(auto_close=1, timeout=iteration_timeout)
        def _dyn_resp_close():  # pragma: no cover
            self.target.close()
            return b"<h1>Close Browser</h1>"
        self.iomanager.server_map.set_dynamic_response(
            "/close_browser",
            _dyn_resp_close,
            mime_type="text/html")

    def close(self):
        self.status.cleanup()
        if self.server is not None:
            self.server.close()

    def display_status(self):
        if not self.adapter.ROTATION_PERIOD:
            assert self.status.test_name is not None
            log.info(
                "[I%04d-L%02d-R%02d] %s",
                self.status.iteration,
                len(self.iomanager.input_files),
                self.status.results,
                os.path.basename(self.status.test_name))
        elif self._lol.ready(self.status.iteration, self.target.monitor.launches):
            if self.status.test_name:
                log.debug("fuzzing: %s", os.path.basename(self.status.test_name))
            log.info("I%04d-R%02d ", self.status.iteration, self.status.results)

    def generate_testcase(self):
        assert self.server is not None
        log.debug("calling iomanager.create_testcase()")
        test = self.iomanager.create_testcase(self.adapter.NAME, rotation_period=self.adapter.ROTATION_PERIOD)
        log.debug("calling self.adapter.generate()")
        self.adapter.generate(test, self.iomanager.active_input, self.iomanager.server_map)
        if self.target.prefs is not None:
            test.add_meta(TestFile.from_file(self.target.prefs, "prefs.js"))
        return test

    def report_result(self):
        # create working directory for current testcase
        result_logs = tempfile.mkdtemp(prefix="grz_logs_", dir=self.iomanager.working_path)
        self.target.save_logs(result_logs, meta=True)
        log.info("Reporting results...")
        self.iomanager.tests.reverse()  # order test cases newest to oldest
        self.reporter.submit(self.iomanager.tests, log_path=result_logs)
        if os.path.isdir(result_logs):
            shutil.rmtree(result_logs)

    def run(self, iteration_limit=None):
        assert self.server is not None, "server is not configured"
        runner = Runner(self.server, self.target)
        while True:  # main fuzzing loop
            self.status.report()
            self.status.iteration += 1

            if self.target.closed:
                # (re-)launch target
                self.iomanager.purge_tests()
                self.adapter.pre_launch()
                if self.iomanager.harness is None:
                    location = runner.location(self.iomanager.landing_page(), self.server.port)
                else:
                    location = runner.location(
                        self.iomanager.landing_page(),
                        self.server.port,
                        close_after=self.target.rl_reset,
                        forced_close=self.target.forced_close,
                        timeout=self.adapter.TEST_DURATION)
                log.info("Launching target")
                try:
                    runner.launch(location, max_retries=3, retry_delay=0)
                except TargetLaunchError:
                    # this result likely has nothing to do with Grizzly
                    self.status.results += 1
                    log.error("Launch error detected")
                    self.report_result()
                    raise
            self.target.step()

            # create and populate a test case
            current_test = self.generate_testcase()
            if self.iomanager.active_input is not None:
                self.status.test_name = self.iomanager.active_input.file_name

            # display status
            self.display_status()

            # run test case
            runner.run(self.ignore, self.iomanager.server_map, current_test)
            # update test case
            if self.adapter.IGNORE_UNSERVED:
                if runner.served:
                    log.debug("removing unserved files from the test case")
                    current_test.purge_optional(runner.served)
                else:
                    log.info("Ignoring test case since nothing was served")
                    self.iomanager.tests.pop().cleanup()
            # adapter callbacks
            if runner.timeout:
                log.debug("calling self.adapter.on_timeout()")
                self.adapter.on_timeout(current_test, runner.served)
            else:
                log.debug("calling self.adapter.on_served()")
                self.adapter.on_served(current_test, runner.served)
            # process results
            if runner.result == runner.FAILED:
                self.status.results += 1
                log.info("Result detected")
                self.report_result()
            elif runner.result == runner.IGNORED:
                self.status.ignored += 1
                log.info("Ignored (%d)", self.status.ignored)

            if self.coverage and runner.result == runner.COMPLETE:
                self.target.dump_coverage()

            # warn about large browser logs
            self.status.log_size = self.target.log_size()
            if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                log.warning("Large browser logs: %dMBs", (self.status.log_size / 0x100000))

            # trigger relaunch by closing the browser if needed
            self.target.check_relaunch()

            # all test cases have been replayed
            if not self.adapter.ROTATION_PERIOD and not self.iomanager.input_files:
                log.info("Replay Complete")
                break

            if iteration_limit is not None and self.status.iteration == iteration_limit:
                log.info("Hit iteration limit")
                break
