# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import shutil
import tempfile

import sapphire
from .common import Status, TestFile
from .target import TargetLaunchError, TargetLaunchTimeout


__all__ = ("Session",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


class Session(object):
    DISPLAY_VERBOSE = 0  # display status every iteration
    DISPLAY_NORMAL = 1  # quickly reduce the amount of output
    EXIT_SUCCESS = 0
    EXIT_ERROR = 1
    EXIT_ABORT = 3
    EXIT_LAUNCH_FAILURE = 7
    TARGET_LOG_SIZE_WARN = 0x1900000  # display warning when target log files exceed limit (25MB)

    def __init__(self, adapter, coverage, ignore, iomanager, reporter, target, display_mode=DISPLAY_NORMAL):
        self._next_display = display_mode
        self.adapter = adapter
        self.coverage = coverage
        self.ignore = ignore
        self.iomanager = iomanager
        self.reporter = reporter
        self.server = None
        self.status = Status.start()
        self.target = target

    def check_results(self, unserved, was_timeout):
        # attempt to detect a failure
        failure_detected = self.target.detect_failure(self.ignore, was_timeout)
        if unserved and self.adapter.IGNORE_UNSERVED:
            # if nothing was served remove most recent
            # test case from list to help maintain browser/fuzzer sync
            log.info("Ignoring test case since nothing was served")
            self.iomanager.tests.pop().cleanup()
        # handle failure if detected
        if failure_detected == self.target.RESULT_FAILURE:
            self.status.results += 1
            log.info("Result detected")
            self.report_result()
        elif failure_detected == self.target.RESULT_IGNORED:
            self.status.ignored += 1
            log.info("Ignored (%d)", self.status.ignored)

    def config_server(self, iteration_timeout):
        assert self.server is None
        log.debug("starting sapphire server")
        # have client error pages (code 4XX) call window.close() after a few seconds
        sapphire.Sapphire.CLOSE_CLIENT_ERROR = 1
        # launch http server used to serve test cases
        self.server = sapphire.Sapphire(timeout=iteration_timeout)
        # add include paths to server
        for url_path, target_path in self.iomanager.server_map.includes:
            self.server.add_include(url_path, target_path)
        # add dynamic responses to the server
        for dyn_rsp in self.iomanager.server_map.dynamic_responses:
            self.server.add_dynamic_response(
                dyn_rsp["url"],
                dyn_rsp["callback"],
                mime_type=dyn_rsp["mime"])
        def _dyn_resp_close():
            self.target.close()
            return b"<h1>Close Browser</h1>"
        self.server.add_dynamic_response("/close_browser", _dyn_resp_close, mime_type="text/html")

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
        elif not self._next_display or self.status.iteration == self._next_display:
            self._next_display *= 2
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
        # update sapphire redirects from the adapter
        for redirect in self.iomanager.server_map.redirects:
            self.server.set_redirect(redirect["url"], redirect["file_name"], redirect["required"])
        return test

    def launch_target(self):
        assert self.target.closed
        launch_timeouts = 0
        while True:
            try:
                log.info("Launching target")
                self.target.launch(self.location)
            except TargetLaunchError:
                # this result likely has nothing to do with Grizzly
                self.status.results += 1
                log.error("Launch error detected")
                self.report_result()
                raise
            except TargetLaunchTimeout:
                launch_timeouts += 1
                log.warning("Launch timeout detected (attempt #%d)", launch_timeouts)
                # likely has nothing to do with Grizzly but is seen frequently on machines under a high load
                # after 3 timeouts in a row something is likely wrong so raise
                if launch_timeouts < 3:
                    continue
                raise
            break

    @property
    def location(self):
        assert self.server is not None
        location = ["http://127.0.0.1:%d/" % self.server.get_port(), self.iomanager.landing_page()]
        if self.iomanager.harness is not None:
            location.append("?timeout=%d" % (self.adapter.TEST_DURATION * 1000))
            location.append("&close_after=%d" % self.target.rl_reset)
            if not self.target.forced_close:
                location.append("&forced_close=0")
        return "".join(location)

    def report_result(self):
        # create working directory for current testcase
        result_logs = tempfile.mkdtemp(prefix="grz_logs_", dir=self.iomanager.working_path)
        self.target.save_logs(result_logs, meta=True)
        log.info("Reporting results...")
        self.iomanager.tests.reverse()  # order test cases newest to oldest
        self.reporter.submit(result_logs, self.iomanager.tests)
        if os.path.isdir(result_logs):
            shutil.rmtree(result_logs)

    def run(self, iteration_limit=None):
        assert self.server is not None, "server is not configured"
        while True:  # main fuzzing loop
            self.status.report()
            self.status.iteration += 1

            if self.target.closed:
                self.iomanager.purge_tests()
                self.adapter.pre_launch()
                self.launch_target()
            self.target.step()

            # create and populate a test case
            current_test = self.generate_testcase()
            if self.iomanager.active_input is not None:
                self.status.test_name = self.iomanager.active_input.file_name

            # display status
            self.display_status()

            # use Sapphire to serve the most recent test case
            server_status, files_served = self.server.serve_testcase(
                current_test,
                continue_cb=self.target.monitor.is_healthy,
                working_path=self.iomanager.working_path)
            if self.adapter.IGNORE_UNSERVED:
                log.debug("removing unserved files from the test case")
                current_test.remove_files_not_served(files_served)

            if server_status == sapphire.SERVED_TIMEOUT:
                log.debug("calling self.adapter.on_timeout()")
                self.adapter.on_timeout(current_test, files_served)
            else:
                log.debug("calling self.adapter.on_served()")
                self.adapter.on_served(current_test, files_served)

            # check for results and report as necessary
            self.check_results(not files_served, server_status == sapphire.SERVED_TIMEOUT)

            # warn about large browser logs
            self.status.log_size = self.target.log_size()
            if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                log.warning("Large browser logs: %dMBs", (self.status.log_size / 0x100000))

            if self.coverage:
                self.target.dump_coverage()

            # trigger relaunch by closing the browser if needed
            self.target.check_relaunch()

            # all test cases have been replayed
            if not self.adapter.ROTATION_PERIOD and not self.iomanager.input_files:
                log.info("Replay Complete")
                break

            if iteration_limit is not None and self.status.iteration == iteration_limit:
                log.info("Hit iteration limit")
                break
