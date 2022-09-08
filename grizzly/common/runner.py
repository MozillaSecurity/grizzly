# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from pathlib import Path
from time import sleep, time

from sapphire import Served, ServerMap

from ..target import Result, TargetLaunchError, TargetLaunchTimeout
from .storage import TestCase

__all__ = ("Runner", "RunResult")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class _IdleChecker:
    """_IdleChecker is used to help determine if the target is hung (actively using CPU)
    or if it has not made expected the HTTP requests for other reasons (idle).
    This will allow the framework to move on without interrupting execution of long
    running test cases.
    This is not perfect! It is to be used AFTER the test case timeout (initial_delay)
    has elapsed.
    """

    __slots__ = ("_check_cb", "_init_delay", "_poll_delay", "_threshold", "_next_poll")

    def __init__(self, check_cb, threshold, initial_delay, poll_delay=1):
        assert callable(check_cb)
        assert initial_delay >= 0
        assert poll_delay >= 0
        assert 100 > threshold >= 0
        self._check_cb = check_cb  # callback used to check if target is idle
        self._init_delay = initial_delay  # time to wait before the initial idle poll
        self._poll_delay = poll_delay  # time to wait between subsequent polls
        self._threshold = threshold  # CPU usage threshold
        self._next_poll = None

    def is_idle(self):
        """Check the target idle callback. This is throttled by '_next_poll'
        which specifies the time at which the next callback call is allowed.

        Args:
            None

        Returns:
            bool: True if the target idle callback returned True otherwise False
        """
        assert self._next_poll is not None, "schedule_poll() must be called first"
        now = time()
        if now >= self._next_poll:
            if self._check_cb(self._threshold):
                return True
            self.schedule_poll(now=now)
        return False

    def schedule_poll(self, initial=False, now=None):
        """Update `_next_poll`.

        Args:
            initial (int): Use `_init_delay` to schedule next poll
            now (int): time in seconds

        Returns:
            None
        """
        if now is None:
            now = time()
        if initial:
            self._next_poll = now + self._init_delay
        else:
            self._next_poll = now + self._poll_delay


class Runner:
    __slots__ = (
        "_close_delay",
        "_idle",
        "_relaunch",
        "_server",
        "_target",
        "_tests_run",
        "startup_failure",
    )

    def __init__(
        self, server, target, close_delay=30, idle_threshold=0, idle_delay=0, relaunch=1
    ):
        self._close_delay = close_delay
        if idle_threshold > 0:
            assert idle_delay > 0
            LOG.debug("using idle check, th %d, delay %ds", idle_threshold, idle_delay)
            self._idle = _IdleChecker(target.is_idle, idle_threshold, idle_delay)
        else:
            self._idle = None
        assert close_delay > 0
        assert relaunch > 0
        self._relaunch = relaunch  # tests to run before relaunching target
        self._server = server  # a sapphire instance to serve the test case
        self._target = target  # target to run test case
        self._tests_run = 0  # number of tests run since target (re)launched
        self.startup_failure = False  # failure before first test was served

    def launch(self, location, max_retries=3, retry_delay=0):
        """Launch a target and open `location`.

        Args:
            location (str): URL to open via Target.
            max_retries (int): Number of retries to perform before re-raising
                               TargetLaunchTimeout.
            retry_delay (int): Time in seconds to wait between retries.

        Returns:
            None
        """
        assert self._server is not None
        assert self._target is not None
        assert max_retries >= 0
        assert retry_delay >= 0
        self._server.clear_backlog()
        self._tests_run = 0
        self.startup_failure = False
        LOG.debug("launching target (timeout %ds)", self._target.launch_timeout)
        for retries in reversed(range(max_retries)):
            try:
                self._target.launch(location)
            except TargetLaunchError as exc:
                # This is likely due to a bad build or environment configuration.
                if retries:
                    LOG.warning("Failure detected during launch (retries %d)", retries)
                    exc.report.cleanup()
                    sleep(retry_delay)
                    continue
                self.startup_failure = True
                raise
            except TargetLaunchTimeout:
                # A TargetLaunchTimeout likely has nothing to do with Grizzly but is
                # seen frequently on machines under a high load. After multiple
                # consecutive timeouts something is likely wrong so raise.
                if retries:
                    LOG.warning("Timeout detected during launch (retries %d)", retries)
                    sleep(retry_delay)
                    continue
                self.startup_failure = True
                raise
            break

    @staticmethod
    def location(
        srv_path, srv_port, close_after=None, post_launch_delay=None, time_limit=None
    ):
        """Build a valid URL to pass to a browser.

        Args:
            srv_path (str): Path segment of the URL
            srv_port (int): Server listening port
            close_after (int): Harness argument.
            post_launch_delay (int): Post-launch delay page argument.
            time_limit (int): Harness argument.

        Returns:
            str: A valid URL.
        """
        location = "http://127.0.0.1:%d/%s" % (srv_port, srv_path.lstrip("/"))
        # set harness related arguments
        args = []
        if close_after is not None:
            assert close_after >= 0
            args.append("close_after=%d" % (close_after,))
        if time_limit:
            assert time_limit > 0
            args.append("time_limit=%d" % (time_limit * 1000,))
        if post_launch_delay is not None:
            assert post_launch_delay >= 0
            args.append("post_launch_delay=%d" % (post_launch_delay,))
        if args:
            return "?".join((location, "&".join(args)))
        return location

    @property
    def initial(self):
        """Check if more than one test has been run since the previous relaunch.

        Args:
            None

        Returns:
            bool: True if at most one test has been run.
        """
        return self._tests_run < 2

    def post_launch(self, delay=None):
        """Perform actions after launching browser before loading test cases.

        Args:
            post_launch_delay (int): Amount of time in seconds before the target will
                                     redirect to test case.

        Returns:
            None
        """
        if delay is not None and not self.startup_failure:
            assert delay >= 0
            with TestCase("post_launch_delay.html", None, "None") as content:
                content.add_from_file(
                    Path(__file__).parent / "post_launch_delay.html",
                    content.landing_page,
                    copy=True,
                )
                srv_map = ServerMap()
                srv_map.set_redirect("grz_start", content.landing_page, required=False)
                srv_map.set_redirect("grz_continue", "grz_start", required=True)
                # temporarily disable server timeout
                srv_timeout = self._server.timeout
                self._server.timeout = 0
                LOG.info("Browser launched, continuing in %ds...", delay)
                # serve prompt page
                self._server.serve_path(
                    content.data_path,
                    continue_cb=self._target.monitor.is_healthy,
                    server_map=srv_map,
                )
                # re-enable server timeout
                self._server.timeout = srv_timeout

    def run(
        self,
        ignore,
        server_map,
        testcase,
        coverage=False,
        wait_for_callback=False,
    ):
        """Serve a testcase and monitor the target for results.

        Args:
            ignore (list): List of failure types to ignore.
            server_map (sapphire.ServerMap): A ServerMap.
            testcase (grizzly.TestCase): The test case that will be served.
            coverage (bool): Trigger coverage dump.
            wait_for_callback (bool): Use `_keep_waiting()` to indicate when
                                      framework should move on.

        Returns:
            RunResult: Files served, status and timeout flag from the run.
        """
        self._tests_run += 1
        if self._idle is not None:
            self._idle.schedule_poll(initial=True)
        if self._tests_run == self._relaunch:
            # overwrite instead of replace 'grz_next_test' for consistency
            server_map.set_redirect("grz_next_test", "grz_empty", required=True)
            server_map.set_dynamic_response("grz_empty", lambda _: b"", required=True)
        # serve the test case
        serve_start = time()
        server_status, served = self._server.serve_path(
            testcase.data_path,
            continue_cb=self._keep_waiting,
            forever=wait_for_callback,
            optional_files=tuple(testcase.optional),
            server_map=server_map,
        )
        duration = time() - serve_start
        result = RunResult(
            served,
            duration,
            attempted=testcase.landing_page in served,
            timeout=server_status == Served.TIMEOUT,
        )
        # TODO: fix calling TestCase.add_batch() for multi-test replay
        # add all include files that were served
        for url, resource in server_map.include.items():
            testcase.add_batch(
                resource.target,
                # only pass files that appear to be in current include path
                (x for x in result.served if x.startswith(resource.target)),
                prefix=url,
            )
        if result.timeout:
            LOG.debug("timeout detected")
            if self._target.handle_hang(ignore_idle=True) or "timeout" in ignore:
                result.status = Result.IGNORED
            server_map.dynamic.pop("grz_empty", None)
        if result.attempted:
            if coverage and not result.timeout:
                # dump_coverage() should be called before check_result()
                # to help catch any coverage related issues.
                self._target.dump_coverage()
            # relaunch check
            if self._tests_run >= self._relaunch and not result.timeout:
                assert self._tests_run == self._relaunch
                server_map.dynamic.pop("grz_empty", None)
                LOG.debug("relaunch/shutdown limit hit")
                # ideally all browser tabs should be closed at this point
                # and the browser should exit on its own
                # NOTE: this will take the full duration if target.is_idle()
                # is not implemented
                for close_delay in range(max(int(self._close_delay / 0.5), 1)):
                    if not self._target.monitor.is_healthy():
                        break
                    # wait 3 seconds (6 passes) before attempting idle exit
                    if close_delay > 5 and self._target.is_idle(10):
                        # NOTE: this will always trigger on systems where the
                        # browser does not exit when the last window is closed
                        LOG.debug("target idle")
                        break
                    # delay to help catch shutdown related crashes, LSan, etc.
                    # debugger and different builds can slow shutdown
                    sleep(0.5)
                else:
                    LOG.debug("target.close() required")
                self._target.close()
        else:
            # something is wrong so close the target
            # previous iteration put target in a bad state?
            LOG.debug("landing page %r not served!", testcase.landing_page)
            self._target.close()
            # detect startup failures
            if self.initial:
                self.startup_failure = True
        # detect results
        if result.status == Result.NONE:
            result.status = self._target.check_result(ignore)
        return result

    def _keep_waiting(self):
        """Callback used by the server to determine if it should continue to
        wait for the requests from the target.

        Args:
            None

        Returns:
            bool: Continue to serve the test case.
        """
        if self._idle is not None and self._idle.is_idle():
            LOG.debug("idle target detected")
            return False
        return self._target.monitor.is_healthy()


class RunResult:
    """A RunResult holds result details from a call to Runner.run().

    Attributes:
        attempted (bool): Test landing page (entry point) was requested.
        duration (float): Time spent waiting for test contents to be served.
        served (tuple(str)): Files that were served.
        status (int): Result status of test.
        timeout (bool): A timeout occurred waiting for test to complete.
    """

    __slots__ = ("attempted", "duration", "served", "status", "timeout")

    def __init__(
        self, served, duration, attempted=False, status=Result.NONE, timeout=False
    ):
        self.attempted = attempted
        self.duration = duration
        self.served = served
        self.status = status
        self.timeout = timeout
