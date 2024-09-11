# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from dataclasses import dataclass
from logging import getLogger
from pathlib import Path
from time import perf_counter, sleep
from typing import Callable

from sapphire import Sapphire, Served, ServerMap

from ..target import Result, Target, TargetLaunchError, TargetLaunchTimeout
from .storage import TestCase

__all__ = ("Runner", "RunResult")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)
# time in seconds to wait for target to navigate away from post launch page
POST_LAUNCH_TIMEOUT = 600
# display warning if launch duration exceeds set value
SLOW_LAUNCH_THRESHOLD = 20


class _IdleChecker:
    """_IdleChecker is used to help determine if the target is hung (actively using CPU)
    or if it has not made expected the HTTP requests for other reasons (idle).
    This will allow the framework to move on without interrupting execution of long
    running test cases.
    This is not perfect! It is to be used AFTER the test case timeout (initial_delay)
    has elapsed.
    """

    __slots__ = ("_check_cb", "_init_delay", "_poll_delay", "_threshold", "_next_poll")

    def __init__(
        self,
        check_cb: Callable[[int], bool],
        threshold: int,
        initial_delay: int,
        poll_delay: float = 1,
    ) -> None:
        assert callable(check_cb)
        assert initial_delay >= 0
        assert poll_delay >= 0
        assert 100 > threshold >= 0
        self._check_cb = check_cb  # callback used to check if target is idle
        self._init_delay = initial_delay  # time to wait before the initial idle poll
        self._poll_delay = poll_delay  # time to wait between subsequent polls
        self._threshold = threshold  # CPU usage threshold
        self._next_poll: float | None = None

    def is_idle(self) -> bool:
        """Check the target idle callback. This is throttled by '_next_poll'
        which specifies the time at which the next callback call is allowed.

        Args:
            None

        Returns:
            True if the target idle callback returned True otherwise False
        """
        assert self._next_poll is not None, "schedule_poll() must be called first"
        now = perf_counter()
        if now >= self._next_poll:
            if self._check_cb(self._threshold):
                return True
            self.schedule_poll(now=now)
        return False

    def schedule_poll(self, initial: int = False, now: float | None = None) -> None:
        """Update `_next_poll`.

        Args:
            initial: Use `_init_delay` to schedule next poll.
            now: Time in seconds.

        Returns:
            None
        """
        if now is None:
            now = perf_counter()
        if initial:
            self._next_poll = now + self._init_delay
        else:
            self._next_poll = now + self._poll_delay


@dataclass(eq=False)
class RunResult:
    """A RunResult holds result details from a call to Runner.run().

    Attributes:
        attempted: Test entry point was requested.
        duration: Time spent waiting for test contents to be served.
        served: Files that were served.
        status: Result status of test.
        timeout: A timeout occurred waiting for test to complete.
        idle: Target was idle (only applies to timeout).
    """

    served: tuple[str, ...]
    duration: float
    attempted: bool = False
    status: Result = Result.NONE
    timeout: bool = False
    idle: bool = False


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
        self,
        server: Sapphire,
        target: Target,
        close_delay: int = 30,
        idle_threshold: int = 0,
        idle_delay: int = 0,
        relaunch: int = 1,
    ) -> None:
        self._close_delay = close_delay
        if idle_threshold > 0:
            assert idle_delay > 0
            LOG.debug("using idle check, th %d, delay %ds", idle_threshold, idle_delay)
            self._idle: _IdleChecker | None = _IdleChecker(
                target.monitor.is_idle, idle_threshold, idle_delay
            )
        else:
            self._idle = None
        assert close_delay > 0
        assert relaunch > 0
        self._relaunch = relaunch  # tests to run before relaunching target
        self._server = server  # a sapphire instance to serve the test case
        self._target = target  # target to run test case
        self._tests_run = 0  # number of tests run since target (re)launched
        self.startup_failure = False  # failure before first test was served

    def launch(self, location: str, max_retries: int = 3, retry_delay: int = 0) -> None:
        """Launch a target and open `location`.

        Args:
            location: URL to open via Target.
            max_retries: Number of retries to perform before re-raising
                         TargetLaunchTimeout.
            retry_delay: Time in seconds to wait between retries.

        Returns:
            None
        """
        assert self._server is not None
        assert self._target is not None
        assert max_retries >= 0
        assert retry_delay >= 0
        # nothing should be trying to connect, did the previous target.close() fail?
        assert self._server.clear_backlog()
        self._tests_run = 0
        self.startup_failure = False
        launch_duration: float = 0
        LOG.debug("launching target (timeout %ds)", self._target.launch_timeout)
        for retries in reversed(range(max_retries)):
            try:
                launch_start = perf_counter()
                self._target.launch(location)
                launch_duration = perf_counter() - launch_start
            except (TargetLaunchError, TargetLaunchTimeout) as exc:
                is_timeout = isinstance(exc, TargetLaunchTimeout)
                if not retries:
                    self.startup_failure = True
                    msg = "timeout" if is_timeout else "failed"
                    LOG.error(
                        "Launch %s, please verify browser build works as expected", msg
                    )
                    raise
                if is_timeout:
                    # A TargetLaunchTimeout likely has nothing to do with Grizzly but is
                    # seen frequently on machines under a high load. After multiple
                    # consecutive timeouts something is likely wrong so raise.
                    LOG.warning("Timeout during launch (retries %d)", retries)
                else:
                    assert isinstance(exc, TargetLaunchError)
                    # This is likely due to a bad build or environment configuration.
                    LOG.warning("Failure during launch (retries %d)", retries)
                    exc.report.cleanup()
                sleep(retry_delay)
                continue
            break

        if launch_duration > SLOW_LAUNCH_THRESHOLD:
            LOG.warning(
                "Slow launch detected (%0.1fs > %ds)",
                launch_duration,
                SLOW_LAUNCH_THRESHOLD,
            )

    @staticmethod
    def location(
        srv_path: str,
        srv_port: int,
        close_after: int | None = None,
        post_launch_delay: int = -1,
        scheme: str = "http",
        time_limit: int | None = None,
    ) -> str:
        """Build a valid URL to pass to a browser.

        Args:
            srv_path: Path segment of the URL
            srv_port: Server listening port
            close_after: Harness argument.
            post_launch_delay: Post-launch delay page argument.
            scheme: URL scheme component (http or https).
            time_limit: Harness argument.

        Returns:
            A valid URL.
        """
        location = f"{scheme}://localhost:{srv_port}/{srv_path.lstrip('/')}"
        # set harness related arguments
        args = []
        if close_after is not None:
            assert close_after >= 0
            args.append(f"close_after={close_after}")
        if time_limit:
            assert time_limit > 0
            args.append(f"time_limit={time_limit * 1000}")
        if post_launch_delay >= 0:
            args.append(f"post_launch_delay={post_launch_delay}")
        if args:
            return "?".join((location, "&".join(args)))
        return location

    @property
    def initial(self) -> bool:
        """Check if more than one test has been run since the previous target launch.

        Args:
            None

        Returns:
            True if at most one test has been run.
        """
        return self._tests_run < 2

    def post_launch(self, delay: int = 0) -> None:
        """Perform actions after launching browser before loading test cases.

        Args:
            delay: Time in seconds before the target will continue.

        Returns:
            None
        """
        assert delay >= 0
        with TestCase("post_launch_delay.html", "None") as content:
            content.add_from_file(
                Path(__file__).parent / "post_launch_delay.html",
                file_name=content.entry_point,
                copy=True,
            )
            srv_map = ServerMap()
            srv_map.set_redirect("grz_start", content.entry_point, required=False)
            srv_map.set_redirect("grz_continue", "grz_start", required=True)
            # temporarily override server timeout
            org_timeout = self._server.timeout
            # add time buffer to redirect delay
            # in practice this should take a few seconds (~10s)
            # in extreme cases ~180s (slow build + debugger + other settings)
            self._server.timeout = delay + POST_LAUNCH_TIMEOUT
            if delay > 0:
                LOG.info("Browser launched, continuing in %ds...", delay)
            LOG.debug("post launch timeout: %ds", self._server.timeout)
            # serve prompt page
            server_status, _ = self._server.serve_path(
                content.root,
                continue_cb=self._target.monitor.is_healthy,
                server_map=srv_map,
            )
            # restore server timeout
            self._server.timeout = org_timeout
            if server_status != Served.ALL:
                self.startup_failure = True
                if server_status == Served.TIMEOUT:
                    # this should never happen with a correctly functioning build
                    LOG.warning("Target hung after launch")
                LOG.warning("Post launch check failed!")

    def run(
        self,
        ignore: set[str],
        server_map: ServerMap,
        testcase: TestCase,
        coverage: bool = False,
        wait_for_callback: bool = False,
    ) -> RunResult:
        """Serve a testcase and monitor the target for results.

        Args:
            ignore: Failure types to ignore.
            server_map: A ServerMap.
            testcase: The test case that will be served.
            coverage: Trigger coverage dump.
            wait_for_callback: Use `_keep_waiting()` to indicate when framework
                               should move on.

        Returns:
            Files served, status and timeout flag from the run.
        """
        self._tests_run += 1
        if self._idle is not None:
            self._idle.schedule_poll(initial=True)
        if self._tests_run == self._relaunch:
            # overwrite instead of replace 'grz_next_test' for consistency
            server_map.set_redirect("grz_next_test", "grz_empty", required=True)
            server_map.set_dynamic_response("grz_empty", lambda _: b"", required=True)
        # clear optional contents from test case
        # it will be repopulated with served contests
        testcase.clear_optional()
        # serve the test case
        serve_start = perf_counter()
        server_status, served = self._server.serve_path(
            testcase.root,
            continue_cb=self._keep_waiting,
            forever=wait_for_callback,
            required_files=tuple(testcase.required),
            server_map=server_map,
        )
        duration = perf_counter() - serve_start
        result = RunResult(
            tuple(served),
            duration,
            attempted=testcase.entry_point in served,
            timeout=server_status == Served.TIMEOUT,
        )
        # add all files that were served (includes, etc...) to test
        existing = set(testcase.required)
        for url, local_file in served.items():
            if url not in existing:
                # copy include files
                testcase.add_from_file(local_file, file_name=url, copy=True)
        # record use of https in testcase
        testcase.https = self._server.scheme == "https"
        if result.timeout:
            LOG.debug("timeout detected")
            result.idle = self._target.handle_hang(
                ignore_idle=True, ignore_timeout="timeout" in ignore
            )
            if result.idle or "timeout" in ignore:
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
                # NOTE: this will take the full duration if target.monitor.is_idle()
                # is unable to detect if the target is idle
                for close_delay in range(max(int(self._close_delay / 0.5), 1)):
                    if not self._target.monitor.is_healthy():
                        break
                    # wait 3 seconds (6 passes) before attempting idle exit
                    if close_delay > 5 and self._target.monitor.is_idle(10):
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
            LOG.debug("entry point not served (%r)", testcase.entry_point)
            self._target.close()
            # detect startup failures
            if self.initial:
                self.startup_failure = True
        # detect results
        if result.status == Result.NONE:
            result.status = self._target.check_result(ignore)
        return result

    def _keep_waiting(self) -> bool:
        """Callback used by the server to determine if it should continue to
        wait for the requests from the target.

        Args:
            None

        Returns:
            Continue to serve the test case.
        """
        if self._idle is not None and self._idle.is_idle():
            LOG.debug("idle target detected")
            return False
        return self._target.monitor.is_healthy()
