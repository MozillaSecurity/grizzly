# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import logging
import os
import signal
import time

import psutil

from ffpuppet import BrowserTimeoutError, FFPuppet, LaunchError
from .target_monitor import TargetMonitor
from .target import Target, TargetLaunchError, TargetLaunchTimeout, TargetError

__all__ = ("PuppetTarget",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


class PuppetTarget(Target):
    PUPPET = FFPuppet  # used in unit tests

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch, **kwds):
        super(PuppetTarget, self).__init__(binary, extension, launch_timeout, log_limit,
                                           memory_limit, prefs, relaunch)
        self.use_rr = kwds.pop("rr", False)
        self.use_valgrind = kwds.pop("valgrind", False)
        use_xvfb = kwds.pop("xvfb", False)
        if kwds:
            log.warning("PuppetTarget ignoring unsupported arguments: %s", ", ".join(kwds))

        # create Puppet object
        self._puppet = self.PUPPET(
            use_rr=self.use_rr,
            use_valgrind=self.use_valgrind,
            use_xvfb=use_xvfb)

    def add_abort_token(self, token):
        self._puppet.add_abort_token(token)

    def cleanup(self):
        # prevent parallel calls to FFPuppet.clean_up()
        with self._lock:
            self._puppet.clean_up()

    def close(self):
        # prevent parallel calls to FFPuppet.close()
        with self._lock:
            self._puppet.close()

    @property
    def closed(self):
        return self._puppet.reason is not None

    @property
    def monitor(self):
        if self._monitor is None:
            class _PuppetMonitor(TargetMonitor):
                # pylint: disable=no-self-argument,protected-access
                def clone_log(_, log_id, offset=0):
                    return self._puppet.clone_log(log_id, offset=offset)
                def is_running(_):
                    return self._puppet.is_running()
                def is_healthy(_):
                    return self._puppet.is_healthy()
                @property
                def launches(_):
                    return self._puppet.launches
                def log_length(_, log_id):
                    return self._puppet.log_length(log_id)
            self._monitor = _PuppetMonitor()
        return self._monitor

    def poll_for_idle(self, threshold, interval):
        # return POLL_IDLE if cpu usage of target is below threshold for interval seconds
        start_time = time.time()
        while time.time() - start_time < interval:
            for _, cpu in self._puppet.cpu_usage():
                if cpu >= threshold:
                    return self.POLL_BUSY
            if not self._puppet.is_running():
                break
        else:
            log.info("Process utilized <= %d%% CPU for %ds", threshold, interval)
        return self.POLL_IDLE

    def detect_failure(self, ignored, was_timeout):
        status = self.RESULT_NONE
        if self.expect_close and not was_timeout:
            # give the browser a moment to close if needed
            self._puppet.wait(timeout=30)
        is_healthy = self._puppet.is_healthy()
        # check if there has been a crash, hang, etc...
        if not is_healthy or was_timeout:
            if self._puppet.is_running():
                log.info("Terminating browser...")
            self.close()
        # if something has happened figure out what
        if not is_healthy:
            if self._puppet.reason == FFPuppet.RC_CLOSED:
                log.info("target.close() was called")
            elif self._puppet.reason == FFPuppet.RC_EXITED:
                log.info("Target closed itself")
            elif (self._puppet.reason == FFPuppet.RC_WORKER
                  and "memory" in ignored
                  and "ffp_worker_memory_usage" in self._puppet.available_logs()):
                status = self.RESULT_IGNORED
                log.info("Memory limit exceeded")
            elif (self._puppet.reason == FFPuppet.RC_WORKER
                  and "log-limit" in ignored
                  and "ffp_worker_log_size" in self._puppet.available_logs()):
                status = self.RESULT_IGNORED
                log.info("Log size limit exceeded")
            else:
                log.debug("failure detected, ffpuppet return code: %r", self._puppet.reason)
                status = self.RESULT_FAILURE
        elif was_timeout:
            log.debug("timeout detected, potential browser hang")
            if ignored and "timeout" in ignored:
                status = self.RESULT_IGNORED
                log.info("Timed out")
            else:
                status = self.RESULT_FAILURE
        return status

    def dump_coverage(self):
        # If at this point, the browser is running, i.e. we did neither
        # relaunch nor crash/timeout, then we need to signal the browser
        # to dump coverage before attempting a new test that potentially
        # crashes.
        # Note: This is not required if we closed or are going to close
        # the browser (relaunch or done with all iterations) because the
        # SIGTERM will also trigger coverage to be synced out.
        pid = self._puppet.get_pid()
        if pid is None or not self._puppet.is_running():
            log.debug("Could not dump coverage because process is not running")
            return
        try:
            for child in psutil.Process(pid).children(recursive=True):
                log.debug("Sending SIGUSR1 to %d", child.pid)
                os.kill(child.pid, signal.SIGUSR1)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        log.debug("Sending SIGUSR1 to %d", pid)
        os.kill(pid, signal.SIGUSR1)

    def launch(self, location, env_mod=None):
        if not self.prefs:
            raise TargetError("A prefs.js file is required")
        self.rl_countdown = self.rl_reset
        env_mod = dict(env_mod or [])
        # do not allow network connections to non local endpoints
        env_mod["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1"
        env_mod["MOZ_CRASHREPORTER_SHUTDOWN"] = "1"
        try:
            self._puppet.launch(
                self.binary,
                launch_timeout=self.launch_timeout,
                location=location,
                log_limit=self.log_limit,
                memory_limit=self.memory_limit,
                prefs_js=self.prefs,
                extension=self.extension,
                env_mod=env_mod)
        except LaunchError as exc:
            log.error("FFPuppet Error: %s", str(exc))
            self.close()
            if isinstance(exc, BrowserTimeoutError):
                raise TargetLaunchTimeout(str(exc))
            raise TargetLaunchError(str(exc))

    def log_size(self):
        return self._puppet.log_length("stderr") + self._puppet.log_length("stdout")

    def save_logs(self, *args, **kwargs):
        self._puppet.save_logs(*args, **kwargs)
