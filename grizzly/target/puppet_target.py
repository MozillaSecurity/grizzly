# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import logging
import os
import platform
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
    __slots__ = ("use_rr", "use_valgrind", "_puppet")

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch, **kwds):
        super(PuppetTarget, self).__init__(binary, extension, launch_timeout, log_limit,
                                           memory_limit, prefs, relaunch)
        self.use_rr = kwds.pop("rr", False)
        self.use_valgrind = kwds.pop("valgrind", False)
        use_xvfb = kwds.pop("xvfb", False)
        if kwds:
            log.warning("PuppetTarget ignoring unsupported arguments: %s", ", ".join(kwds))

        # create Puppet object
        self._puppet = FFPuppet(
            use_rr=self.use_rr,
            use_valgrind=self.use_valgrind,
            use_xvfb=use_xvfb)

    def _abort_hung_proc(self):
        # send SIGABRT to the busiest process
        with self._lock:
            proc_usage = self._puppet.cpu_usage()
        for pid, cpu in sorted(proc_usage, reverse=True, key=lambda x: x[1]):
            log.debug("sending SIGABRT to pid: %r, cpu: %0.2f%%", pid, cpu)
            os.kill(pid, signal.SIGABRT)
            break

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

    def is_idle(self, threshold):
        for _, cpu in self._puppet.cpu_usage():
            if cpu >= threshold:
                return False
        return True

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

    def detect_failure(self, ignored, was_timeout):
        status = self.RESULT_NONE
        if self.expect_close and not was_timeout:
            # give the browser a moment to close if needed
            self._puppet.wait(timeout=30)
        is_healthy = self._puppet.is_healthy()
        # check if there has been a crash, hang, etc...
        if not is_healthy or was_timeout:
            if self._puppet.is_running():
                log.debug("terminating browser...")
                if was_timeout and "timeout" not in ignored and platform.system() == "Linux":
                    self._abort_hung_proc()
                    # give the process a moment to start dump
                    self._puppet.wait(timeout=1)
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
            log.info("Timeout detected")
            status = self.RESULT_IGNORED if "timeout" in ignored else self.RESULT_FAILURE
        return status

    def dump_coverage(self, timeout=15):
        # Note: This is not required if the browser is going to close.
        # SIGTERM will also trigger coverage to be synced out.
        pid = self._puppet.get_pid()
        if pid is None or not self._puppet.is_healthy():
            log.debug("Skipping coverage dump")
            return
        # If at this point, the browser is in a good state, i.e. no crashes
        # or hangs, so signal the browser to dump coverage.
        try:
            for child in psutil.Process(pid).children(recursive=True):
                log.debug("Sending SIGUSR1 to %d (child)", child.pid)
                os.kill(child.pid, signal.SIGUSR1)
        except (psutil.AccessDenied, psutil.NoSuchProcess):  # pragma: no cover
            pass
        log.debug("Sending SIGUSR1 to %d (parent)", pid)
        os.kill(pid, signal.SIGUSR1)
        start_time = time.time()
        gcda_found = False
        delay = 0.1
        # wait for processes to write .gcno files
        # this should typically take less than 1 second
        while True:
            for proc in psutil.process_iter(attrs=["pid", "ppid", "open_files"]):
                # check if proc is the target or child process
                if pid in (proc.info["pid"], proc.info["ppid"]):
                    if proc.info["open_files"] is None:
                        continue
                    if any(x.path.endswith(".gcda") for x in proc.info["open_files"]):
                        gcda_found = True
                        # get the pid of the process that has the file open
                        gcda_open = proc.info["pid"]
                        break
            else:
                gcda_open = None
            elapsed = time.time() - start_time
            if gcda_found:
                if gcda_open is None:
                    # success
                    log.debug("gcda dump took %0.2fs", elapsed)
                    break
                if elapsed >= timeout:
                    # timeout failure
                    log.warning("gcda file open by pid %d after %0.2fs", gcda_open, elapsed)
                    break
            elif elapsed >= 5:
                # assume we missed the process writing .gcno files
                log.warning("No gcda files seen after %0.2fs", elapsed)
                break
            if not self._puppet.is_healthy():
                log.warning("Browser failure during dump_coverage()")
                break
            time.sleep(delay)
            if delay < 1.0:
                # increase delay to a maximum of 1 second
                delay = min(1.0, delay + 0.1)

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
            log.error("FFPuppet LaunchError: %s", str(exc))
            self.close()
            if isinstance(exc, BrowserTimeoutError):
                raise TargetLaunchTimeout(str(exc))
            raise TargetLaunchError(str(exc))

    def log_size(self):
        return self._puppet.log_length("stderr") + self._puppet.log_length("stdout")

    def save_logs(self, *args, **kwargs):
        self._puppet.save_logs(*args, **kwargs)
