# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from os import close, getenv, kill, makedirs, unlink
from os.path import isdir, isfile
from platform import system
import signal
from time import localtime, sleep, strftime, time
from tempfile import mkdtemp, mkstemp

from psutil import AccessDenied, NoSuchProcess, Process, process_iter

from ffpuppet import BrowserTimeoutError, FFPuppet, LaunchError
from prefpicker import PrefPicker

from .target_monitor import TargetMonitor
from .target import Target, TargetLaunchError, TargetLaunchTimeout, TargetError
from ..common.utils import grz_tmp


__all__ = ("PuppetTarget",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger("puppet_target")


class PuppetTarget(Target):
    __slots__ = ("use_rr", "use_valgrind", "_browser_logs", "_puppet", "_tmp_prefs")

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch, **kwds):
        super(PuppetTarget, self).__init__(binary, extension, launch_timeout, log_limit,
                                           memory_limit, prefs, relaunch)
        self.use_rr = kwds.pop("rr", False)
        self.use_valgrind = kwds.pop("valgrind", False)
        use_xvfb = kwds.pop("xvfb", False)
        if kwds:
            LOG.warning("PuppetTarget ignoring unsupported arguments: %s", ", ".join(kwds))
        self._browser_logs = None
        # generate prefs.js file if needed
        if self.prefs is None:
            for prefs_template in PrefPicker.templates():
                if prefs_template.endswith("browser-fuzzing.yml"):
                    LOG.debug("using prefpicker template %r", prefs_template)
                    tmp_fd, self.prefs = mkstemp(prefix="prefs_", suffix=".js", dir=grz_tmp())
                    close(tmp_fd)
                    PrefPicker.load_template(prefs_template).create_prefsjs(self.prefs)
                    LOG.debug("generated prefs.js %r", self.prefs)
                    break
            else:  # pragma: no cover
                raise TargetError("Failed to generate prefs.js")
            self._tmp_prefs = True
        else:
            self._tmp_prefs = False
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
            LOG.debug("sending SIGABRT to pid: %r, cpu: %0.2f%%", pid, cpu)
            kill(pid, signal.SIGABRT)
            break

    def add_abort_token(self, token):
        self._puppet.add_abort_token(token)

    def cleanup(self):
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        if self._browser_logs:
            self.close()
        with self._lock:
            self._puppet.clean_up()
        if self._tmp_prefs and isfile(self.prefs):
            unlink(self.prefs)

    def close(self):
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.close()
            # save logs in lock to avoid a parallel clean_up() removing them
            if self._browser_logs:
                log_path = mkdtemp(
                    prefix=strftime("%Y%m%d-%H%M%S_", localtime()),
                    suffix="_browser_logs",
                    dir=self._browser_logs)
                LOG.debug("saving browser logs to %r", log_path)
                self._puppet.save_logs(log_path)
                # only save logs once per launch
                self._browser_logs = None

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
                LOG.debug("terminating browser...")
                if was_timeout and "timeout" not in ignored and system() == "Linux":
                    self._abort_hung_proc()
                    # give the process a moment to start dump
                    self._puppet.wait(timeout=1)
            self.close()
        # if something has happened figure out what
        if not is_healthy:
            if self._puppet.reason == FFPuppet.RC_CLOSED:
                LOG.info("target.close() was called")
            elif self._puppet.reason == FFPuppet.RC_EXITED:
                LOG.info("Target closed itself")
            elif (self._puppet.reason == FFPuppet.RC_WORKER
                  and "memory" in ignored
                  and "ffp_worker_memory_usage" in self._puppet.available_logs()):
                status = self.RESULT_IGNORED
                LOG.info("Memory limit exceeded")
            elif (self._puppet.reason == FFPuppet.RC_WORKER
                  and "log-limit" in ignored
                  and "ffp_worker_log_size" in self._puppet.available_logs()):
                status = self.RESULT_IGNORED
                LOG.info("Log size limit exceeded")
            else:
                LOG.debug("failure detected, ffpuppet return code: %r", self._puppet.reason)
                status = self.RESULT_FAILURE
        elif was_timeout:
            LOG.info("Timeout detected")
            status = self.RESULT_IGNORED if "timeout" in ignored else self.RESULT_FAILURE
        return status

    def dump_coverage(self, timeout=15):
        pid = self._puppet.get_pid()
        if pid is None or not self._puppet.is_healthy():
            LOG.debug("Skipping coverage dump (target is not in a good state)")
            return
        # If at this point, the browser is in a good state, i.e. no crashes
        # or hangs, so signal the browser to dump coverage.
        try:
            for child in Process(pid).children(recursive=True):
                LOG.debug("Sending SIGUSR1 to %d (child)", child.pid)
                kill(child.pid, signal.SIGUSR1)
        except (AccessDenied, NoSuchProcess):  # pragma: no cover
            pass
        LOG.debug("Sending SIGUSR1 to %d (parent)", pid)
        kill(pid, signal.SIGUSR1)
        start_time = time()
        gcda_found = False
        delay = 0.1
        # wait for processes to write .gcno files
        # this should typically take less than 1 second
        while True:
            for proc in process_iter(attrs=["pid", "ppid", "open_files"]):
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
            elapsed = time() - start_time
            if gcda_found:
                if gcda_open is None:
                    # success
                    LOG.debug("gcda dump took %0.2fs", elapsed)
                    break
                if elapsed >= timeout:
                    # timeout failure
                    LOG.warning("gcda file open by pid %d after %0.2fs", gcda_open, elapsed)
                    kill(gcda_open, signal.SIGABRT)
                    sleep(1)
                    self.close()
                    break
                if delay < 1.0:
                    # increase delay to a maximum of 1 second
                    delay = min(1.0, delay + 0.1)
            elif elapsed >= 3:
                # assume we missed the process writing .gcno files
                LOG.warning("No gcda files seen after %0.2fs", elapsed)
                break
            if not self._puppet.is_healthy():
                LOG.warning("Browser failure during dump_coverage()")
                break
            sleep(delay)

    def launch(self, location, env_mod=None):
        # GRZ_BROWSER_LOGS is intended to be used to aid in debugging.
        # when close() is called a copy of the browser logs will be saved
        # to the directory specified by GRZ_BROWSER_LOGS
        self._browser_logs = getenv("GRZ_BROWSER_LOGS")
        if self._browser_logs and not isdir(self._browser_logs):
            makedirs(self._browser_logs)
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
            LOG.error("FFPuppet LaunchError: %s", str(exc))
            self.close()
            if isinstance(exc, BrowserTimeoutError):
                raise TargetLaunchTimeout(str(exc))
            raise TargetLaunchError(str(exc))

    def log_size(self):
        return self._puppet.log_length("stderr") + self._puppet.log_length("stdout")

    def save_logs(self, *args, **kwargs):
        self._puppet.save_logs(*args, **kwargs)
