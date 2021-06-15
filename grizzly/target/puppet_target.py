# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from os import close, kill, unlink
from os.path import abspath, isfile
from platform import system
from signal import SIGABRT

try:
    from signal import SIGUSR1
except ImportError:
    SIGUSR1 = None
from tempfile import mkdtemp, mkstemp
from time import sleep, time

from ffpuppet import BrowserTimeoutError, Debugger, FFPuppet, LaunchError, Reason
from prefpicker import PrefPicker
from psutil import AccessDenied, NoSuchProcess, Process, process_iter

from ..common.reporter import Report
from ..common.utils import grz_tmp
from .target import Target, TargetError, TargetLaunchError, TargetLaunchTimeout
from .target_monitor import TargetMonitor

__all__ = ("PuppetTarget",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


class PuppetTarget(Target):
    __slots__ = ("use_valgrind", "_puppet", "_remove_prefs")

    def __init__(
        self, binary, extension, launch_timeout, log_limit, memory_limit, **kwds
    ):
        super().__init__(binary, extension, launch_timeout, log_limit, memory_limit)
        # TODO: clean up handling debuggers
        debugger = Debugger.NONE
        if kwds.pop("pernosco", False):
            debugger = Debugger.PERNOSCO
        if kwds.pop("rr", False):
            debugger = Debugger.RR
        if kwds.pop("valgrind", False):
            self.use_valgrind = True
            debugger = Debugger.VALGRIND
        self._remove_prefs = False

        # create Puppet object
        self._puppet = FFPuppet(
            debugger=debugger,
            use_xvfb=kwds.pop("xvfb", False),
            working_path=grz_tmp("target_ffpuppet"),
        )
        if kwds:
            LOG.warning(
                "PuppetTarget ignoring unsupported arguments: %s", ", ".join(kwds)
            )

    def add_abort_token(self, token):
        self._puppet.add_abort_token(token)

    def cleanup(self):
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.clean_up()
        if self._remove_prefs and self._prefs and isfile(self._prefs):
            unlink(self._prefs)

    def close(self, force_close=False):
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.close(force_close=force_close)

    @property
    def closed(self):
        return self._puppet.reason is not None

    def is_idle(self, threshold):
        for _, cpu in self._puppet.cpu_usage():
            if cpu >= threshold:
                return False
        return True

    def create_report(self, is_hang=False):
        logs = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
        self.save_logs(logs)
        return Report(logs, self.binary, is_hang=is_hang)

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

    def detect_failure(self, ignored):
        status = self.RESULT_NONE
        # check if there has been a crash, hangs will appear as SIGABRT
        if not self._puppet.is_healthy():
            self.close()
            # something has happened figure out what
            if self._puppet.reason == Reason.CLOSED:
                LOG.debug("target.close() was called")
            elif self._puppet.reason == Reason.EXITED:
                LOG.debug("target closed itself")
            elif (
                self._puppet.reason == Reason.WORKER
                and "memory" in ignored
                and "ffp_worker_memory_usage" in self._puppet.available_logs()
            ):
                status = self.RESULT_IGNORED
                LOG.debug("memory limit exceeded")
            elif (
                self._puppet.reason == Reason.WORKER
                and "log-limit" in ignored
                and "ffp_worker_log_size" in self._puppet.available_logs()
            ):
                status = self.RESULT_IGNORED
                LOG.debug("log size limit exceeded")
            else:
                # crash or hang (forced SIGABRT) has been detected
                LOG.debug("failure detected, ffpuppet %s", self._puppet.reason)
                status = self.RESULT_FAILURE
        return status

    def handle_hang(self, ignore_idle=True):
        was_idle = False
        if self._puppet.is_healthy():
            proc_usage = sorted(self._puppet.cpu_usage(), key=lambda x: x[1])
            if proc_usage:
                pid, cpu = proc_usage.pop()
                if ignore_idle and cpu < 15:
                    # don't send SIGABRT if process is idle
                    LOG.debug("ignoring idle hang (%0.1f%%)", cpu)
                    was_idle = True
                elif system() == "Linux":
                    # sending SIGABRT is only supported on Linux for now
                    # TODO: add/test on other OSs
                    LOG.debug("sending SIGABRT to %r (%0.1f%%)", pid, cpu)
                    try:
                        kill(pid, SIGABRT)
                    except OSError:
                        LOG.warning("Failed to send SIGABRT to pid %d", pid)
                    self._puppet.wait(timeout=10)
        # always call close() since this function should only/always
        # be called when there has been a timeout
        self.close()
        return was_idle

    def dump_coverage(self, timeout=15):
        assert SIGUSR1 is not None
        pid = self._puppet.get_pid()
        if pid is None or not self._puppet.is_healthy():
            LOG.debug("Skipping coverage dump (target is not in a good state)")
            return
        # If at this point, the browser is in a good state, i.e. no crashes
        # or hangs, so signal the browser to dump coverage.
        try:
            for child in Process(pid).children(recursive=True):
                LOG.debug("Sending SIGUSR1 to %d (child)", child.pid)
                try:
                    kill(child.pid, SIGUSR1)
                except OSError:
                    LOG.warning("Failed to send SIGUSR1 to pid %d", child.pid)
        except (AccessDenied, NoSuchProcess):  # pragma: no cover
            pass
        LOG.debug("Sending SIGUSR1 to %d (parent)", pid)
        try:
            kill(pid, SIGUSR1)
        except OSError:
            LOG.warning("Failed to send SIGUSR1 to pid %d", pid)
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
                    LOG.warning(
                        "gcda file open by pid %d after %0.2fs", gcda_open, elapsed
                    )
                    try:
                        kill(gcda_open, SIGABRT)
                    except OSError:
                        pass
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
        # setup environment
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
                env_mod=env_mod,
            )
        except LaunchError as exc:
            LOG.error("FFPuppet LaunchError: %s", str(exc))
            self.close()
            if isinstance(exc, BrowserTimeoutError):
                raise TargetLaunchTimeout(str(exc)) from None
            raise TargetLaunchError(str(exc), self.create_report()) from None

    def log_size(self):
        return self._puppet.log_length("stderr") + self._puppet.log_length("stdout")

    @property
    def prefs(self):
        if self._prefs is None:
            # generate temporary prefs.js
            for prefs_template in PrefPicker.templates():
                if prefs_template.endswith("browser-fuzzing.yml"):
                    LOG.debug("using prefpicker template %r", prefs_template)
                    tmp_fd, self._prefs = mkstemp(
                        prefix="prefs_", suffix=".js", dir=grz_tmp()
                    )
                    close(tmp_fd)
                    PrefPicker.load_template(prefs_template).create_prefsjs(self._prefs)
                    LOG.debug("generated prefs.js %r", self._prefs)
                    self._remove_prefs = True
                    break
            else:  # pragma: no cover
                raise TargetError("Failed to generate prefs.js")
        return self._prefs

    @prefs.setter
    def prefs(self, prefs_file):
        if self._remove_prefs and self._prefs and isfile(self._prefs):
            unlink(self._prefs)
        if prefs_file is None:
            self._prefs = None
            self._remove_prefs = True
        elif isfile(prefs_file):
            self._prefs = abspath(prefs_file)
            self._remove_prefs = False
        else:
            raise TargetError("Missing prefs.js file %r" % (prefs_file,))

    def save_logs(self, *args, **kwargs):
        self._puppet.save_logs(*args, **kwargs)
