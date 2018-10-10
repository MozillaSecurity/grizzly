import logging
import os
import shutil
import signal
import tempfile
import time

from ffpuppet import FFPuppet, LaunchError
import psutil


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly")  # pylint: disable=invalid-name

class Target(object):
    PUPPET = FFPuppet  # used in unit tests
    RESULT_NONE = 0
    RESULT_FAILURE = 1
    RESULT_IGNORED = 2
    POLL_BUSY = 0
    POLL_IDLE = 1
    POLL_ERROR = 2

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch,
                 use_rr, use_valgrind, use_xvfb):
        self.binary = binary
        self.extension = extension
        self.launch_timeout = max(launch_timeout, 300)
        self.log_limit = log_limit * 0x100000 if log_limit and log_limit > 0 else 0
        self.memory_limit = memory_limit * 0x100000 if memory_limit and memory_limit > 0 else 0
        self.prefs = os.path.abspath(prefs) if prefs else None
        self.rl_countdown = 0
        self.rl_reset = max(relaunch, 1)
        self.rr_path = None  # TODO: this should likely be in FFPuppet
        self.use_rr = use_rr

        assert self.binary is not None and os.path.isfile(self.binary)
        assert self.prefs is None or os.path.isfile(self.prefs)
        if self.prefs is not None:
            log.info("Using prefs %r", self.prefs)

        # create Puppet object
        self._puppet = self.PUPPET(
            use_rr=self.use_rr,
            use_valgrind=use_valgrind,
            use_xvfb=use_xvfb)

        # this is a readonly monitor that can be safely passed to Adapters
        self.monitor = TargetMonitor.monitor(self._puppet)


    def add_abort_token(self, token):
        self._puppet.add_abort_token(token)


    def cleanup(self):
        self._puppet.clean_up()


    def close(self):
        self._puppet.close()


    @property
    def closed(self):
        return self._puppet.reason is not None


    def check_relaunch(self, wait=60):
        # this should be called once per iteration
        self.rl_countdown -= 1
        if self.rl_countdown > 0:
            return
        wait = max(wait, 0)
        # if the corpus manager does not use the default harness
        # chances are it will hang here for 60 seconds
        log.debug("relaunch will be triggered... waiting up to %d seconds", wait)
        for _ in range(wait):
            if not self._puppet.is_healthy():
                break
            time.sleep(1)

        if self._puppet.is_healthy():
            log.info("Forcing target relaunch")
        self._puppet.close()


    def poll_for_idle(self, threshold, interval):
        # return POLL_IDLE if cpu usage of target is below threshold for interval seconds
        pid = self._puppet.get_pid()
        if pid is not None:
            try:
                process = psutil.Process(pid)
                log.debug('Polling process...')
                # poll for 100ms at a time so we can exit earlier if the threshold is exceeded
                intervals = int(interval / 0.1)
                result = all(process.cpu_percent(interval=0.1) <= threshold
                             for _ in range(intervals))
                if result:
                    log.info('Process utilized <= %d%% CPU for %ds.', threshold, interval)
                    return self.POLL_IDLE
                return self.POLL_BUSY
            except psutil.NoSuchProcess:
                log.debug('Error polling process: %d no longer exists', pid)
        # default to False if we could not measure cpu usage
        return self.POLL_ERROR


    def detect_failure(self, ignored, was_timeout):
        # attempt to detect a failure
        status = self.RESULT_NONE
        if not self._puppet.is_running():
            self._puppet.close()
            if self._puppet.reason == FFPuppet.RC_EXITED:
                log.info("Target closed itself")
            elif (self._puppet.reason == FFPuppet.RC_WORKER
                  and "memory" in ignored
                  and "ffp_worker_memory_limiter" in self._puppet.available_logs()):
                status = self.RESULT_IGNORED
                log.info("Memory limit exceeded")
            elif (self._puppet.reason == FFPuppet.RC_WORKER
                  and "log-limit" in ignored
                  and "ffp_worker_log_size_limiter" in self._puppet.available_logs()):
                status = self.RESULT_IGNORED
                log.info("Log size limit exceeded")
            else:
                log.debug("failure detected")
                status = self.RESULT_FAILURE
        elif not self._puppet.is_healthy():
            # this should be e10s only
            status = self.RESULT_FAILURE
            log.info("Browser is alive but has crash reports. Terminating...")
            self._puppet.close()
        elif was_timeout:
            log.debug("timeout detected")
            self._puppet.close()
            # handle ignored timeouts
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
        self.rl_countdown = self.rl_reset
        env_mod = dict(env_mod or [])  # if passed, make a copy so modifications aren't passed out

        # do not allow network connections to non local endpoints
        env_mod["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1"

        if self.use_rr:
            if self.rr_path is not None and os.path.isdir(self.rr_path):
                shutil.rmtree(self.rr_path)
            self.rr_path = tempfile.mkdtemp(prefix="grz_rr")
            env_mod["_RR_TRACE_DIR"] = self.rr_path

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
        except LaunchError:
            self._puppet.close()
            raise


    def log_size(self):
        return self._puppet.log_length("stderr") + self._puppet.log_length("stdout")


    def save_logs(self, *args, **kwargs):
        self._puppet.save_logs(*args, **kwargs)


class TargetMonitor(object):
    def __init__(self):
        self._fn_clone_log = None
        self._fn_is_healthy = None
        self._fn_is_running = None
        self._fn_launches = None
        self._fn_log_length = None


    def clone_log(self, log_id, offset=0):
        if self._fn_clone_log is None:
            return None
        return self._fn_clone_log(log_id, offset=offset)

    @property
    def launches(self):
        return 0 if self._fn_launches is None else self._fn_launches()


    def is_healthy(self):
        return False if self._fn_is_healthy is None else self._fn_is_healthy()


    def is_running(self):
        return False if self._fn_is_running is None else self._fn_is_running()


    def log_data(self, log_id, offset=0):
        if self._fn_clone_log is None:
            return None
        log_file = self._fn_clone_log(log_id, offset=offset)
        if log_file is None:
            return None
        try:
            with open(log_file, "rb") as log_fp:
                return log_fp.read()
        finally:
            os.remove(log_file)


    def log_length(self, log_id):
        return 0 if self._fn_log_length is None else self._fn_log_length(log_id)


    @classmethod
    def monitor(cls, target):
        mon = TargetMonitor()
        mon._fn_clone_log = target.clone_log  # pylint: disable=protected-access
        mon._fn_is_healthy = target.is_healthy  # pylint: disable=protected-access
        mon._fn_is_running = target.is_running  # pylint: disable=protected-access
        mon._fn_launches = lambda: target.launches  # pylint: disable=protected-access
        mon._fn_log_length = target.log_length  # pylint: disable=protected-access
        return mon
