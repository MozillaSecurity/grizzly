# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import logging
import os

from ffpuppet import LaunchError

from .adb_device import ADBProcess, ADBSession
from .target import Target
from .target_monitor import TargetMonitor

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


class ADBTarget(Target):
    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch, **kwds):
        super(ADBTarget, self).__init__(binary, extension, launch_timeout, log_limit,
                                        memory_limit, prefs, relaunch)
        self.forced_close = True  # app will not close itself on Android
        self.use_rr = False

        if kwds.pop("rr", False):
            log.warning("ADBTarget ignoring 'rr': not supported")
        if kwds.pop("valgrind", False):
            log.warning("ADBTarget ignoring 'valgrind': not supported")
        if kwds.pop("xvfb", False):
            log.warning("ADBTarget ignoring 'xvfb': not supported")
        if kwds:
            log.warning("ADBTarget ignoring unsupported arguments: %s", ", ".join(kwds))

        log.debug("opening a session and setting up the environment")
        self._session = ADBSession.create(as_root=True)
        if self._session is None:
            raise RuntimeError("Could not create ADB Session!")
        self._package = ADBSession.get_package_name(self.binary)
        self._proc = ADBProcess(self._package, self._session)
        self._session.symbols[self._package] = os.path.join(os.path.dirname(self.binary), "symbols")

    def cleanup(self):
        with self._lock:
            if self._proc is not None:
                self._proc.cleanup()
            if self._session.connected:
                self._session.reverse_remove()
            self._session.disconnect()

    def close(self):
        with self._lock:
            if self._proc is not None:
                self._proc.close()

    @property
    def closed(self):
        return self._proc.reason is not None

    def detect_failure(self, ignored, was_timeout):
        status = self.RESULT_NONE
        is_healthy = self._proc.is_healthy()
        # check if there has been a crash, hang, etc...
        if not is_healthy or was_timeout:
            if self._proc.is_running():
                log.info("Terminating browser...")
            self._proc.close()
        # if something has happened figure out what
        if not is_healthy:
            if self._proc.reason == ADBProcess.RC_CLOSED:
                log.info("target.close() was called")
            elif self._proc.reason == ADBProcess.RC_EXITED:
                log.info("Target closed itself")
            else:
                log.debug("failure detected")
                status = self.RESULT_FAILURE
        elif was_timeout:
            log.debug("timeout detected, potential browser hang")
            if ignored and "timeout" in ignored:
                status = self.RESULT_IGNORED
                log.info("Timed out")
            else:
                status = self.RESULT_FAILURE
        return status

    def launch(self, location, env_mod=None):
        self.rl_countdown = self.rl_reset
        env_mod = dict(env_mod or [])  # if passed, make a copy so modifications aren't passed out

        # This may be used to disabled network connections during testing, e.g.
        env_mod["MOZ_IN_AUTOMATION"] = "1"
        # prevent crash reporter from touching the dmp files
        env_mod["MOZ_CRASHREPORTER"] = "1"
        env_mod["MOZ_CRASHREPORTER_NO_REPORT"] = "1"
        env_mod["MOZ_CRASHREPORTER_SHUTDOWN"] = "1"
        # do not allow network connections to non local endpoints
        env_mod["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1"

        try:
            self._proc.launch(
                env_mod=env_mod,
                prefs_js=self.prefs,
                url=location)
        except LaunchError:
            self._proc.close()
            raise

    @property
    def monitor(self):
        if self._monitor is None:
            class _ADBMonitor(TargetMonitor):
                # pylint: disable=no-self-argument,protected-access
                def clone_log(_, *_a, **_k):  # pylint: disable=arguments-differ
                    log_file = self._proc.clone_log()
                    if log_file is None:
                        return None
                    try:
                        with open(log_file, "rb") as log_fp:
                            return log_fp.read()
                    finally:
                        os.remove(log_file)
                def is_running(_):
                    return self._proc.is_running()
                def is_healthy(_):
                    return self._proc.is_healthy()
                @property
                def launches(_):
                    return self._proc.launches
                def log_length(_, *_a):  # pylint: disable=arguments-differ
                    # TODO: This needs to be implemented
                    return 0

            self._monitor = _ADBMonitor()

        return self._monitor

    def reverse(self, remote, local):
        # remote->device, local->desktop
        self._session.reverse(remote, local)

    def save_logs(self, *args, **kwargs):
        self._proc.save_logs(*args, **kwargs)
