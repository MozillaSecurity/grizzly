# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
from logging import getLogger
from pathlib import Path
from tempfile import TemporaryDirectory, mkdtemp

from ffpuppet import LaunchError
from prefpicker import PrefPicker

from ..common.reporter import Report
from ..common.utils import grz_tmp
from .adb_device import ADBProcess, ADBSession
from .target import Result, Target
from .target_monitor import TargetMonitor

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger("adb_target")


class ADBTarget(Target):
    SUPPORTED_ASSETS = ("prefs",)

    def __init__(self, binary, launch_timeout, log_limit, memory_limit, **kwds):
        super().__init__(binary, launch_timeout, log_limit, memory_limit)
        self.forced_close = True  # app will not close itself on Android
        self.use_rr = False

        for unsupported in ("pernosco", "rr", "valgrind", "xvfb"):
            if kwds.pop(unsupported, False):
                LOG.warning("ADBTarget ignoring %r: not supported", unsupported)
        if kwds:
            LOG.warning("ADBTarget ignoring unsupported arguments: %s", ", ".join(kwds))

        LOG.debug("opening a session and setting up the environment")
        self._session = ADBSession.create(as_root=True)
        if self._session is None:
            raise RuntimeError("Could not create ADB Session!")
        self._package = ADBSession.get_package_name(self.binary)
        self._prefs = None
        self._proc = ADBProcess(self._package, self._session)
        self._session.symbols[self._package] = os.path.join(
            os.path.dirname(self.binary), "symbols"
        )

    def _cleanup(self):
        with self._lock:
            if self._proc is not None:
                self._proc.cleanup()
            if self._session.connected:
                self._session.reverse_remove()
            self._session.disconnect()
        if self._prefs and os.path.isfile(self._prefs):
            os.remove(self._prefs)

    def close(self, force_close=False):
        with self._lock:
            if self._proc is not None:
                self._proc.close()

    @property
    def closed(self):
        return self._proc.reason is not None

    def check_result(self, _ignored):
        status = Result.NONE
        if not self._proc.is_healthy():
            self._proc.close()
            # if something has happened figure out what
            if self._proc.reason == ADBProcess.RC_CLOSED:
                LOG.info("target.close() was called")
            elif self._proc.reason == ADBProcess.RC_EXITED:
                LOG.info("Target closed itself")
            else:
                LOG.debug("failure detected")
                status = Result.FOUND
        return status

    def handle_hang(self, ignore_idle=True):
        # TODO: attempt to detect idle hangs?
        self.close()
        return False

    def launch(self, location):
        env_mod = dict(self.environ)
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
                launch_timeout=self.launch_timeout,
                prefs_js=self._prefs,
                url=location,
            )
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

    def process_assets(self):
        self._prefs = self.assets.get("prefs")
        # generate temporary prefs.js with prefpicker
        if self._prefs is None:
            LOG.debug("using prefpicker to generate prefs.js")
            with TemporaryDirectory(dir=grz_tmp("target")) as tmp_path:
                prefs = Path(tmp_path) / "prefs.js"
                template = PrefPicker.lookup_template("browser-fuzzing.yml")
                PrefPicker.load_template(template).create_prefsjs(prefs)
                self._prefs = self.assets.add("prefs", str(prefs), copy=False)

    def create_report(self, is_hang=False):
        logs = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
        self.save_logs(logs)
        return Report(logs, self.binary, is_hang=is_hang)

    def reverse(self, remote, local):
        # remote->device, local->desktop
        self._session.reverse(remote, local)

    def save_logs(self, *args, **kwargs):
        self._proc.save_logs(*args, **kwargs)
