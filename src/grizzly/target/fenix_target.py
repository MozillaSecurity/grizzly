# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from contextlib import suppress
from logging import getLogger
from pathlib import Path
from tempfile import TemporaryDirectory, mkdtemp
from typing import TYPE_CHECKING

with suppress(ImportError):
    from fxpoppet import ADBLaunchError, ADBProcess, ADBSession, Reason
from prefpicker import PrefPicker

from ..common.report import Report
from ..common.utils import grz_tmp
from .firefox_target import merge_sanitizer_options
from .target import Result, Target, TargetLaunchError
from .target_monitor import TargetMonitor

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from typing import Any

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


class FenixMonitor(TargetMonitor):
    def __init__(self, proc: ADBProcess) -> None:
        self._proc = proc

    def is_healthy(self) -> bool:
        return self._proc.is_healthy()

    def is_idle(self, threshold: int) -> bool:
        return all(cpu < threshold for _, cpu in self._proc.cpu_usage())

    def is_running(self) -> bool:
        return self._proc.is_running()

    @property
    def launches(self) -> int:
        return self._proc.launches

    def log_length(self, log_id: str) -> int:
        # TODO: This needs to be implemented
        return 0


class FenixTarget(Target):
    """This target adds support for Firefox on Android. Currently this is only
    supported on Linux.
    """

    SUPPORTED_ASSETS = ("prefs",)

    __slots__ = (
        "_monitor",
        "_package",
        "_prefs",
        "_proc",
        "_session",
        "forced_close",
        "use_rr",
    )

    def __init__(
        self,
        binary: Path,
        launch_timeout: int,
        log_limit: int,
        memory_limit: int,
        **kwds: dict[str, Any],
    ) -> None:
        super().__init__(binary, launch_timeout, log_limit, memory_limit)
        # app will not close itself on Android
        self.forced_close = True
        self.use_rr = False
        self._prefs: Path | None = None

        for unsupported in ("pernosco", "rr", "valgrind", "xvfb"):
            if kwds.pop(unsupported, None):
                LOG.warning("FenixTarget ignoring '%s': not supported", unsupported)
        if kwds:
            LOG.warning(
                "FenixTarget ignoring unsupported arguments: %s", ", ".join(kwds)
            )

        self._package = ADBSession.get_package_name(self.binary)
        if self._package is None:
            LOG.error("FenixTarget init failed!")
            raise RuntimeError("Could not find package name.")

        LOG.debug("opening adb session...")
        session = ADBSession.create(as_root=True, max_attempts=10, retry_delay=15)
        if session is None:
            LOG.error("FenixTarget init failed!")
            raise RuntimeError("Could not create ADB Session!")
        LOG.debug("connected to device (%s)", session.device_id)
        self._session = session
        self._session.symbols[self._package] = self.binary.parent / "symbols"

        try:
            self._proc = ADBProcess(self._package, self._session)
        except:
            LOG.error("FenixTarget init failed!")
            self._session.disconnect()
            raise
        self._monitor = FenixMonitor(self._proc)

    def _cleanup(self) -> None:
        with self._lock:
            if self._proc is not None:
                self._proc.cleanup()
            if self._session.connected:
                self._session.reverse_remove()
            self._session.disconnect()
        if self._prefs and self._prefs.is_file():
            self._prefs.unlink()

    def close(self, force_close: bool = False) -> None:
        with self._lock:
            if self._proc is not None:
                self._proc.close()

    @property
    def closed(self) -> bool:
        return self._proc.reason is not None

    def check_result(self, _ignored: Iterable[str]) -> Result:
        status = Result.NONE
        if not self._proc.is_healthy():
            self._proc.close()
            # if something has happened figure out what
            if self._proc.reason == Reason.CLOSED:
                LOG.debug("target.close() was called")
            elif self._proc.reason == Reason.EXITED:
                LOG.debug("Target closed itself")
            else:
                LOG.debug("failure detected")
                status = Result.FOUND
        return status

    def create_report(self, is_hang: bool = False, unstable: bool = False) -> Report:
        logs = Path(mkdtemp(prefix="logs_", dir=grz_tmp("logs")))
        self.save_logs(logs)
        return Report(logs, self.binary, is_hang=is_hang, unstable=unstable)

    def dump_coverage(self, timeout: int = 0) -> None:
        raise NotImplementedError()  # pragma: no cover

    def handle_hang(
        self, ignore_idle: bool = True, ignore_timeout: bool = False
    ) -> bool:
        was_idle = self.monitor.is_idle(15)
        self.close()
        return was_idle

    def https(self) -> bool:
        # HTTPS support is not currently supported
        return False

    def launch(self, location: str) -> None:
        env_mod = dict(self.environ)
        # disabled external network connections during testing
        env_mod["MOZ_IN_AUTOMATION"] = "1"
        # prevent crash reporter from touching the dmp files
        env_mod["MOZ_CRASHREPORTER"] = "1"
        env_mod["MOZ_CRASHREPORTER_NO_REPORT"] = "1"
        env_mod["MOZ_CRASHREPORTER_SHUTDOWN"] = "1"
        # do not allow network connections to non local endpoints
        env_mod["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1"
        if not self._session.wait_for_boot(1):
            LOG.error("Device is not available for launch attempt!")
            # TODO: this should likely be a TargetLaunchError or similar
            # but we cannot get logs when the device goes away
            raise RuntimeError("Device not available")
        try:
            self._proc.launch(
                env_mod=env_mod,
                launch_timeout=self.launch_timeout,
                prefs_js=self._prefs,
                url=location,
            )
        except ADBLaunchError as exc:
            LOG.error("ADBProcess LaunchError: %s", exc)
            self.close()
            raise TargetLaunchError(str(exc), self.create_report()) from None

    def log_size(self) -> int:
        LOG.debug("log_size not currently implemented")
        return 0

    def merge_environment(self, extra: Mapping[str, str]) -> None:
        output = dict(extra)
        output.update(self.environ)
        output.update(merge_sanitizer_options(self.environ, extra=extra))
        self.environ = output

    @property
    def monitor(self) -> FenixMonitor:
        return self._monitor

    def process_assets(self) -> None:
        self._prefs = self.asset_mgr.get("prefs")
        # generate temporary prefs.js with prefpicker
        if self._prefs is None:
            LOG.debug("using prefpicker to generate prefs.js")
            with TemporaryDirectory(dir=grz_tmp("target")) as tmp_path:
                prefs = Path(tmp_path) / "prefs.js"
                template = PrefPicker.lookup_template("browser-fuzzing.yml")
                assert template is not None
                PrefPicker.load_template(template).create_prefsjs(prefs)
                self._prefs = self.asset_mgr.add("prefs", prefs, copy=False)

    def reverse(self, remote: int, local: int) -> None:
        # remote->device, local->desktop
        self._session.reverse(remote, local)

    def save_logs(self, dst: Path) -> None:
        self._proc.save_logs(dst)
