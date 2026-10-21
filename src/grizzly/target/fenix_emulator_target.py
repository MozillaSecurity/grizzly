# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from logging import getLogger
from os import getenv
from subprocess import TimeoutExpired
from typing import TYPE_CHECKING

from fxpoppet.adb_session import ADBSession, ADBSessionError
from fxpoppet.emulator.android import (
    PATHS,
    SYS_IMG,
    AndroidEmulator,
    AndroidEmulatorError,
)

from ..common.report import MAX_LOG_SIZE
from .fenix_target import FenixTarget
from .target import Result, TargetLaunchError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from typing import Any

__all__ = ("FenixEmulatorTarget", "emulator_installed")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


def emulator_installed() -> bool:
    """Check if the Android emulator and required SDK components are installed.

    Args:
        None

    Returns:
        True if the required components are installed otherwise False.
    """
    sdk_root = PATHS.sdk_root
    required = (
        sdk_root / "emulator" / "emulator",
        sdk_root / "emulator" / "mksdcard",
        sdk_root / "platform-tools" / "adb",
        sdk_root / "system-images" / SYS_IMG / "default" / "x86_64",
    )
    return all(entry.exists() for entry in required)


class FenixEmulatorTarget(FenixTarget):  # pylint: disable=abstract-method
    """This target adds support for Firefox on Android running in an emulator
    managed by the target. Currently this is only supported on Linux.
    """

    BOOT_TIMEOUT = 300
    LAUNCH_ATTEMPTS = 3

    __slots__ = (
        "_display_mode",
        "_emulator",
        "_reverse",
    )

    def __init__(
        self,
        binary: Path,
        launch_timeout: int,
        log_limit: int,
        memory_limit: int,
        report_size_limit: int = MAX_LOG_SIZE,
        **kwds: Any,
    ) -> None:
        # display mode is used by the emulator, not the browser
        self._display_mode: str = kwds.pop("display_mode", None) or "default"
        assert self._display_mode in {"default", "headless", "xvfb"}
        self._emulator: AndroidEmulator | None = None
        self._reverse: dict[int, int] = {}
        if not emulator_installed():
            LOG.warning("Android emulator is not installed")
            raise RuntimeError("Android emulator is not installed")
        try:
            super().__init__(
                binary,
                launch_timeout,
                log_limit,
                memory_limit,
                report_size_limit=report_size_limit,
                **kwds,
            )
        except:
            self._shutdown_emulator()
            raise

    def _cleanup(self) -> None:
        try:
            super()._cleanup()
        finally:
            with self._lock:
                self._shutdown_emulator()

    def _launch_emulator(self) -> AndroidEmulator:
        """Launch an Android emulator.

        Args:
            None

        Returns:
            Running emulator.
        """
        port = AndroidEmulator.search_free_ports()
        avd_name = f"x86.{port:d}"
        LOG.debug("launching 'emulator-%d'...", port)
        AndroidEmulator.create_avd(avd_name)
        try:
            emu = AndroidEmulator(
                avd_name=avd_name,
                port=port,
                headless=self._display_mode == "headless",
                xvfb=self._display_mode == "xvfb",
                boot_timeout=self.BOOT_TIMEOUT,
                emulator_output=getenv("EMULATOR_OUTPUT") == "1",
            )
        except:
            AndroidEmulator.remove_avd(avd_name)
            raise
        return emu

    def _open_device(self) -> str:
        """Launch an emulator and install the target.

        Args:
            None

        Returns:
            Serial of the emulator.
        """
        assert self._emulator is None
        for attempt in range(1, self.LAUNCH_ATTEMPTS + 1):
            try:
                self._emulator = self._launch_emulator()
            except AndroidEmulatorError as exc:
                LOG.warning(
                    "Failed to launch emulator (%d/%d): %s",
                    attempt,
                    self.LAUNCH_ATTEMPTS,
                    exc,
                )
                continue
            serial = f"emulator-{self._emulator.port:d}"
            if self._prepare_device(serial):
                return serial
            LOG.warning(
                "Failed to prepare '%s' (%d/%d)", serial, attempt, self.LAUNCH_ATTEMPTS
            )
            self._shutdown_emulator()
        LOG.error("Failed to launch emulator")
        raise RuntimeError("Failed to launch emulator")

    def _prepare_device(self, serial: str) -> bool:
        """Configure the device and install the target.

        Args:
            serial: Serial of the device to prepare.

        Returns:
            True if the device is ready otherwise False.
        """
        LOG.debug("preparing '%s'...", serial)
        try:
            session = ADBSession.connect(serial, as_root=True, boot_timeout=10)
        except ADBSessionError as exc:
            LOG.debug("cannot connect to prepare '%s': %s", serial, exc)
            return False
        # disable UI animations
        session.device.shell(
            ["settings", "put", "global", "animator_duration_scale", "0"]
        )
        session.device.shell(
            ["settings", "put", "global", "transition_animation_scale", "0"]
        )
        session.device.shell(
            ["settings", "put", "global", "window_animation_scale", "0"]
        )
        # prevent device throttling
        session.device.shell(["settings", "put", "global", "device_idle_enabled", "0"])
        session.device.shell(["settings", "put", "global", "low_power", "0"])
        session.device.shell(
            ["settings", "put", "global", "background_process_limit", "0"]
        )
        session.device.shell(["dumpsys", "deviceidle", "disable"])
        LOG.debug("installing '%s'...", self.binary)
        try:
            session.install(self.binary)
        except ADBSessionError as exc:
            LOG.debug("failed to install APK: %s", exc)
            return False
        return True

    def _relaunch_emulator(self) -> None:
        """Shutdown the emulator, launch a new emulator and reconnect.

        Args:
            None

        Returns:
            None
        """
        LOG.debug("relaunching emulator...")
        with self._lock:
            # shutdown first to avoid waiting on an unresponsive device
            self._shutdown_emulator()
            self._proc.cleanup()
        self._connect(self._open_device())
        self._monitor.proc = self._proc
        # restore port forwarding
        for remote, local in self._reverse.items():
            self._session.reverse(remote, local)

    def _shutdown_emulator(self) -> None:
        """Shutdown the emulator and remove related files.

        Args:
            None

        Returns:
            None
        """
        if self._emulator is None:
            return
        LOG.debug("shutting down 'emulator-%d'...", self._emulator.port)
        if self._emulator.poll() is None:
            self._emulator.terminate()
        try:
            self._emulator.wait(timeout=30)
        except TimeoutExpired:
            self._emulator.emu.kill()
            try:
                self._emulator.wait(timeout=30)
            except TimeoutExpired:
                LOG.warning("Failed to shutdown emulator")
        finally:
            self._emulator.cleanup()
            self._emulator = None

    def check_result(self, ignored: Iterable[str]) -> Result:
        if self._emulator is None or self._emulator.poll() is not None:
            LOG.warning("Emulator is not running")
            self.close()
            return Result.NONE
        return super().check_result(ignored)

    def launch(self, location: str) -> None:
        if self._emulator is None or self._emulator.poll() is not None:
            LOG.warning("Emulator is not running, relaunching...")
            self._relaunch_emulator()
        elif not self._session.device.wait_for_boot(10):
            LOG.warning("Emulator is not responding, relaunching...")
            self._relaunch_emulator()
        try:
            super().launch(location)
        except TargetLaunchError:
            # launch a fresh emulator on the next attempt
            with self._lock:
                self._shutdown_emulator()
            raise

    def reverse(self, remote: int, local: int) -> None:
        self._reverse[remote] = local
        super().reverse(remote, local)
