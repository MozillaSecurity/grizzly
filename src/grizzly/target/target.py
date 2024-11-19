# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from enum import IntEnum, unique
from logging import getLogger
from os import environ
from threading import Lock
from typing import TYPE_CHECKING, final

from sapphire import CertificateBundle

from ..common.utils import grz_tmp
from .assets import AssetManager

if TYPE_CHECKING:
    from pathlib import Path

    from ..common.report import Report
    from .target_monitor import TargetMonitor

__all__ = ("Result", "Target", "TargetError", "TargetLaunchError")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


@unique
class Result(IntEnum):
    """Target result codes"""

    NONE = 0
    FOUND = 1
    IGNORED = 2


class TargetError(Exception):
    """Raised by Target"""


class TargetLaunchError(TargetError):
    """Raised if a failure during launch occurs"""

    def __init__(self, message: str, report: Report) -> None:
        super().__init__(message)
        self.report = report


class TargetLaunchTimeout(TargetError):
    """Raised if the target does not launch within the defined amount of time"""


class Target(metaclass=ABCMeta):
    SUPPORTED_ASSETS: tuple[str, ...] = ()
    TRACKED_ENVVARS: tuple[str, ...] = ()

    __slots__ = (
        "_asset_mgr",
        "_https",
        "_lock",
        "_monitor",
        "binary",
        "certs",
        "environ",
        "launch_timeout",
        "log_limit",
        "memory_limit",
    )

    def __init__(
        self,
        binary: Path,
        launch_timeout: int,
        log_limit: int,
        memory_limit: int,
        certs: CertificateBundle | None = None,
    ) -> None:
        assert launch_timeout > 0
        assert log_limit >= 0
        assert memory_limit >= 0
        assert binary is not None and binary.is_file()
        assert certs is None or isinstance(certs, CertificateBundle)
        self._asset_mgr = AssetManager(base_path=grz_tmp("target"))
        self._https = False
        self._lock = Lock()
        self._monitor: TargetMonitor | None = None
        self.binary = binary
        self.certs = certs
        self.environ = self.scan_environment(dict(environ), self.TRACKED_ENVVARS)
        self.launch_timeout = launch_timeout
        self.log_limit = log_limit
        self.memory_limit = memory_limit

    def __enter__(self) -> Target:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    @property
    def asset_mgr(self) -> AssetManager:
        """Get current AssetManager.

        Args:
            None

        Returns:
            AssetManager.
        """
        return self._asset_mgr

    @asset_mgr.setter
    def asset_mgr(self, asset_mgr: AssetManager) -> None:
        """Set AssetManager and cleanup previous AssetManager.

        Args:
            None

        Returns:
            AssetManager.
        """
        self._asset_mgr.cleanup()
        assert isinstance(asset_mgr, AssetManager)
        self._asset_mgr = asset_mgr

    @abstractmethod
    def _cleanup(self) -> None:
        """Cleanup method to be implemented by subclass.

        Args:
            None

        Returns:
            None.
        """

    @abstractmethod
    def check_result(self, ignored: set[str]) -> Result:
        """Check for results.

        Args:
            ignored: Result types that are currently ignored.

        Returns:
            Result code.
        """

    @final
    def cleanup(self) -> None:
        """Perform necessary cleanup. DO NOT OVERRIDE.

        Args:
            ignored: Types of results to ignore.

        Returns:
            Result code.
        """
        # call target specific _cleanup method first
        self._cleanup()
        self._asset_mgr.cleanup()

    @abstractmethod
    def close(self, force_close: bool = False) -> None:
        """Close target.

        Args:
            force_close: Close as quickly as possible. Logs will not be collected.

        Returns:
            None.
        """

    @property
    @abstractmethod
    def closed(self) -> bool:
        """Check if the target is closed.

        Args:
            None

        Returns:
            True if closed otherwise False.
        """

    @abstractmethod
    def create_report(self, is_hang: bool = False, unstable: bool = False) -> Report:
        """Process logs and create a Report.

        Args:
            is_hang: Indicate whether the results is due to a hang/timeout.
            unstable: Indicate whether build is unstable.

        Returns:
            Report object.
        """

    @abstractmethod
    def dump_coverage(self, timeout: int = 0) -> None:
        """Trigger target coverage data dump.

        Args:
            timeout: Amount of time to wait for data to be written.

        Returns:
            None.
        """

    def filtered_environ(self) -> dict[str, str]:
        """Used to collect the environment to add to a testcase.

        Args:
            None

        Returns:
            Environment variables.
        """
        return dict(self.environ)

    @abstractmethod
    def handle_hang(
        self,
        ignore_idle: bool = True,
        ignore_timeout: bool = False,
    ) -> bool:
        """Handle a target hang.

        Args:
            ignore_idle: Do not treat as a hang if target is idle.
            ignore_timeout: Indicates if a timeout will be ignored.

        Returns:
            True if the target was idle otherwise False.
        """

    @abstractmethod
    def https(self) -> bool:
        """Target configured for HTTPS.

        Args:
            None

        Returns:
            True if HTTPS can be used otherwise False.
        """

    @abstractmethod
    def launch(self, location: str) -> None:
        """Launch the target.

        Args:
            location: URL to load.

        Returns:
            None.
        """

    @abstractmethod
    def log_size(self) -> int:
        """Calculate the amount of data contained in target log files.

        Args:
            None

        Returns:
            Total data size of log files in bytes.
        """

    @abstractmethod
    def merge_environment(self, extra: dict[str, str]) -> None:
        """Add to existing environment.

        Args:
            extra: Environment variables to add.

        Returns:
            None.
        """

    @property
    @abstractmethod
    def monitor(self) -> TargetMonitor:
        """TargetMonitor.

        Args:
            extra: Environment variables to add.

        Returns:
            TargetMonitor
        """

    @abstractmethod
    def process_assets(self) -> None:
        """Prepare assets for use by the target.

        Args:
            None

        Returns:
            None.
        """

    def reverse(self, remote: int, local: int) -> None:
        """Configure port mappings. Remote -> device, local -> desktop (current system).

        Args:
            remote: Port on remote device.
            local: Port on local machine.

        Returns:
            None.
        """

    @staticmethod
    def scan_environment(
        env: dict[str, str],
        include: tuple[str, ...] | None,
    ) -> dict[str, str]:
        """Scan environment for tracked environment variables.

        Args:
            env: Environment to scan.
            include: Variables to include in output.

        Returns:
            Tracked variables found in scanned environment.
        """
        return {var: env[var] for var in include if var in env} if include else {}

    @abstractmethod
    def save_logs(self, dst: Path) -> None:
        """Save logs to specified location.

        Args:
            dst: Location to save logs.

        Returns:
            None.
        """
