# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ("TargetMonitor",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


class TargetMonitor(metaclass=ABCMeta):
    @abstractmethod
    def clone_log(self, log_id: str, offset: int = 0) -> Path | None:
        """Create a copy of a log.

        Args:
            log_id: Log identifier.
            offset: Number of bytes to seek into log before copying data.

        Returns:
            Copy of specified log.
        """

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check for failures such as assertions, crashes, etc.

        Args:
            None

        Returns:
            True if no target failures are found otherwise False.
        """

    @abstractmethod
    def is_idle(self, threshold: int) -> bool:
        """Check if target is idle.

        Args:
            threshold: Maximum allowed CPU usage as percentage (per process).

        Returns:
            True if CPU usage for all processes is below the threshold otherwise False.
        """

    @abstractmethod
    def is_running(self) -> bool:
        """Check if target is running.

        Args:
            None

        Returns:
            True if target is running otherwise False.
        """

    @property
    @abstractmethod
    def launches(self) -> int:
        """Number of successful target launches.

        Args:
            None

        Returns:
            Number of successful launches.
        """

    @abstractmethod
    def log_length(self, log_id: str) -> int:
        """Calculate the length of a specific log file.

        Args:
            log_id: Log identifier.

        Returns:
            Log file size in bytes.
        """
