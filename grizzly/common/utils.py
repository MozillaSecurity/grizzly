# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import sys  # mypy looks for `sys.version_info`
from enum import IntEnum, unique
from importlib.metadata import EntryPoint, PackageNotFoundError, entry_points, version
from logging import DEBUG, basicConfig, getLogger
from os import getenv
from pathlib import Path
from tempfile import gettempdir
from typing import Any, Generator, Iterable

__all__ = (
    "ConfigError",
    "configure_logging",
    "display_time_limits",
    "DEFAULT_TIME_LIMIT",
    "Exit",
    "grz_tmp",
    "HARNESS_FILE",
    "iter_entry_points",
    "package_version",
    "time_limits",
    "TIMEOUT_DELAY",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


DEFAULT_TIME_LIMIT = 30
GRZ_TMP = Path(getenv("GRZ_TMP", gettempdir()), "grizzly")
HARNESS_FILE = Path(__file__).parent / "harness.html"
LOG = getLogger(__name__)
# TIMEOUT_DELAY is added to the test time limit to create the default timeout
TIMEOUT_DELAY = 15


class ConfigError(Exception):
    """Raised to indicate invalid configuration a state"""

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@unique
class Exit(IntEnum):
    """Exit codes"""

    SUCCESS = 0
    # unexpected error occurred (invalid input, unhanded exception, etc)
    ERROR = 1
    # invalid argument
    ARGS = 2
    # run aborted (ctrl+c, etc)
    ABORT = 3
    # unrelated Target failure (browser startup crash, etc)
    LAUNCH_FAILURE = 4
    # expected results not reproduced (opposite of SUCCESS)
    FAILURE = 5


def configure_logging(log_level: int) -> None:
    """Configure log output level and formatting.

    Args:
        log_level: Set log level.

    Returns:
        None
    """
    # allow force enabling log_level via environment
    if getenv("DEBUG", "0").lower() in ("1", "true"):
        log_level = DEBUG
    if log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)


def display_time_limits(time_limit: int, timeout: int, no_harness: bool) -> None:
    """Output configuration of time limits and harness.

    Args:
        time_limit: Time in seconds before harness attempts to close current test.
        timeout: Time in seconds before iteration is considered a timeout.
        no_harness: Indicate whether harness will is disabled.

    Returns:
        None
    """
    if timeout > 0:
        if no_harness:
            LOG.info("Using timeout: %ds, harness: DISABLED", timeout)
        else:
            LOG.info("Using time limit: %ds, timeout: %ds", time_limit, timeout)
            if time_limit == timeout:
                LOG.info("To avoid unnecessary relaunches set timeout > time limit")
    else:
        if no_harness:
            LOG.info("Using timeout: DISABLED, harness: DISABLED")
        else:
            LOG.info("Using time limit: %ds, timeout: DISABLED,", time_limit)
        LOG.warning("TIMEOUT DISABLED, not recommended for automation")


def iter_entry_points(
    group: str,
) -> Generator[EntryPoint, None, None]:  # pragma: no cover
    """Compatibility wrapper code for importlib.metadata.entry_points()

    Args:
        group: See entry_points().

    Yields:
        EntryPoint
    """
    # TODO: remove this function when support for Python 3.9 is dropped
    assert group
    if sys.version_info >= (3, 10):
        yield from entry_points().select(group=group)
    else:
        raise AssertionError("Unsupported Python version")


def package_version(name: str, default: str = "unknown") -> str:
    """Get version of an installed package.

    Args:
        name: Package name.
        default: String to use if package is not found.

    Returns:
        Version string.
    """
    try:
        return version(name)
    except PackageNotFoundError:
        # package is not installed
        return default


def grz_tmp(*subdir: str | Path) -> Path:
    """Create (if needed) a temporary working directory in a known location.

    Args:
        subdir: Nested directories.

    Returns:
        Path within the temporary working directory.
    """
    path = Path(GRZ_TMP, *subdir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def time_limits(
    time_limit: int | None,
    timeout: int | None,
    # NOTE: Any should be TestCase, this function should likely live somewhere else
    tests: Iterable[Any] | None = None,
    default_limit: int = DEFAULT_TIME_LIMIT,
    timeout_delay: int = TIMEOUT_DELAY,
) -> tuple[int, int]:
    """Determine the test time limit and timeout. If time_limit or timeout is None
    it is calculated otherwise the provided value is used.

    Args:
        time_limit: Test time limit.
        timeout: Iteration timeout.
        tests: Testcases that may contain time limit values.
        default_limit: Value to use as default time limit.
        timeout_delay: Value to use as delay when calculating timeout.

    Returns:
        Time limit and timeout.
    """
    assert default_limit > 0
    assert timeout_delay >= 0
    # calculate time limit
    calc_limit = time_limit is None
    if calc_limit:
        # use default_limit as a minimum
        test_limits = [default_limit]
        if tests:
            # add small time buffer to duration
            test_limits.extend(int(x.duration) + 10 for x in tests if x.duration)
        time_limit = max(test_limits)
    assert time_limit is not None and time_limit > 0
    # calculate timeout
    if timeout is None:
        timeout = time_limit + timeout_delay
    elif calc_limit and time_limit > timeout > 0:
        LOG.debug("calculated time limit > given timeout, using timeout")
        time_limit = timeout
    assert timeout >= 0
    # timeout should always be >= time limit unless timeout is disabled
    assert timeout >= time_limit or timeout == 0
    return time_limit, timeout
