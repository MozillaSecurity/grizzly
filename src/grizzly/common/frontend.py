# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from enum import IntEnum, unique
from logging import DEBUG, basicConfig, getLogger
from os import getenv, getpid
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

from sapphire import CertificateBundle

from .cache import add_cached, find_cached
from .utils import grz_tmp

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .storage import TestCase

__all__ = (
    "DEFAULT_TIME_LIMIT",
    "TIMEOUT_DELAY",
    "ConfigError",
    "Exit",
    "configure_logging",
    "display_time_limits",
    "time_limits",
)

DEFAULT_TIME_LIMIT = 30
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


def get_certs() -> CertificateBundle:
    """Load or create a CertificateBundle. This will search for a cached
    certificate bundle before generating and caching a new bundle.
    The cache allows reuse across processes.

    Args:
        None.

    Returns:
        CertificateBundle
    """
    cached = find_cached("crypto")
    # create certificates if required
    if cached is None or not (cached / "certs").exists():
        with TemporaryDirectory() as tmp_path:
            certs = Path(tmp_path) / "certs"
            certs.mkdir(parents=True)
            CertificateBundle.create(certs)
            # add newly generated certs to cache
            cached = add_cached("crypto", certs)
    # copy data from cache
    path = grz_tmp("certs") / str(getpid())
    copytree(cached / "certs", path)
    return CertificateBundle.load(path)


def time_limits(
    time_limit: int | None,
    timeout: int | None,
    tests: Iterable[TestCase] | None = None,
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
