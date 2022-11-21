# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from enum import IntEnum, unique
from logging import DEBUG, basicConfig, getLogger
from math import ceil
from os import getenv
from pathlib import Path
from tempfile import gettempdir

__all__ = (
    "ConfigError",
    "configure_logging",
    "display_time_limits",
    "DEFAULT_TIME_LIMIT",
    "Exit",
    "grz_tmp",
    "time_limits",
    "TIMEOUT_DELAY",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

DEFAULT_TIME_LIMIT = 30
GRZ_TMP = Path(getenv("GRZ_TMP", gettempdir()), "grizzly")
LOG = getLogger(__name__)
# TIMEOUT_DELAY is added to the test time limit to create the default timeout
TIMEOUT_DELAY = 15


class ConfigError(Exception):
    """Raised to indicate invalid configuration a state"""

    def __init__(self, message, exit_code):
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


def configure_logging(log_level):
    """Configure log output level and formatting.

    Args:
        log_level (int): Set log level.

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


def display_time_limits(time_limit, timeout, no_harness):
    """Output configuration of time limits and harness.

    Args:
        time_limit (int): Time in seconds before harness attempts to close current test.
        timeout (int): Time in seconds before iteration is considered a timeout.
        no_harness (bool): Indicate whether harness will is disabled.

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


def grz_tmp(*subdir):
    path = Path(GRZ_TMP, *subdir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def time_limits(
    time_limit,
    timeout,
    tests=None,
    default_limit=DEFAULT_TIME_LIMIT,
    timeout_delay=TIMEOUT_DELAY,
):
    """Determine the test time limit and timeout. If time_limit or timeout is None
    it is calculated otherwise the provided value is used.

    Args:
        time_limit (int): Test time limit.
        timeout (int): Iteration timeout.
        tests (iterable): Testcases that may contain time limit values.
        default_limit (int): Value to used as default time limit.
        timeout_delay (int): Value to used as delay when calculating timeout.

    Returns:
        tuple (int, int): Time limit and timeout.
    """
    assert default_limit > 0
    assert timeout_delay >= 0
    # calculate time limit
    calc_limit = time_limit is None
    if calc_limit:
        # use default_limit as a minimum
        test_limits = [default_limit]
        if tests:
            test_limits.extend(int(ceil(x.duration)) for x in tests if x.duration)
        time_limit = max(test_limits)
    assert time_limit > 0
    # calculate timeout
    calc_timeout = timeout is None
    if calc_timeout:
        timeout = time_limit + timeout_delay
    elif calc_limit and time_limit > timeout > 0:
        LOG.debug("calculated time limit > given timeout, using timeout")
        time_limit = timeout
    assert timeout >= 0
    # timeout should always be >= time limit unless timeout is disabled
    assert timeout >= time_limit or timeout == 0
    return time_limit, timeout
