# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod, abstractproperty
from logging import getLogger
from os.path import isfile
from re import split as resplit
from threading import Lock


__all__ = ("Target", "sanitizer_opts")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


def sanitizer_opts(env_data):
    """Parse the values defined in given *SAN_OPTIONS environment variable.
    For example "ASAN_OPTIONS=debug=false:log_path='/test/file.log'"
    would return {"debug": "false", "log_path": "'/test/file.log'"}

    Args:
        env_var (str): *SAN_OPTIONS environment variable to parse.

    Returns:
        dict: Sanitized values from environment.
    """
    opts = dict()
    for opt in resplit(r":(?![\\|/])", env_data):
        if not opt:
            continue
        key, val = opt.split("=")
        opts[key] = val
    return opts


class TargetError(Exception):
    """Raised by Target"""


class TargetLaunchError(TargetError):
    """Raised if a failure during launch occurs"""
    def __init__(self, message, report):
        super().__init__(message)
        self.report = report


class TargetLaunchTimeout(TargetError):
    """Raised if the target does not launch within the defined amount of time"""


class Target(metaclass=ABCMeta):
    RESULT_NONE = 0
    RESULT_FAILURE = 1
    RESULT_IGNORED = 2

    __slots__ = (
        "_lock", "_monitor", "_prefs", "binary", "extension", "launch_timeout",
        "log_limit", "memory_limit")

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit):
        assert log_limit >= 0
        assert memory_limit >= 0
        assert binary is not None and isfile(binary)
        self._lock = Lock()
        self._monitor = None
        self._prefs = None
        self.binary = binary
        self.extension = extension
        self.launch_timeout = max(launch_timeout, 300)
        self.log_limit = log_limit
        self.memory_limit = memory_limit

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add_abort_token(self, token):  # pylint: disable=no-self-use,unused-argument
        LOG.warning("add_abort_token() not implemented!")

    @abstractmethod
    def cleanup(self):
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractproperty
    def closed(self):
        pass

    # TODO: add collect_report()?

    @abstractmethod
    def detect_failure(self, ignored, was_timeout):
        pass

    def dump_coverage(self):  # pylint: disable=no-self-use
        LOG.warning("dump_coverage() is not supported!")

    # TODO: move to monitor?
    def is_idle(self, threshold):  # pylint: disable=no-self-use,unused-argument
        LOG.debug("Target.is_idle() not implemented! returning False")
        return False

    @abstractmethod
    def launch(self):
        pass

    def log_size(self):  # pylint: disable=no-self-use
        LOG.debug("log_size() not implemented! returning 0")
        return 0

    @abstractproperty
    def monitor(self):
        pass

    # TODO: better meta file handling
    @abstractproperty
    def prefs(self):
        pass

    def reverse(self, remote, local):
        # remote->device, local->desktop
        pass

    @abstractmethod
    def save_logs(self, *args, **kwargs):
        pass
