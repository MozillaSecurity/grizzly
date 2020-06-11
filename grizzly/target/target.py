# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod, abstractproperty
from logging import getLogger
from os import getenv
from os.path import abspath, isfile
from re import split as resplit
from threading import Lock
from time import sleep, time


__all__ = ("Target", "sanitizer_opts")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger("grizzly")


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


class TargetLaunchTimeout(TargetError):
    """Raised if the target does not launch within the defined amount of time"""


class Target(metaclass=ABCMeta):
    RESULT_NONE = 0
    RESULT_FAILURE = 1
    RESULT_IGNORED = 2

    __slots__ = (
        "_lock", "_monitor", "binary", "extension", "forced_close", "launch_timeout",
        "log_limit", "memory_limit", "prefs", "rl_countdown", "rl_reset")

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch):
        assert log_limit >= 0
        assert memory_limit >= 0
        assert relaunch >= 1
        self._lock = Lock()
        self._monitor = None
        self.binary = binary
        self.extension = extension
        self.forced_close = getenv("GRZ_FORCED_CLOSE") != "0"
        self.launch_timeout = max(launch_timeout, 300)
        self.log_limit = log_limit
        self.memory_limit = memory_limit
        self.prefs = abspath(prefs) if prefs else None
        self.rl_countdown = 0
        self.rl_reset = relaunch
        assert self.binary is not None and isfile(self.binary)
        if self.prefs is not None:
            if not isfile(self.prefs):
                raise TargetError("Prefs file does not exist %r" % (self.prefs,))
            LOG.info("Using prefs %r", self.prefs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add_abort_token(self, token):  # pylint: disable=no-self-use,unused-argument
        LOG.warning("add_abort_token() not implemented!")

    def check_relaunch(self, wait=60):
        if self.rl_countdown > 0:
            return
        # if the adapter does not use the default harness
        # or close the browser it will hang here for 60 seconds
        LOG.debug("relaunch will be triggered... waiting up to %0.2f seconds", wait)
        deadline = time() + wait
        while self.monitor.is_healthy():
            if time() >= deadline:
                LOG.info("Forcing target relaunch")
                break
            sleep(1)
        self.close()

    @abstractmethod
    def cleanup(self):
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractproperty
    def closed(self):
        pass

    @abstractmethod
    def detect_failure(self, ignored, was_timeout):
        pass

    def dump_coverage(self):  # pylint: disable=no-self-use
        LOG.warning("dump_coverage() is not supported!")

    @property
    def expect_close(self):
        # This is used to indicate if the browser will self close after the current iteration
        return self.rl_countdown < 1 and not self.forced_close

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

    def reverse(self, remote, local):
        # remote->device, local->desktop
        pass

    @abstractmethod
    def save_logs(self, *args, **kwargs):
        pass

    def step(self):
        # this should be called once per iteration
        self.rl_countdown -= 1
