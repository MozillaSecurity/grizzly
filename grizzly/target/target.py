# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import abc
import logging
import os
import re
import threading
import time

import six

__all__ = ("Target", "sanitizer_opts")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


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
    for opt in re.split(r":(?![\\|/])", env_data):
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


@six.add_metaclass(abc.ABCMeta)
class Target(object):
    RESULT_NONE = 0
    RESULT_FAILURE = 1
    RESULT_IGNORED = 2

    __slots__ = (
        "_lock", "_monitor", "binary", "extension", "forced_close", "launch_timeout",
        "log_limit", "memory_limit", "prefs", "rl_countdown", "rl_reset")

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch):
        self._lock = threading.Lock()
        self._monitor = None
        self.binary = binary
        self.extension = extension
        self.forced_close = os.getenv("GRZ_FORCED_CLOSE", "1").lower() not in ("false", "0")
        self.launch_timeout = max(launch_timeout, 300)
        self.log_limit = log_limit * 0x100000 if log_limit and log_limit > 0 else 0
        self.memory_limit = memory_limit * 0x100000 if memory_limit and memory_limit > 0 else 0
        self.prefs = os.path.abspath(prefs) if prefs else None
        self.rl_countdown = 0
        self.rl_reset = max(relaunch, 1)

        assert self.binary is not None and os.path.isfile(self.binary)
        if self.prefs is not None:
            if not os.path.isfile(self.prefs):
                raise TargetError("Prefs file does not exist %r" % (self.prefs,))
            log.info("Using prefs %r", self.prefs)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add_abort_token(self, token):  # pylint: disable=no-self-use,unused-argument
        log.warning("add_abort_token() not implemented!")

    def check_relaunch(self, wait=60):
        if self.rl_countdown > 0:
            return
        # if the adapter does not use the default harness
        # or close the browser it will hang here for 60 seconds
        log.debug("relaunch will be triggered... waiting up to %0.2f seconds", wait)
        deadline = time.time() + wait
        while self.monitor.is_healthy():
            if time.time() >= deadline:
                log.info("Forcing target relaunch")
                break
            time.sleep(1)
        self.close()

    @abc.abstractmethod
    def cleanup(self):
        pass

    @abc.abstractmethod
    def close(self):
        pass

    @abc.abstractproperty
    def closed(self):
        pass

    @abc.abstractmethod
    def detect_failure(self, ignored, was_timeout):
        pass

    def dump_coverage(self):  # pylint: disable=no-self-use
        log.warning("dump_coverage() is not supported!")

    @property
    def expect_close(self):
        # This is used to indicate if the browser will self close after the current iteration
        return self.rl_countdown < 1 and not self.forced_close

    def is_idle(self, threshold):  # pylint: disable=no-self-use,unused-argument
        log.debug("Target.is_idle() not implemented! returning False")
        return False

    @abc.abstractmethod
    def launch(self):
        pass

    def log_size(self):  # pylint: disable=no-self-use
        log.debug("log_size() not implemented! returning 0")
        return 0

    @abc.abstractproperty
    def monitor(self):
        pass

    def reverse(self, remote, local):
        # remote->device, local->desktop
        pass

    @abc.abstractmethod
    def save_logs(self, *args, **kwargs):
        pass

    def step(self):
        # this should be called once per iteration
        self.rl_countdown -= 1
