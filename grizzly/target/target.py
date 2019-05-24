# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import abc
import logging
import os
import threading
import time

import six

__all__ = ("Target",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


@six.add_metaclass(abc.ABCMeta)
class Target(object):
    RESULT_NONE = 0
    RESULT_FAILURE = 1
    RESULT_IGNORED = 2
    POLL_BUSY = 0
    POLL_IDLE = 1
    POLL_ERROR = 2

    def __init__(self, binary, extension, launch_timeout, log_limit, memory_limit, prefs, relaunch):
        self._lock = threading.Lock()
        self._monitor = None
        self.binary = binary
        self.extension = extension
        self.forced_close = os.getenv("GRZ_FORCED_CLOSE", "1").lower() not in ("false", "0")
        self.launch_timeout = max(launch_timeout, 300)
        self.log_limit = log_limit * 0x100000 if log_limit and log_limit > 0 else 0
        self.memory_limit = memory_limit * 0x100000 if memory_limit and memory_limit > 0 else 0
        self.rl_countdown = 0
        self.rl_reset = max(relaunch, 1)
        self.prefs = os.path.abspath(prefs) if prefs else None

        assert self.binary is not None and os.path.isfile(self.binary)
        if self.prefs is not None:
            log.info("Using prefs %r", self.prefs)
            assert os.path.isfile(self.prefs)

    def add_abort_token(self, token):  # pylint: disable=no-self-use,unused-argument
        log.warning("add_abort_token() not implemented!")

    def check_relaunch(self, wait=60):
        if self.rl_countdown > 0:
            return
        # if the corpus manager does not use the default harness
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
        log.error("dump_coverage() is not supported!")

    @property
    def expect_close(self):
        # This is used to indicate if the browser will self close after the current iteration
        return self.rl_countdown < 1 and not self.forced_close

    @abc.abstractmethod
    def launch(self):
        pass

    def log_size(self):  # pylint: disable=no-self-use
        log.debug("log_size() not implemented! returning 0")
        return 0

    @abc.abstractproperty
    def monitor(self):
        pass

    def poll_for_idle(self, threshold, interval):  # pylint: disable=unused-argument
        log.debug("poll_for_idle() not implemented! returning POLL_BUSY")
        return self.POLL_BUSY

    def reverse(self, remote, local):
        # remote->device, local->desktop
        pass

    @abc.abstractmethod
    def save_logs(self, *args, **kwargs):
        pass

    def step(self):
        # this should be called once per iteration
        self.rl_countdown -= 1
