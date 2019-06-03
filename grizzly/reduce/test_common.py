# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import unicode_literals
import os
from grizzly.target.target import Target
from grizzly.common import Reporter


class BaseFakeReporter(Reporter):
    def _pre_submit(self, _):
        pass

    def _reset(self):
        pass

    def _submit(self, *_args, **_kwds):
        pass


class FakeReduceStatus(object):
    "Stub to fake parts of ReduceStatus"

    def __init__(self):
        self.uid = 0
        self.duration = 0
        self.ignored = 0
        self.iteration = 0
        self.rate = 0
        self.results = 0
        self.reduce_error = 0
        self.reduce_fail = 0
        self.reduce_pass = 0
        self.start_time = 1558051385
        self.timestamp = 1558051385

    def cleanup(self):
        pass

    @classmethod
    def load(cls, uid):
        return cls.start(uid=uid) if uid > 0 else None

    def report(self, force=False):
        pass

    @classmethod
    def start(cls, uid=None):
        status = FakeReduceStatus()
        status.uid = 123 if uid is None else uid
        return status


class FakeTarget(object):
    "Stub to fake parts of grizzly.target.Target needed for testing the reduce loop"

    def __init__(self, *args, **kwds):
        self.rl_reset = 10
        self.closed = True
        self.binary = ""
        self.forced_close = os.getenv("GRZ_FORCED_CLOSE", "1").lower() not in ("false", "0")
        self.prefs = None
        self.rl_countdown = 0
        self.use_valgrind = False

        self._calls = {
            "save_logs": 0,
            "poll_for_idle": 0,
            "launch": 0,
            "check_relaunch": 0,
            "close": 0,
            "cleanup": 0,
            "detect_failure": 0,
        }
        self._is_healthy = False

        class FakeMonitor(object):  # pylint: disable=too-few-public-methods

            @staticmethod
            def is_healthy():
                return self._is_healthy

        self.monitor = FakeMonitor()

    def save_logs(self, dest, **kwds):
        self._calls["save_logs"] += 1
        with open(os.path.join(dest, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT")
        with open(os.path.join(dest, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("Assertion failure: bad thing happened, at test.c:123")

    def poll_for_idle(self, *args, **kwds):
        self._calls["poll_for_idle"] += 1
        return False

    def launch(self, *args, **kwds):
        self._calls["launch"] += 1

    def check_relaunch(self):
        self._calls["check_relaunch"] += 1

    def close(self):
        self._calls["close"] += 1

    def cleanup(self):
        self._calls["cleanup"] += 1

    def detect_failure(self, *args, **kwds):
        self._calls["detect_failure"] += 1
        return Target.RESULT_FAILURE

    @property
    def expect_close(self):
        return self.rl_countdown < 1 and not self.forced_close

    def step(self):
        self.rl_countdown -= 1


def create_target_binary(target, tmp_path):
    (tmp_path / "firefox.fuzzmanagerconf").write_text(
        "[Main]\n"
        "platform = x86-64\n"
        "product = mozilla-central\n"
        "os = linux\n"
    )
    target.binary = str(tmp_path / "firefox")
