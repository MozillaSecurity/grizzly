# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os

from grizzly.target import Target


class FakeTarget(object):
    "Stub to fake parts of grizzly.target.Target needed for testing the reduce loop"

    def __init__(self, *args, **kwds):
        self.rl_reset = 10
        self.closed = True
        self.binary = ""
        self.prefs = None
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

        class FakePuppet(object):  # pylint: disable=too-few-public-methods

            @staticmethod
            def is_healthy():
                return self._is_healthy

        self._puppet = FakePuppet()

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


def create_target_binary(target, tmpdir):
    tmpdir.join("firefox.fuzzmanagerconf").write(
        "[Main]\n"
        "platform = x86-64\n"
        "product = mozilla-central\n"
        "os = linux\n"
    )
    target.binary = tmpdir.join("firefox").strpath
