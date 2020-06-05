# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import unicode_literals
import os
from grizzly.target.target import Target
from grizzly.common import Reporter
from grizzly.reduce import crash, reduce


class BaseFakeReporter(Reporter):
    def _process_report(self, _):
        pass

    def _reset(self):
        pass

    def _submit_report(self, *_args, **_kwds):
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
    RESULT_NONE = 0
    RESULT_FAILURE = 1
    RESULT_IGNORED = 2

    def __init__(self, *args, **kwds):
        self.rl_reset = 10
        self.closed = True
        self.binary = ""
        self.forced_close = os.getenv("GRZ_FORCED_CLOSE", "1").lower() not in ("false", "0")
        self.prefs = None
        self.rl_countdown = 0
        self.use_valgrind = False

        self._calls = {
            "check_relaunch": 0,
            "cleanup": 0,
            "close": 0,
            "detect_failure": 0,
            "is_idle": 0,
            "launch": 0,
            "save_logs": 0,
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

    def is_idle(self, *args, **kwds):
        self._calls["is_idle"] += 1
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


class TestReductionJob(reduce.ReductionJob):
    """Stub to fake parts of grizzly.reduce.ReductionJob needed for testing the reduce loop"""
    __slots__ = []

    def __init__(self, tmp_path, create_binary=True, testcase_cache=False, skip_analysis=True):
        super(TestReductionJob, self).__init__([], FakeTarget(), 60, False, False, 0, 1, 1, 3, 25,
                                               FakeReduceStatus(),
                                               testcase_cache=testcase_cache,
                                               skip_analysis=skip_analysis)
        if create_binary:
            create_target_binary(self.target, tmp_path)

    def lithium_init(self):
        pass

    def close(self, *_args, **_kwds):
        super(TestReductionJob, self).close(keep_temp=False)

    def _run(self, testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs)
        testcase.duration = 0.1
        with open(self.reduce_file) as fp:
            return "required" in fp.read()

    def lithium_cleanup(self):
        pass


class TestMainReductionJob(TestReductionJob):
    __slots__ = []

    def __init__(self, *_args, **_kwds):
        super(TestMainReductionJob, self).__init__(None, create_binary=False)


# this is the same as TestReductionJob, but for CrashReductionJob
class TestMainCrashReductionJob(TestMainReductionJob, crash.CrashReductionJob):
    """Stub to fake parts of grizzly.crash.CrashReductionJob needed for testing the reduce loop"""
    __slots__ = []


class TestReductionJobAlt(TestReductionJob):
    """Version of TestReductionJob that only reports alternate crashes"""
    __slots__ = ['__first_run']

    def lithium_init(self):
        self.__first_run = True

    def _run(self, testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs)
        testcase.duration = 0.1
        with open(self.reduce_file) as fp:
            if "required" in fp.read():
                self.on_other_crash_found(testcase, temp_prefix)
        if self.__first_run:
            self.__first_run = False
            return True
        return False


class TestReductionJobKeepHarness(TestReductionJob):
    """Version of TestReductionJob that keeps the entire harness"""
    __slots__ = ['__init_data']

    def lithium_init(self):
        self.__init_data = None
        if os.path.basename(self.reduce_file).startswith("harness_"):
            with open(self.reduce_file) as harness_fp:
                self.__init_data = harness_fp.read()

    def _run(self, testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs)
        testcase.duration = 0.1
        if self.__init_data is not None:
            with open(self.reduce_file) as fp:
                return self.__init_data == fp.read()
        else:
            with open(self.reduce_file) as fp:
                return "required" in fp.read()


class TestReductionJobSemiReliable(TestReductionJob):
    """Version of TestReductionJob that returns interesting N times only"""
    __slots__ = ['__interesting_times', '__interesting_count', '__require_no_harness']

    def __init__(self, *args, **kwds):
        super(TestReductionJobSemiReliable, self).__init__(*args, **kwds)
        self.__interesting_times = 0
        self.__interesting_count = 0
        self.__require_no_harness = False

    def test_set_n(self, n, require_no_harness=False):
        self.__interesting_times = n
        self.__interesting_count = 0
        self.__require_no_harness = require_no_harness

    def _run(self, testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs)
        testcase.duration = 0.1
        if self.__require_no_harness and not self._no_harness:
            return False
        self.__interesting_count += 1
        return self.__interesting_count <= self.__interesting_times
