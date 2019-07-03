# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

import os
import signal
import tempfile
import threading
import time

import pytest

from ffpuppet import FFPuppet

from .puppet_target import PuppetTarget
from .target import Target, TargetError
from .target_monitor import TargetMonitor


class FakePuppet(object):
    def __init__(self, use_rr, use_valgrind, use_xvfb):  # pylint: disable=unused-argument
        self.reason = FFPuppet.RC_CLOSED
        self.running = False
        self._launches = 0
        self.test_check_abort = False  # used to control testing
        self.test_crashed = False  # used to control testing
        self.test_running = False  # used to control testing
        self.test_available_logs = list()  # used to control testing

    def add_abort_token(self, token):  # pylint: disable=no-self-use
        pass

    def available_logs(self):
        return self.test_available_logs

    def clean_up(self):
        self.close()

    def clone_log(self, log_id, offset=0):  # pylint: disable=no-self-use,unused-argument
        assert log_id is not None
        tmp_fd, log_file = tempfile.mkstemp(
            suffix="_log.txt",
            prefix="test_")
        os.close(tmp_fd)
        with open(log_file, "wb") as log_fp:
            log_fp.write(b"test")
        return log_file

    def close(self):
        # the reason code is dependent on the state of test_crashed and test_running
        # this MUST model FFPuppet.close()
        if self.reason is not None:
            self.test_check_abort = False
            self.test_crashed = False
            self.test_running = False
            return
        if self.test_crashed:
            self.reason = FFPuppet.RC_ALERT
        elif self.test_check_abort:
            self.reason = FFPuppet.RC_WORKER
        elif self.test_running:
            self.reason = FFPuppet.RC_CLOSED
        else:
            self.reason = FFPuppet.RC_EXITED
        self.test_check_abort = False
        self.test_crashed = False
        self.test_running = False

    def get_pid(self):  # pylint: disable=no-self-use
        return os.getpid()

    def is_healthy(self):
        return not self.test_crashed and self.test_running and not self.test_check_abort

    def is_running(self):
        return self.test_running

    def launch(self, binary, launch_timeout=0, location=None, log_limit=0, memory_limit=0,  # pylint: disable=unused-argument,too-many-arguments
               prefs_js=None, extension=None, env_mod=None):  # pylint: disable=unused-argument,too-many-arguments
        self.reason = None
        self.test_crashed = False
        self.test_running = True

    @property
    def launches(self):
        return self._launches

    def log_length(self, log_id):  # pylint: disable=no-self-use
        if log_id == "stderr":
            return 1024
        if log_id == "stdout":
            return 100
        return int(log_id.split("=")[1])

    def save_logs(self, *args, **kwargs):
        pass

    def wait(self, timeout=0):  # pylint: disable=no-self-use,unused-argument
        return 1234  # successful wait()

class SimpleTarget(Target):
    def cleanup(self):
        pass
    def close(self):
        pass
    @property
    def closed(self):
        pass
    def detect_failure(self, ignored, was_timeout):
        pass
    def launch(self, location, env_mod=None):
        pass
    @property
    def monitor(self):
        return self._monitor
    def save_logs(self, *args, **kwargs):
        pass

def test_target_01(tmp_path):
    """test creating a simple Target"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = SimpleTarget(str(fake_file), str(fake_file), 321, 2, 3, str(fake_file), 25)
    assert target.binary == str(fake_file)
    assert target.extension == str(fake_file)
    assert target.forced_close
    assert target.launch_timeout == 321
    assert target.log_size() == 0
    assert target.log_limit == 2 * 0x100000
    assert target.memory_limit == 3 * 0x100000
    assert target.rl_countdown == 0
    assert target.rl_reset == 25
    assert target.poll_for_idle(0, 0) == target.POLL_BUSY
    assert target.prefs == str(fake_file)
    assert not target.expect_close

def test_target_02(tmp_path):
    """test setting Target.forced_close"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    os.environ["GRZ_FORCED_CLOSE"] = "0"
    try:
        target = SimpleTarget(str(fake_file), None, 300, 25, 5000, None, 25)
        assert not target.forced_close
        assert target.extension is None
        assert target.prefs is None
        target.rl_countdown = 1
        assert not target.expect_close
        target.rl_countdown = 0
        assert target.expect_close
    finally:
        os.environ.pop("GRZ_FORCED_CLOSE", None)

def test_target_03(tmp_path, mocker):
    """test Target.check_relaunch() and Target.step()"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = SimpleTarget(str(fake_file), None, 300, 25, 5000, None, 1)
    try:
        target._monitor = mocker.Mock(spec=TargetMonitor)
        target._monitor.is_healthy.return_value = True
        # test skipping relaunch
        target.rl_countdown = 2
        target.step()
        assert target.rl_countdown == 1
        target.check_relaunch(wait=60)
        # test triggering relaunch
        target.rl_countdown = 1
        target.step()
        assert target.rl_countdown == 0
        target.check_relaunch(wait=0)
        # test with "crashed" process
        target._monitor.is_healthy.return_value = False
        target.rl_countdown = 0
        target.step()
        target.check_relaunch(wait=5)
    finally:
        target.cleanup()

def test_puppet_target_01(tmp_path):
    """test creating a PuppetTarget"""
    PuppetTarget.PUPPET = FakePuppet
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 25)
    try:
        assert target.closed
        assert target.detect_failure([], False) == Target.RESULT_NONE
        assert target.log_size() == 1124
        assert target.monitor is not None
        assert isinstance(target._puppet, FakePuppet)
        target.add_abort_token("test")
        target.save_logs()
    finally:
        target.cleanup()

def test_puppet_target_02(tmp_path):
    """test PuppetTarget.launch()"""
    PuppetTarget.PUPPET = FakePuppet
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 35)
    with pytest.raises(TargetError, match=r"A prefs.js file is required"):
        target.launch("launch_target_page")
    target.prefs = str(fake_file)
    try:
        target.launch("launch_target_page")
        assert not target.closed
        assert target.detect_failure([], False) == Target.RESULT_NONE
        target.close()
        assert target.closed
    finally:
        target.cleanup()

def test_puppet_target_03(tmp_path):
    """test PuppetTarget.detect_failure()"""
    PuppetTarget.PUPPET = FakePuppet
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 25)
    try:
        target.launch("launch_target_page")
        # no failures
        assert target.detect_failure([], False) == Target.RESULT_NONE
        assert target.detect_failure(["memory"], False) == Target.RESULT_NONE
        assert not target.closed
        assert target._puppet.reason is None
        # test close
        target.close()
        assert target.detect_failure([], False) == Target.RESULT_NONE
        assert target.closed
        assert target._puppet.reason == FFPuppet.RC_CLOSED
        # test single process crash
        target.launch("launch_page")
        target._puppet.test_crashed = True
        target._puppet.test_running = False
        assert target.detect_failure([], False) == Target.RESULT_FAILURE
        assert target.closed
        # test multiprocess crash
        target.launch("launch_page")
        target._puppet.test_crashed = True
        assert target.detect_failure([], False) == Target.RESULT_FAILURE
        assert target._puppet.reason == FFPuppet.RC_ALERT
        assert target.closed
        # test exit with no crash logs
        target.launch("launch_page")
        target._puppet.test_running = False
        assert target.detect_failure([], False) == Target.RESULT_NONE
        assert target._puppet.reason == FFPuppet.RC_EXITED
        assert target.closed
        # test timeout
        target.launch("launch_page")
        target._puppet.test_running = True
        assert target.detect_failure([], True) == Target.RESULT_FAILURE
        assert target.closed
        # test timeout ignored
        target.launch("launch_page")
        target._puppet.test_running = True
        assert target.detect_failure(["timeout"], True) == Target.RESULT_IGNORED
        assert target.closed
        # test worker
        target.launch("launch_page")
        target._puppet.test_check_abort = True
        assert target.detect_failure([], False) == Target.RESULT_FAILURE
        assert target._puppet.reason == FFPuppet.RC_WORKER
        assert target.closed
        # test memory ignored
        target.launch("launch_page")
        target._puppet.test_check_abort = True
        target._puppet.test_available_logs = ["ffp_worker_memory_usage"]
        assert target.detect_failure(["memory"], False) == Target.RESULT_IGNORED
        assert target._puppet.reason == FFPuppet.RC_WORKER
        assert target.closed
        # test log-limit ignored
        target.launch("launch_page")
        target._puppet.test_check_abort = True
        target._puppet.test_available_logs = ["ffp_worker_log_size"]
        assert target.detect_failure(["log-limit"], False) == Target.RESULT_IGNORED
        assert target.closed
    finally:
        # test browser closing test case
        target.cleanup()
    os.environ["GRZ_FORCED_CLOSE"] = "0"
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 1)
    try:
        target.launch("launch_page")
        target.step()
        assert target.expect_close
        assert target.detect_failure([], False) == Target.RESULT_NONE
        target.close()
    finally:
        os.environ.pop("GRZ_FORCED_CLOSE", None)
        target.cleanup()

def test_puppet_target_04(tmp_path):
    """test PuppetTarget.dump_coverage()"""
    PuppetTarget.PUPPET = FakePuppet
    class SigCatcher(object):  # pylint: disable=too-few-public-methods
        CAUGHT = False
        @staticmethod
        def signal_handler(*args):  # pylint: disable=unused-argument
            SigCatcher.CAUGHT = True
    sig_catcher = SigCatcher()
    signal.signal(signal.SIGUSR1, sig_catcher.signal_handler)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 10)
    target.dump_coverage()
    assert not sig_catcher.CAUGHT
    target.launch("launch_page")
    target.dump_coverage()
    assert sig_catcher.CAUGHT  # not sure if there is a race here...

def test_puppet_target_05(tmp_path):
    """test poll_for_idle()"""
    PuppetTarget.PUPPET = FakePuppet
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 10)
    assert target.poll_for_idle(90, 0.2), "the test process should be mostly idle"
    evt = threading.Event()
    def busy_wait():
        while not evt.is_set():
            pass
    waiter = threading.Thread(target=busy_wait)
    try:
        waiter.start()
        time.sleep(0.1)
        assert target.poll_for_idle(10, 0.2) == Target.POLL_BUSY, "the test process should be busy"
    finally:
        evt.set()
        waiter.join()

def test_puppet_target_06(tmp_path):
    """test PuppetTarget.monitor"""
    PuppetTarget.PUPPET = FakePuppet
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 25)
    try:
        assert target.monitor is not None
        assert not target.monitor.is_healthy()
        assert not target.monitor.is_running()
        assert target.monitor.launches == 0
        assert target.monitor.log_length("stdout") == 100
        cloned = target.monitor.clone_log("somelog")
        assert os.path.isfile(cloned)
        os.remove(cloned)
    finally:
        target.cleanup()
