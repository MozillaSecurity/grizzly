# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
import platform

import pytest

from ffpuppet import BrowserTerminatedError, BrowserTimeoutError, FFPuppet

from .puppet_target import PuppetTarget
from .target import Target, TargetError, TargetLaunchError, TargetLaunchTimeout

def test_puppet_target_01(mocker, tmp_path):
    """test creating a PuppetTarget"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_ffp.return_value.reason = FFPuppet.RC_CLOSED
    fake_ffp.return_value.log_length.return_value = 562
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 25) as target:
        assert target.closed
        assert target.detect_failure([], False) == Target.RESULT_NONE
        assert target.log_size() == 1124
        fake_ffp.return_value.log_length.assert_any_call("stderr")
        fake_ffp.return_value.log_length.assert_any_call("stdout")
        assert target.monitor is not None
        target.add_abort_token("test")
        assert fake_ffp.return_value.add_abort_token.call_count == 1
        target.save_logs("fake_dest")
        assert fake_ffp.return_value.save_logs.call_count == 1
    assert fake_ffp.return_value.clean_up.call_count == 1

def test_puppet_target_02(mocker, tmp_path):
    """test PuppetTarget.launch()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 35)
    with pytest.raises(TargetError, match=r"A prefs.js file is required"):
        target.launch("launch_target_page")
    assert fake_ffp.return_value.launch.call_count == 0
    target.prefs = str(fake_file)
    target.launch("launch_target_page")
    assert fake_ffp.return_value.launch.call_count == 1
    assert fake_ffp.return_value.close.call_count == 0
    fake_ffp.return_value.launch.side_effect = BrowserTimeoutError
    with pytest.raises(TargetLaunchTimeout):
        target.launch("launch_target_page")
    assert fake_ffp.return_value.launch.call_count == 2
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.return_value.launch.side_effect = BrowserTerminatedError
    with pytest.raises(TargetLaunchError):
        target.launch("launch_target_page")

def test_puppet_target_03(mocker, tmp_path):
    """test PuppetTarget.detect_failure()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_ffp.RC_ALERT = FFPuppet.RC_ALERT
    fake_ffp.RC_CLOSED = FFPuppet.RC_CLOSED
    fake_ffp.RC_EXITED = FFPuppet.RC_EXITED
    fake_ffp.RC_WORKER = FFPuppet.RC_WORKER
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 25)
    # no failures
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.reason = None
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert target.detect_failure(["memory"], False) == Target.RESULT_NONE
    assert not target.closed
    # test close
    fake_ffp.return_value.is_healthy.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_CLOSED
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_ffp.return_value.is_running.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    # test single process crash
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_ALERT
    assert target.detect_failure([], False) == Target.RESULT_FAILURE
    assert fake_ffp.return_value.close.call_count == 1
    # test multiprocess crash
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = True
    fake_ffp.return_value.reason = FFPuppet.RC_ALERT
    assert target.detect_failure([], False) == Target.RESULT_FAILURE
    assert fake_ffp.return_value.close.call_count == 1
    # test exit with no crash logs
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_EXITED
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_ffp.return_value.close.call_count == 1
    # test timeout
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.is_running.return_value = True
    fake_ffp.return_value.reason = None
    fake_ffp.return_value.cpu_usage.return_value = ((1234, 10), (1236, 75), (1238, 60))
    fake_os = mocker.patch("grizzly.target.puppet_target.os", autospec=True)
    assert target.detect_failure([], True) == Target.RESULT_FAILURE
    if platform.system() == "Linux":
        assert fake_os.kill.call_count == 1
        assert fake_ffp.return_value.wait.call_count == 1
    else:
        assert fake_os.kill.call_count == 0
        assert fake_ffp.return_value.wait.call_count == 0
    assert fake_ffp.return_value.close.call_count == 1
    # test timeout ignored
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.is_running.return_value = True
    fake_ffp.return_value.reason = None
    assert target.detect_failure(["timeout"], True) == Target.RESULT_IGNORED
    assert fake_ffp.return_value.close.call_count == 1
    # test worker
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_WORKER
    assert target.detect_failure([], False) == Target.RESULT_FAILURE
    assert fake_ffp.return_value.close.call_count == 1
    # test memory ignored
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_WORKER
    fake_ffp.return_value.available_logs.return_value = " ffp_worker_memory_usage "
    assert target.detect_failure(["memory"], False) == Target.RESULT_IGNORED
    assert fake_ffp.return_value.close.call_count == 1
    # test log-limit ignored
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_WORKER
    fake_ffp.return_value.available_logs.return_value = " ffp_worker_log_size "
    assert target.detect_failure(["log-limit"], False) == Target.RESULT_IGNORED
    assert fake_ffp.return_value.close.call_count == 1
    # test browser closing test case
    fake_ffp.return_value.close.call_count = 0
    fake_ffp.return_value.wait.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_EXITED
    target.forced_close = False
    target.rl_countdown = 0
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_ffp.return_value.wait.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1

@pytest.mark.skipif(platform.system() == "Windows",
                    reason="Unsupported on Windows")
def test_puppet_target_04(mocker, tmp_path):
    """test PuppetTarget.dump_coverage()"""
    mocker.patch("grizzly.target.puppet_target.time.sleep", autospec=True)
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_psutil = mocker.patch("grizzly.target.puppet_target.psutil", autospec=True)
    fake_psutil.Process.return_value.children.return_value = (mocker.Mock(pid=123),)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 10)
    fake_os = mocker.patch("grizzly.target.puppet_target.os", autospec=True)
    # not running
    fake_ffp.return_value.get_pid.return_value = None
    target.dump_coverage()
    assert not fake_os.kill.call_count
    assert fake_ffp.return_value.get_pid.call_count == 1
    assert fake_psutil.process_iter.call_count == 0
    # timeout
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.get_pid.return_value = 1234
    target.dump_coverage(timeout=0)
    assert fake_os.kill.call_count == 2
    assert fake_psutil.process_iter.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 1
    # browser crashes
    fake_os.kill.call_count = 0
    fake_ffp.return_value.is_healthy.call_count = 0
    fake_ffp.return_value.is_healthy.side_effect = [True, False]
    fake_ffp.return_value.get_pid.return_value = 1234
    target.dump_coverage()
    assert fake_os.kill.call_count == 2
    assert fake_psutil.process_iter.call_count == 2
    assert fake_ffp.return_value.is_healthy.call_count == 2
    # wait for files
    fake_os.kill.call_count = 0
    fake_ffp.return_value.is_healthy.call_count = 0
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.is_healthy.side_effect = None
    fake_ffp.return_value.get_pid.return_value = 123
    fpi = mocker.Mock(iters=0)
    def fake_process_iter(*args, **kwargs):
        fpi.iters += 1
        if fpi.iters == 1:
            yield mocker.Mock(info={
                "pid": 123,
                "ppid": 0,
                "open_files": (mocker.Mock(path="a.bin"), mocker.Mock(path="/a/s/d"))
            })
            yield mocker.Mock(info={
                "pid": 321,
                "ppid": 0,
                "open_files": (mocker.Mock(path="a.bin"),)
            })
        elif fpi.iters == 2:
            yield mocker.Mock(info={
                "pid": 123,
                "ppid": 0,
                "open_files": (mocker.Mock(path="a.gcda"),)
            })
            yield mocker.Mock(info={
                "pid": 321,
                "ppid": 0,
                "open_files": (mocker.Mock(path="a.bin"),)
            })
        elif fpi.iters == 3:
            yield mocker.Mock(info={
                "pid": 123,
                "ppid": 0,
                "open_files": (mocker.Mock(path="a.bin"),)
            })
            yield mocker.Mock(info={
                "pid": 321,
                "ppid": 0,
                "open_files": (mocker.Mock(path="ignore.gcda"),)
            })
    fake_psutil.process_iter = fake_process_iter
    target.dump_coverage()
    assert fpi.iters == 3
    assert fake_os.kill.call_count == 2

def test_puppet_target_05(mocker, tmp_path):
    """test is_idle()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 10)
    fake_ffp.return_value.cpu_usage.return_value = [(999, 30), (998, 20), (997, 10)]
    assert not target.is_idle(0)
    assert not target.is_idle(25)
    assert target.is_idle(50)

def test_puppet_target_06(mocker, tmp_path):
    """test PuppetTarget.monitor"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 25)
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.is_healthy.return_value = False
    assert target.monitor is not None
    assert not target.monitor.is_healthy()
    assert not target.monitor.is_running()
    fake_ffp.return_value.is_running.return_value = True
    fake_ffp.return_value.is_healthy.return_value = True
    assert target.monitor.is_healthy()
    assert target.monitor.is_running()
    fake_ffp.return_value.launches = 123
    assert target.monitor.launches == 123
    fake_ffp.return_value.log_length.return_value = 100
    assert target.monitor.log_length("stdout") == 100
    target.monitor.clone_log("somelog")
    assert fake_ffp.return_value.clone_log.call_count == 1
