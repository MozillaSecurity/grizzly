# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from os.path import isfile
from platform import system

from pytest import mark, raises

from ffpuppet import BrowserTerminatedError, BrowserTimeoutError, FFPuppet

from .puppet_target import PuppetTarget
from .target import Target, TargetLaunchError, TargetLaunchTimeout

def test_puppet_target_01(mocker, tmp_path):
    """test creating a PuppetTarget"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_ffp.return_value.reason = FFPuppet.RC_CLOSED
    fake_ffp.return_value.log_length.return_value = 562
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), None, 300, 25, 5000, None, 25) as target:
        assert target.closed
        assert target._browser_logs is None
        assert isfile(target.prefs)
        prefs_file = target.prefs
        assert target._tmp_prefs
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
    assert not isfile(prefs_file)
    # with extra args
    with PuppetTarget(str(fake_file), None, 1, 1, 1, None, 1, rr=True, fake=1) as target:
        pass

def test_puppet_target_02(mocker, tmp_path):
    """test PuppetTarget.launch()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    # test providing prefs.js
    with PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 35) as target:
        assert target.prefs == str(fake_file)
        assert not target._tmp_prefs
        target.launch("launch_target_page")
        assert target._browser_logs is None
        assert fake_ffp.return_value.launch.call_count == 1
        assert fake_ffp.return_value.close.call_count == 0
        fake_ffp.return_value.launch.side_effect = BrowserTimeoutError
        with raises(TargetLaunchTimeout):
            target.launch("launch_target_page")
        assert fake_ffp.return_value.launch.call_count == 2
        assert fake_ffp.return_value.close.call_count == 1
        fake_ffp.return_value.launch.side_effect = BrowserTerminatedError
        with raises(TargetLaunchError):
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
    fake_ffp.reset_mock()
    # test close
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_CLOSED
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_ffp.return_value.is_running.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test single process crash
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_ALERT
    assert target.detect_failure([], False) == Target.RESULT_FAILURE
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test multiprocess crash
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = True
    fake_ffp.return_value.reason = FFPuppet.RC_ALERT
    assert target.detect_failure([], False) == Target.RESULT_FAILURE
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test exit with no crash logs
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_EXITED
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test timeout
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.is_running.return_value = True
    fake_ffp.return_value.reason = None
    fake_ffp.return_value.cpu_usage.return_value = ((1234, 10), (1236, 75), (1238, 60))
    fake_kill = mocker.patch("grizzly.target.puppet_target.kill", autospec=True)
    assert target.detect_failure([], True) == Target.RESULT_FAILURE
    if system() == "Linux":
        assert fake_kill.call_count == 1
        assert fake_ffp.return_value.wait.call_count == 1
    else:
        assert fake_kill.call_count == 0
        assert fake_ffp.return_value.wait.call_count == 0
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test timeout ignored
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.is_running.return_value = True
    fake_ffp.return_value.reason = None
    assert target.detect_failure(["timeout"], True) == Target.RESULT_IGNORED
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test worker
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_WORKER
    assert target.detect_failure([], False) == Target.RESULT_FAILURE
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test memory ignored
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_WORKER
    fake_ffp.return_value.available_logs.return_value = " ffp_worker_memory_usage "
    assert target.detect_failure(["memory"], False) == Target.RESULT_IGNORED
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test log-limit ignored
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_WORKER
    fake_ffp.return_value.available_logs.return_value = " ffp_worker_log_size "
    assert target.detect_failure(["log-limit"], False) == Target.RESULT_IGNORED
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    # test browser closing test case
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.is_running.return_value = False
    fake_ffp.return_value.reason = FFPuppet.RC_EXITED
    target.forced_close = False
    target.rl_countdown = 0
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_ffp.return_value.wait.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1

@mark.skipif(system() == "Windows", reason="Unsupported on Windows")
def test_puppet_target_04(mocker, tmp_path):
    """test PuppetTarget.dump_coverage()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_proc = mocker.patch("grizzly.target.puppet_target.Process", autospec=True)
    fake_proc.return_value.children.return_value = (mocker.Mock(pid=101),)
    fake_proc_iter = mocker.patch("grizzly.target.puppet_target.process_iter", autospec=True)
    mocker.patch("grizzly.target.puppet_target.sleep", autospec=True)
    fake_time = mocker.patch("grizzly.target.puppet_target.time", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 10)
    fake_kill = mocker.patch("grizzly.target.puppet_target.kill", autospec=True)
    # not running
    target.rl_countdown = 1
    fake_ffp.return_value.get_pid.return_value = None
    target.dump_coverage()
    assert not fake_kill.call_count
    assert fake_ffp.return_value.get_pid.call_count == 1
    assert fake_proc_iter.call_count == 0
    # gcda not found
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.get_pid.return_value = 100
    fake_time.side_effect = (0, 1, 10)
    target.dump_coverage()
    assert fake_kill.call_count == 2
    assert fake_proc_iter.call_count == 2
    assert fake_ffp.return_value.is_healthy.call_count == 2
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    # browser crashes
    fake_ffp.return_value.is_healthy.side_effect = (True, False)
    fake_time.side_effect = None
    fake_time.return_value = 1.0
    target.dump_coverage()
    assert fake_kill.call_count == 2
    assert fake_proc_iter.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 2
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    # timeout while waiting for files
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.is_healthy.side_effect = None
    fake_ffp.return_value.get_pid.return_value = 100
    fake_proc_iter.return_value = (
        mocker.Mock(info={"pid": 100, "ppid": 0, "open_files": (mocker.Mock(path="a.gcda"),)}),
    )
    fake_time.side_effect = (0, 1, 20, 20)
    target.dump_coverage(timeout=15)
    assert fake_kill.call_count == 3
    assert fake_proc_iter.call_count == 2
    assert fake_ffp.return_value.is_healthy.call_count == 2
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    # wait for files (success)
    fake_ffp.return_value.get_pid.return_value = 100
    fake_time.side_effect = None
    fake_time.return_value = 1.0
    fake_proc_iter.side_effect = (
        (
            mocker.Mock(info={"pid": 100, "ppid": 0, "open_files": (mocker.Mock(path="a.bin"), mocker.Mock(path="/a/s/d"))}),
            mocker.Mock(info={"pid": 101, "ppid": 100, "open_files": None}),
            mocker.Mock(info={"pid": 999, "ppid": 0, "open_files": None})
        ),
        (
            mocker.Mock(info={"pid": 100, "ppid": 0, "open_files": (mocker.Mock(path="a.gcda"),)}),
        ),
        (
            mocker.Mock(info={"pid": 100, "ppid": 0, "open_files": (mocker.Mock(path="a.bin"),)}),
            mocker.Mock(info={"pid": 999, "ppid": 0, "open_files": (mocker.Mock(path="ignore.gcda"),)})
        )
    )
    target.dump_coverage()
    assert fake_proc_iter.call_count == 3
    assert fake_kill.call_count == 2

def test_puppet_target_05(mocker, tmp_path):
    """test is_idle()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_ffp.return_value.cpu_usage.return_value = [(999, 30), (998, 20), (997, 10)]
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 10) as target:
        assert not target.is_idle(0)
        assert not target.is_idle(25)
        assert target.is_idle(50)

def test_puppet_target_06(mocker, tmp_path):
    """test PuppetTarget.monitor"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 25) as target:
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

def test_puppet_target_07(mocker, tmp_path):
    """test PuppetTarget with GRZ_BROWSER_LOGS set"""
    browser_logs = (tmp_path / "browser_logs")
    fake_getenv = mocker.patch("grizzly.target.puppet_target.getenv", autospec=True)
    fake_getenv.return_value = str(browser_logs)
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), None, 300, 25, 5000, str(fake_file), 35) as target:
        target.launch("launch_target_page")
        assert target._browser_logs == str(browser_logs)
        assert browser_logs.is_dir()
        target.cleanup()
        assert target._browser_logs is None
    assert fake_ffp.return_value.save_logs.call_count == 1
