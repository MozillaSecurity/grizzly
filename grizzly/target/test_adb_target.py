# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .adb_device import ADBSession
from .adb_target import ADBTarget
from .target import Target

def test_adb_target_01(mocker, tmp_path):
    """test creating a simple ADBTarget"""
    fake_process = mocker.patch("grizzly.target.adb_target.ADBProcess", autospec=True)
    fake_process.RC_ALERT = "ALERT"
    fake_process.RC_CLOSED = "CLOSED"
    fake_process.RC_EXITED = "EXITED"
    fake_process.return_value.is_healthy.return_value = False
    fake_process.return_value.is_running.return_value = False
    fake_process.return_value.launches = 0
    fake_process.return_value.reason = fake_process.RC_CLOSED
    fake_sess_obj = mocker.Mock(spec=ADBSession)
    fake_sess_obj.connected = True
    fake_sess_obj.symbols = {}
    fake_session = mocker.patch("grizzly.target.adb_target.ADBSession", autospec=True)
    fake_session.create.return_value = fake_sess_obj
    fake_session.get_package_name.return_value = "the_name"
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    target = ADBTarget(str(fake_apk), None, 300, 25, 5000)
    try:
        assert target.closed
        assert target.forced_close
        assert target.monitor is not None
        assert target.detect_failure([], False) == Target.RESULT_NONE
        assert not target.log_size()
    finally:
        target.cleanup()
    assert not target.monitor.is_running()
    assert not target.monitor.is_healthy()
    assert target.monitor.launches == 0
    assert fake_session.create.call_count == 1
    assert fake_session.get_package_name.call_count == 1
    assert "the_name" in fake_sess_obj.symbols
    assert fake_sess_obj.reverse_remove.call_count == 1
    assert fake_sess_obj.disconnect.call_count == 1

def test_adb_target_02(mocker, tmp_path):
    """test ADBTarget.launch()"""
    fake_process = mocker.patch("grizzly.target.adb_target.ADBProcess", autospec=True)
    fake_process.return_value.launches = 0
    mocker.patch("grizzly.target.adb_target.ADBSession", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    target = ADBTarget(str(fake_apk), None, 300, 25, 5000)
    target.launch("fake.url")
    assert fake_process.return_value.launch.call_count == 1
    assert target.monitor.is_running()
    assert target.monitor.is_healthy()

def test_adb_target_03(mocker, tmp_path):
    """test ADBTarget.launch()"""
    fake_process = mocker.patch("grizzly.target.adb_target.ADBProcess", autospec=True)
    mocker.patch("grizzly.target.adb_target.ADBSession", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    target = ADBTarget(str(fake_apk), None, 300, 25, 5000)
    # test everything is running
    fake_process.return_value.is_healthy.return_value = True
    fake_process.return_value.is_running.return_value = True
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_process.return_value.close.call_count == 0
    # test timeout case
    assert target.detect_failure([], True) == Target.RESULT_FAILURE
    assert fake_process.return_value.close.call_count == 1
    fake_process.return_value.close.reset_mock()
    # test ignored timeout case
    assert target.detect_failure(["timeout"], True) == Target.RESULT_IGNORED
    assert fake_process.return_value.close.call_count == 1
    fake_process.return_value.close.reset_mock()
    # test process not running
    fake_process.return_value.is_healthy.return_value = False
    fake_process.return_value.is_running.return_value = False
    fake_process.return_value.reason = fake_process.RC_EXITED
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_process.return_value.close.call_count == 1
    fake_process.return_value.close.reset_mock()
    # test process exited
    fake_process.return_value.is_healthy.return_value = False
    fake_process.return_value.is_running.return_value = False
    fake_process.return_value.reason = fake_process.RC_CLOSED
    assert target.detect_failure([], False) == Target.RESULT_NONE
    assert fake_process.return_value.close.call_count == 1
    fake_process.return_value.close.reset_mock()
    # test process running but is_healthy() failed
    fake_process.return_value.is_healthy.return_value = False
    fake_process.return_value.is_running.return_value = True
    fake_process.return_value.reason = fake_process.RC_ALERT
    assert target.detect_failure([], False) == Target.RESULT_FAILURE
    assert fake_process.return_value.close.call_count == 1
    fake_process.return_value.close.reset_mock()
