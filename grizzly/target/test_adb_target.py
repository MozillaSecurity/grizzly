# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from pytest import mark

from .adb_device import ADBProcess, ADBSession
from .adb_target import ADBTarget
from .target import Result

def test_adb_target_01(mocker, tmp_path):
    """test creating a simple ADBTarget"""
    fake_process = mocker.patch("grizzly.target.adb_target.ADBProcess", autospec=True)
    fake_process.RC_ALERT = ADBProcess.RC_ALERT
    fake_process.RC_CLOSED = ADBProcess.RC_CLOSED
    fake_process.RC_EXITED = ADBProcess.RC_EXITED
    fake_process.return_value.is_healthy.return_value = False
    fake_process.return_value.is_running.return_value = False
    fake_process.return_value.launches = 0
    fake_process.return_value.reason = fake_process.RC_CLOSED
    fake_sess_obj = mocker.Mock(spec=ADBSession, connected=True, symbols={})
    fake_session = mocker.patch("grizzly.target.adb_target.ADBSession", autospec=True)
    fake_session.create.return_value = fake_sess_obj
    fake_session.get_package_name.return_value = "the_name"
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with ADBTarget(str(fake_apk), 300, 25, 5000) as target:
        assert target.closed
        assert target.forced_close
        assert target.monitor is not None
        assert target.check_result(False) == Result.NONE
        assert not target.log_size()
        target.cleanup()
        assert fake_sess_obj.reverse_remove.call_count == 1
        assert fake_sess_obj.disconnect.call_count == 1
    assert not target.monitor.is_running()
    assert not target.monitor.is_healthy()
    assert target.monitor.launches == 0
    assert fake_session.create.call_count == 1
    assert fake_session.get_package_name.call_count == 1
    assert "the_name" in fake_sess_obj.symbols

def test_adb_target_02(mocker, tmp_path):
    """test ADBTarget.launch()"""
    fake_process = mocker.patch("grizzly.target.adb_target.ADBProcess", autospec=True)
    fake_process.return_value.launches = 0
    mocker.patch("grizzly.target.adb_target.ADBSession", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with ADBTarget(str(fake_apk), 300, 25, 5000) as target:
        target.launch("fake.url")
        assert fake_process.return_value.launch.call_count == 1
        assert target.monitor.is_running()
        assert target.monitor.is_healthy()

@mark.parametrize(
    "healthy, reason, result, closes",
    [
        # running as expected - no failures
        (True, None, Result.NONE, 0),
        # browser process closed
        (False, ADBProcess.RC_CLOSED, Result.NONE, 1),
        # browser process crashed
        (False, ADBProcess.RC_ALERT, Result.FOUND, 1),
        # browser exit with no crash logs
        (False, ADBProcess.RC_EXITED, Result.NONE, 1),
    ],
)
def test_adb_target_03(mocker, tmp_path, healthy, reason, result, closes):
    """test ADBTarget.check_result()"""
    fake_process = mocker.patch("grizzly.target.adb_target.ADBProcess", autospec=True)
    fake_process.RC_ALERT = ADBProcess.RC_CLOSED
    fake_process.RC_CLOSED = ADBProcess.RC_CLOSED
    fake_process.RC_EXITED = ADBProcess.RC_EXITED
    mocker.patch("grizzly.target.adb_target.ADBSession", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with ADBTarget(str(fake_apk), 300, 25, 5000) as target:
        # test everything is running
        fake_process.return_value.is_healthy.return_value = healthy
        fake_process.return_value.reason = reason
        assert target.check_result(None) == result
        assert fake_process.return_value.close.call_count == closes

def test_adb_target_04(mocker, tmp_path):
    """test ADBTarget.handle_hang()"""
    fake_process = mocker.patch("grizzly.target.adb_target.ADBProcess", autospec=True)
    mocker.patch("grizzly.target.adb_target.ADBSession", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with ADBTarget(str(fake_apk), 300, 25, 5000) as target:
        fake_process.return_value.is_healthy.return_value = True
        fake_process.return_value.is_running.return_value = True
        assert not target.handle_hang()
        assert fake_process.return_value.close.call_count == 1
