# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from fxpoppet.adb_process import ADBLaunchError, Reason
from fxpoppet.adb_session import ADBSession, ADBSessionError
from pytest import mark, raises

from .fenix_target import FenixMonitor, FenixTarget
from .target import Result, TargetLaunchError


def test_fenix_target_missing_package_name(mocker, tmp_path):
    """test FenixTarget missing package name"""
    session_cls = mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    session_cls.get_package_name.return_value = None
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with raises(RuntimeError, match="Could not find package name."):
        FenixTarget(fake_apk, 300, 25, 5000)


def test_fenix_target_adb_proc_error(mocker, tmp_path):
    """test FenixTarget ADBProcess error"""
    mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    mocker.patch(
        "grizzly.target.fenix_target.ADBProcess", side_effect=ADBSessionError("test")
    )
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with raises(ADBSessionError, match="test"):
        FenixTarget(fake_apk, 300, 25, 5000)


def test_fenix_target_launch_missing_device(mocker, tmp_path):
    """test FenixTarget.launch() missing device"""
    session_cls = mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    session_cls.create.return_value.wait_for_boot.return_value = False
    mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with (
        raises(RuntimeError, match="Device not available"),
        FenixTarget(fake_apk, 300, 25, 5000) as target,
    ):
        target.launch("foo")


def test_fenix_target_launch_failure(mocker, tmp_path):
    """test FenixTarget ADBProcess.launch() failure"""
    mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    mocker.patch("grizzly.target.fenix_target.FenixTarget.create_report", autospec=True)
    proc_cls = mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    proc_cls.return_value.launch.side_effect = ADBLaunchError("test")
    with (
        raises(TargetLaunchError, match="test"),
        FenixTarget(fake_apk, 300, 25, 5000) as target,
    ):
        target.launch("foo")


@mark.parametrize(
    "kwargs",
    [
        # no extra kwargs
        {},
        # unsupported debuggers
        {"pernosco": True, "rr": True},
        # unknown kwargs
        {"unknown_kwarg": "1"},
    ],
)
def test_fenix_target_simple(mocker, tmp_path, kwargs):
    """test creating a simple FenixTarget"""
    # pylint: disable=protected-access
    fake_process = mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    fake_process.return_value.is_healthy.return_value = False
    fake_process.return_value.is_running.return_value = False
    fake_process.return_value.launches = 0
    fake_process.return_value.reason = Reason.CLOSED
    fake_sess_obj = mocker.Mock(spec_set=ADBSession, connected=True, symbols={})
    fake_session = mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    fake_session.create.return_value = fake_sess_obj
    fake_session.get_package_name.return_value = "the_name"
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with FenixTarget(fake_apk, 300, 25, 5000, **kwargs) as target:
        assert target.closed
        assert target.forced_close
        assert target.monitor is not None
        assert not target.https()
        assert "foo" not in target.environ
        target.merge_environment({"foo": "bar"})
        assert "foo" in target.environ
        assert target.check_result(None) == Result.NONE
        assert not target.log_size()
        target.reverse(5345, 4323)
        assert target._prefs is None
        target.process_assets()
        assert target._prefs is not None
        target.cleanup()
        assert fake_sess_obj.reverse_remove.call_count == 1
        assert fake_sess_obj.disconnect.call_count == 1
    assert not target.monitor.is_running()
    assert not target.monitor.is_healthy()
    assert target.monitor.launches == 0
    assert fake_session.create.call_count == 1
    assert fake_session.get_package_name.call_count == 1
    assert "the_name" in fake_sess_obj.symbols


def test_fenix_target_create_session_failed(mocker, tmp_path):
    """test FenixTarget fail to create session"""
    session_cls = mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    session_cls.create.return_value = None
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with raises(RuntimeError, match="Could not create ADB Session!"):
        FenixTarget(fake_apk, 300, 25, 5000)


@mark.parametrize(
    "healthy, reason, result, closes",
    [
        # running as expected - no failures
        (True, None, Result.NONE, 0),
        # browser process closed
        (False, Reason.CLOSED, Result.NONE, 1),
        # browser process crashed
        (False, Reason.ALERT, Result.FOUND, 1),
        # browser exit with no crash logs
        (False, Reason.EXITED, Result.NONE, 1),
    ],
)
def test_fenix_target_launch_and_check_result(
    mocker, tmp_path, healthy, reason, result, closes
):
    """test FenixTarget launch() and check_result()"""
    fake_process = mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with FenixTarget(fake_apk, 300, 25, 5000) as target:
        target.launch("fake.url")
        assert fake_process.return_value.launch.call_count == 1
        assert target.monitor.is_running()
        assert target.monitor.is_healthy()
        fake_process.return_value.is_healthy.return_value = healthy
        fake_process.return_value.reason = reason
        assert target.check_result(None) == result
        assert fake_process.return_value.close.call_count == closes


def test_fenix_target_handle_hang(mocker, tmp_path):
    """test FenixTarget.handle_hang()"""
    fake_process = mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()
    with FenixTarget(fake_apk, 300, 25, 5000) as target:
        fake_process.return_value.is_healthy.return_value = True
        fake_process.return_value.is_running.return_value = True
        assert target.handle_hang()
        assert fake_process.return_value.close.call_count == 1


def test_fenix_target_create_report(mocker, tmp_path):
    """test FenixTarget ADBProcess.create_report()"""
    mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    proc_cls = mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    fake_apk = tmp_path / "test.apk"
    fake_apk.touch()

    def fake_save_logs(dst):
        (dst / "log_stderr.txt").write_text("foo")
        (dst / "log_stdout.txt").write_text("foo")

    proc_cls.return_value.save_logs = fake_save_logs
    with FenixTarget(fake_apk, 300, 25, 5000) as target:
        target.create_report()


def test_fenix_monitor(mocker):
    """test FenixMonitor simple"""
    proc = mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    proc.cpu_usage.return_value = ((123, 20), (124, 10), (125, 0))
    proc.launches = 3
    monitor = FenixMonitor(proc)
    assert monitor.is_healthy()
    assert proc.is_healthy.call_count == 1
    assert not monitor.is_idle(10)
    assert monitor.is_idle(25)
    assert proc.cpu_usage.call_count == 2
    assert monitor.is_running()
    assert proc.is_running.call_count == 1
    assert monitor.launches == 3
    # zero until implemented
    assert monitor.log_length("foo") == 0
