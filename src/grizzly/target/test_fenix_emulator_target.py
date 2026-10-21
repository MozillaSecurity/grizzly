# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from subprocess import TimeoutExpired

from fxpoppet.adb_process import ADBLaunchError, Reason
from fxpoppet.adb_session import ADBSession, ADBSessionError
from fxpoppet.emulator.android import AndroidEmulatorError
from pytest import mark, raises

from .fenix_emulator_target import FenixEmulatorTarget, emulator_installed
from .target import Result, TargetLaunchError

MODULE = "grizzly.target.fenix_emulator_target"


def _mock_target(mocker):
    """Patch everything used to launch an emulator and create the target."""
    mocker.patch(f"{MODULE}.emulator_installed", autospec=True, return_value=True)
    emu_cls = mocker.patch(f"{MODULE}.AndroidEmulator", autospec=True)
    emu_cls.search_free_ports.return_value = 5554
    emu_cls.return_value.port = 5554
    emu_cls.return_value.poll.return_value = None
    # used to prepare the emulator
    prep_session = mocker.patch(f"{MODULE}.ADBSession", autospec=True)
    # used by FenixTarget
    session_cls = mocker.patch("grizzly.target.fenix_target.ADBSession", autospec=True)
    session_cls.get_package_name.return_value = "the_name"
    session_cls.connect.return_value = mocker.Mock(spec_set=ADBSession, symbols={})
    proc_cls = mocker.patch("grizzly.target.fenix_target.ADBProcess", autospec=True)
    return emu_cls, prep_session, session_cls, proc_cls


@mark.parametrize(
    "display_mode, headless, xvfb",
    [
        (None, False, False),
        ("default", False, False),
        ("headless", True, False),
        ("xvfb", False, True),
    ],
)
def test_fenix_emulator_target_simple(mocker, tmp_path, display_mode, headless, xvfb):
    """test creating a simple FenixEmulatorTarget"""
    emu_cls, prep_session, session_cls, _ = _mock_target(mocker)
    warning = mocker.patch("grizzly.target.fenix_target.LOG.warning", autospec=True)
    apk = tmp_path / "test.apk"
    with FenixEmulatorTarget(apk, 300, 25, 5000, display_mode=display_mode) as target:
        assert emu_cls.call_count == 1
        assert emu_cls.call_args.kwargs["headless"] == headless
        assert emu_cls.call_args.kwargs["xvfb"] == xvfb
        assert emu_cls.create_avd.call_count == 1
        assert prep_session.connect.call_args.args[0] == "emulator-5554"
        prep_session.connect.return_value.install.assert_called_once_with(apk)
        assert session_cls.connect.call_args.args[0] == "emulator-5554"
        target.reverse(5345, 4323)
        assert target._reverse == {5345: 4323}
    # display_mode is consumed and not reported as unsupported
    assert warning.call_count == 0
    assert target._emulator is None
    assert emu_cls.return_value.terminate.call_count == 1
    assert emu_cls.return_value.cleanup.call_count == 1


def test_fenix_emulator_target_not_installed(mocker, tmp_path):
    """test FenixEmulatorTarget when the emulator is not installed"""
    emu_cls = mocker.patch(f"{MODULE}.AndroidEmulator", autospec=True)
    mocker.patch(f"{MODULE}.emulator_installed", autospec=True, return_value=False)
    with raises(RuntimeError, match="Android emulator is not installed"):
        FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000)
    assert emu_cls.call_count == 0


def test_fenix_emulator_target_launch_emulator_failures(mocker, tmp_path):
    """test FenixEmulatorTarget emulator launch failures"""
    emu_cls, prep_session, _, _ = _mock_target(mocker)
    # failed to boot
    emu_cls.side_effect = AndroidEmulatorError("test")
    with raises(RuntimeError, match="Failed to launch emulator"):
        FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000)
    assert emu_cls.call_count == FenixEmulatorTarget.LAUNCH_ATTEMPTS
    assert emu_cls.remove_avd.call_count == FenixEmulatorTarget.LAUNCH_ATTEMPTS
    # failed to prepare (connect and install)
    emu_cls.reset_mock()
    emu_cls.side_effect = None
    prep_session.connect.side_effect = (
        ADBSessionError("test"),
        prep_session.connect.return_value,
        prep_session.connect.return_value,
    )
    prep_session.connect.return_value.install.side_effect = ADBSessionError("test")
    with raises(RuntimeError, match="Failed to launch emulator"):
        FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000, display_mode="xvfb")
    assert emu_cls.call_count == FenixEmulatorTarget.LAUNCH_ATTEMPTS
    assert prep_session.connect.call_count == FenixEmulatorTarget.LAUNCH_ATTEMPTS
    assert (
        emu_cls.return_value.cleanup.call_count == FenixEmulatorTarget.LAUNCH_ATTEMPTS
    )
    # recover after failure
    emu_cls.reset_mock()
    prep_session.connect.side_effect = None
    prep_session.connect.return_value.install.side_effect = None
    emu_cls.side_effect = (AndroidEmulatorError("test"), emu_cls.return_value)
    with FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000) as target:
        assert target._emulator is not None
    assert emu_cls.call_count == 2


def test_fenix_emulator_target_init_failure(mocker, tmp_path):
    """test FenixEmulatorTarget emulator is shutdown when init fails"""
    emu_cls, _, session_cls, _ = _mock_target(mocker)
    session_cls.connect.side_effect = ADBSessionError("test")
    with raises(RuntimeError, match="Could not create ADBSession"):
        FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000)
    assert emu_cls.return_value.terminate.call_count == 1
    assert emu_cls.return_value.cleanup.call_count == 1


@mark.parametrize("running, responding", [(False, True), (True, False)])
def test_fenix_emulator_target_relaunch(mocker, tmp_path, running, responding):
    """test FenixEmulatorTarget relaunch emulator"""
    emu_cls, prep_session, session_cls, proc_cls = _mock_target(mocker)
    old_proc = mocker.Mock()
    new_proc = mocker.Mock()
    proc_cls.side_effect = (old_proc, new_proc)
    sess_obj = session_cls.connect.return_value
    with FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000) as target:
        target.reverse(5345, 4323)
        assert target.monitor.proc is old_proc
        emu_cls.return_value.poll.return_value = None if running else 1
        sess_obj.device.wait_for_boot.side_effect = (responding, True)
        target.launch("fake.html")
        assert emu_cls.call_count == 2
        assert prep_session.connect.return_value.install.call_count == 2
        assert old_proc.cleanup.call_count == 1
        assert target.monitor.proc is new_proc
        assert new_proc.launch.call_count == 1
        assert sess_obj.reverse.call_count == 2
        sess_obj.reverse.assert_called_with(5345, 4323)


def test_fenix_emulator_target_launch(mocker, tmp_path):
    """test FenixEmulatorTarget launch"""
    emu_cls, _, session_cls, proc_cls = _mock_target(mocker)
    session_cls.connect.return_value.device.wait_for_boot.return_value = True
    with FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000) as target:
        target.launch("fake.html")
        assert proc_cls.return_value.launch.call_count == 1
        assert emu_cls.call_count == 1


def test_fenix_emulator_target_launch_failure(mocker, tmp_path):
    """test FenixEmulatorTarget browser launch failure"""
    mocker.patch.object(FenixEmulatorTarget, "create_report", autospec=True)
    emu_cls, _, session_cls, proc_cls = _mock_target(mocker)
    session_cls.connect.return_value.device.wait_for_boot.return_value = True
    proc_cls.return_value.launch.side_effect = ADBLaunchError("test")
    with FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000) as target:
        with raises(TargetLaunchError):
            target.launch("fake.html")
        # emulator is shutdown so a new emulator is used for the next attempt
        assert target._emulator is None
        assert emu_cls.return_value.terminate.call_count == 1
        proc_cls.return_value.launch.side_effect = None
        target.launch("fake.html")
        assert emu_cls.call_count == 2
        assert target._emulator is not None


@mark.parametrize(
    "emu_running, healthy, reason, result",
    [
        (True, True, None, Result.NONE),
        (True, False, Reason.ALERT, Result.FOUND),
        (False, False, Reason.ALERT, Result.NONE),
    ],
)
def test_fenix_emulator_target_check_result(
    mocker, tmp_path, emu_running, healthy, reason, result
):
    """test FenixEmulatorTarget.check_result()"""
    emu_cls, _, _, proc_cls = _mock_target(mocker)
    proc_cls.return_value.is_healthy.return_value = healthy
    proc_cls.return_value.reason = reason
    with FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000) as target:
        emu_cls.return_value.poll.return_value = None if emu_running else 1
        assert target.check_result([]) == result


def test_fenix_emulator_target_shutdown_timeout(mocker, tmp_path):
    """test FenixEmulatorTarget emulator shutdown timeout"""
    emu_cls, _, _, _ = _mock_target(mocker)
    emu_cls.return_value.wait.side_effect = TimeoutExpired("emu", 30)
    emu_cls.return_value.emu = mocker.Mock()
    with FenixEmulatorTarget(tmp_path / "test.apk", 300, 25, 5000):
        pass
    assert emu_cls.return_value.terminate.call_count == 1
    assert emu_cls.return_value.emu.kill.call_count == 1
    assert emu_cls.return_value.wait.call_count == 2
    assert emu_cls.return_value.cleanup.call_count == 1


def test_fenix_emulator_target_installed(mocker, tmp_path):
    """test emulator_installed()"""
    paths = mocker.patch(f"{MODULE}.PATHS", autospec=True)
    paths.sdk_root = tmp_path
    assert not emulator_installed()
    (tmp_path / "emulator").mkdir()
    (tmp_path / "emulator" / "emulator").touch()
    (tmp_path / "emulator" / "mksdcard").touch()
    (tmp_path / "platform-tools").mkdir()
    (tmp_path / "platform-tools" / "adb").touch()
    assert not emulator_installed()
    mocker.patch(f"{MODULE}.SYS_IMG", "android-test")
    (tmp_path / "system-images" / "android-test" / "default" / "x86_64").mkdir(
        parents=True
    )
    assert emulator_installed()
