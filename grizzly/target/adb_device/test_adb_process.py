# pylint: disable=protected-access
import pytest

from .adb_process import ADBProcess, ADBLaunchError
from .adb_session import ADBSession, ADBSessionError

def test_adb_process_01(mocker):
    """test creating a simple device"""
    test_pkg = "org.test.preinstalled"
    fake_session = mocker.Mock(spec=ADBSession)
    proc = ADBProcess(test_pkg, fake_session)
    try:
        assert isinstance(proc._session, ADBSession)
        assert proc._package == test_pkg
        assert proc.logs is None
        assert proc.profile is None
        assert proc.reason == proc.RC_CLOSED
        assert proc._pid is None
        proc.close()
        assert not proc.logs  # should not have logs
    finally:
        proc.cleanup()

def test_adb_process_02(mocker):
    """test creating device with unknown package"""
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.is_installed.side_effect = ADBSessionError("blah")
    with pytest.raises(ADBSessionError):
        ADBProcess("org.test.unknown", fake_session)

def test_adb_process_03(mocker):
    """test failed launch() and is_running()"""
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (1, b"")
    fake_session.collect_logs.return_value = b""
    fake_session.listdir.return_value = ()
    fake_session.process_exists.return_value = False
    proc = ADBProcess("org.test.unknown", fake_session)
    try:
        assert not proc.is_running()
        with pytest.raises(ADBLaunchError):
            proc.launch("fake.url")
        assert not proc.is_running()
        proc.cleanup()
        assert proc.logs is None
    finally:
        proc.cleanup()

def test_adb_process_04(mocker):
    """test launch(), is_running() and is_healthy()"""
    fake_bs = mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_bs.return_value.location.return_value = "http://localhost"
    fake_bs.return_value.port.return_value = 1234
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (0, b"Status: ok")
    fake_session.collect_logs.return_value = b""
    fake_session.get_pid.return_value = 1337
    fake_session.listdir.return_value = ()
    #fake_session.process_exists.return_value = False
    proc = ADBProcess("org.mozilla.fennec_aurora", fake_session)
    try:
        assert not proc.is_running()
        assert proc.launch("fake.url")
        assert proc.is_running()
        assert proc.is_healthy()
        proc.close()
        assert proc._pid is None
        assert proc.logs
    finally:
        proc.cleanup()
    assert fake_bs.return_value.wait.call_count == 1
    assert fake_bs.return_value.close.call_count == 1

def test_adb_process_05(mocker):
    """test launch() with environment variables"""
    fake_bs = mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_bs.return_value.location.return_value = "http://localhost"
    fake_bs.return_value.port.return_value = 1234
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (0, b"Status: ok")
    fake_session.collect_logs.return_value = b""
    fake_session.get_pid.return_value = 1337
    fake_session.listdir.return_value = ()
    env = {"test1":"1", "test2": "2"}
    proc = ADBProcess("org.mozilla.fennec_aurora", fake_session)
    try:
        assert proc.launch("fake.url", env_mod=env)
        assert proc.is_running()
        proc.close()
    finally:
        proc.cleanup()

def test_adb_process_06(mocker):
    """test wait_on_files()"""
    fake_bs = mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_bs.return_value.location.return_value = "http://localhost"
    fake_bs.return_value.port.return_value = 1234
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (0, b"Status: ok")
    fake_session.collect_logs.return_value = b""
    fake_session.get_open_files.return_value = ((1, "some_file"),)
    fake_session.get_pid.return_value = 1337
    fake_session.listdir.return_value = ()
    fake_session.realpath.side_effect = str.strip
    proc = ADBProcess("org.mozilla.fennec_aurora", fake_session)
    try:
        proc.wait_on_files(["not_running"])
        assert proc.launch("fake.url")
        assert proc.wait_on_files([])
        fake_session.get_open_files.return_value = ((1, "some_file"), (1, "/existing/file.txt"))
        assert not proc.wait_on_files(["/existing/file.txt"], poll_rate=0.1, timeout=0.3)
        proc.close()
    finally:
        proc.cleanup()

# TODO:
# _process_logs
# save_logs
