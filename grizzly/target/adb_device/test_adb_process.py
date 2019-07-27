# pylint: disable=protected-access
import os
import shutil

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
    """test failed ADBProcess.launch() and ADBProcess.is_running()"""
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (1, "")
    fake_session.collect_logs.return_value = ""
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
    """test ADBProcess.launch(), ADBProcess.is_running() and ADBProcess.is_healthy()"""
    fake_bs = mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_bs.return_value.location.return_value = "http://localhost"
    fake_bs.return_value.port.return_value = 1234
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (0, "Status: ok")
    fake_session.collect_logs.return_value = ""
    fake_session.get_pid.return_value = 1337
    fake_session.listdir.return_value = ()
    #fake_session.process_exists.return_value = False
    proc = ADBProcess("org.mozilla.fennec_aurora", fake_session)
    try:
        assert not proc.is_running()
        assert proc.launches == 0
        assert proc.launch("fake.url")
        assert proc.is_running()
        assert proc.is_healthy()
        assert proc.launches == 1
        proc.close()
        assert proc._pid is None
        assert proc.logs
    finally:
        proc.cleanup()
    assert fake_bs.return_value.wait.call_count == 1
    assert fake_bs.return_value.close.call_count == 1

def test_adb_process_05(mocker):
    """test ADBProcess.launch() with environment variables"""
    fake_bs = mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_bs.return_value.location.return_value = "http://localhost"
    fake_bs.return_value.port.return_value = 1234
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (0, "Status: ok")
    fake_session.collect_logs.return_value = ""
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
    """test ADBProcess.wait_on_files()"""
    mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.call.return_value = (0, "Status: ok")
    fake_session.collect_logs.return_value = ""
    fake_session.get_open_files.return_value = ((1, "some_file"),)
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

def test_adb_process_07(mocker):
    """test ADBProcess.find_crashreports()"""
    mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_session = mocker.Mock(spec=ADBSession)
    proc = ADBProcess("org.mozilla.fennec_aurora", fake_session)
    try:
        proc.profile = "profile_path"
        # no dump files
        fake_session.listdir.return_value = ("somefile.txt")
        assert not proc.find_crashreports()
        # contains dump file
        fake_session.listdir.return_value = ("somefile.txt", "test.dmp")
        assert proc.find_crashreports()
        # contains missing path
        fake_session.listdir.side_effect = IOError("test")
        assert not proc.find_crashreports()
    finally:
        proc.cleanup()

def test_adb_process_08(mocker, tmp_path):
    """test ADBProcess.save_logs()"""
    mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    fake_session = mocker.Mock(spec=ADBSession)
    log_path = tmp_path / "src"
    log_path.mkdir()
    (log_path / "nested").mkdir()
    fake_log = log_path / "fake.txt"
    fake_log.touch()
    dmp_path = tmp_path / "dst"
    proc = ADBProcess("org.mozilla.fennec_aurora", fake_session)
    proc.logs = str(log_path)
    try:
        proc.save_logs(str(dmp_path))
    finally:
        proc.cleanup()
    assert "fake.txt" in os.listdir(str(dmp_path))

def test_adb_process_09(mocker):
    """test ADBProcess._process_logs()"""
    mocker.patch("grizzly.target.adb_device.adb_process.Bootstrapper", autospec=True)
    mocker.patch("grizzly.target.adb_device.adb_process.PuppetLogger", autospec=True)
    fake_proc_md = mocker.patch("grizzly.target.adb_device.adb_process.process_minidumps", autospec=True)
    fake_session = mocker.Mock(spec=ADBSession)
    fake_session.collect_logs.return_value = "fake logcat data"
    proc = ADBProcess("org.mozilla.fennec_aurora", fake_session)
    try:
        # no extra logs
        proc._process_logs([])
        assert os.path.isdir(proc.logs)
        try:
            assert "log_logcat.txt" in os.listdir(proc.logs)
        finally:
            shutil.rmtree(proc.logs)
        proc.logs = None
        assert fake_proc_md.call_count == 0
        assert fake_session.pull.call_count == 0
        # other logs available
        proc._process_logs(["log.dmp", "asan_log.txt"])
        assert os.path.isdir(proc.logs)
        try:
            assert "log_logcat.txt" in os.listdir(proc.logs)
        finally:
            shutil.rmtree(proc.logs)
        assert fake_proc_md.call_count == 1
        assert fake_session.pull.call_count == 2
    finally:
        proc.cleanup()


# TODO:
# _process_logs
