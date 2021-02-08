# pylint: disable=protected-access
import os
from pathlib import Path
from subprocess import CalledProcessError
import zipfile

import pytest

from .adb_session import ADBCommandError, ADBCommunicationError, ADBSession, ADBSessionError

def test_adb_session_01(mocker):
    """test ADBSession._call_adb()"""
    def fake_call(cmd, stderr=None, stdout=None):
        assert cmd[0] == "test"
        stderr.write(b"")
        stdout.write(b"blah_out")
        return 0
    mocker.patch("grizzly.target.adb_device.adb_session.call", side_effect=fake_call)
    ret, output = ADBSession._call_adb(["test"])
    assert ret == 0
    assert "blah_out" in output
    # test with invalid timeout
    with pytest.raises(AssertionError):
        ADBSession._call_adb(["test"], timeout=-1)
    # test with timeout
    class FakeProc(object):
        def __init__(self, cmd, stderr=None, stdout=None):
            assert cmd[0] == "test"
            self.stdout = stdout
            stderr.write(b"")
            stdout.write(b"init\n")
        def wait(self):
            self.stdout.write(b"wait\n")
            return 1
        def terminate(self):
            self.stdout.write(b"terminate\n")
        def poll(self):
            self.stdout.write(b"poll\n")
    mocker.patch("grizzly.target.adb_device.adb_session.Popen", new=FakeProc)
    mocker.patch("grizzly.target.adb_device.adb_session.sleep")
    mocker.patch("grizzly.target.adb_device.adb_session.time", side_effect=(1, 1, 2))
    ret, output = ADBSession._call_adb(["test"], timeout=0.5)
    assert ret == 1
    assert "init" in output
    assert "poll" in output
    assert "terminate" in output
    assert "wait" in output

def test_adb_session_02(mocker):
    """test ADBSession.call()"""
    # not connected
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="fake_adb")
    session = ADBSession()
    with pytest.raises(ADBCommunicationError, match="ADB session is not connected!"):
        session.call(["test"])
    # successful call
    session.connected = True
    session._debug_adb = True
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", return_value=(0, "pass"))
    ret_code, output = session.call(["test"])
    assert ret_code == 0
    assert output == "pass"
    # invalid command
    session._debug_adb = False
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", return_value=(1, "Android Debug Bridge version"))
    with pytest.raises(ADBCommandError, match="Invalid ADB command 'test'"):
        session.call(["test"])
    # invalid command
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", return_value=(1, "adb: usage:"))
    with pytest.raises(ADBCommandError, match="adb: usage:"):
        session.call(["test"])
    # disconnected device
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", return_value=(1, "error: closed"))
    with pytest.raises(ADBCommunicationError, match="No device detected!"):
        session.call(["test"])
    assert not session.connected

def test_adb_session_03(mocker):
    """test creating a session with invalid args"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check")
    with pytest.raises(ValueError):
        ADBSession("invalid.ip")
    with pytest.raises(ValueError):
        ADBSession("127.0.0.1", port=7)
    with pytest.raises(ValueError):
        ADBSession("127.0.0.1", port="bad")

def test_adb_session_04(mocker):
    """test simple ADBSession"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check")
    test_ip = "127.0.0.1"
    test_port = 5556
    session = ADBSession(test_ip, test_port)
    assert not session.connected
    assert not session._root
    assert session._cpu_arch is None
    assert session._ip_addr == test_ip
    assert session._port == test_port
    assert session._os_version is None

def test_adb_session_05(mocker):
    """test ADBSession.devices()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_01(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "devices":
            return 1, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_01)
    assert not ADBSession().devices()
    def fake_adb_02(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "devices":
            return 0, "List of devices attached\n" \
                      "emulator-5554   device\n" \
                      "emulator-5556   offline"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_02)
    devices = ADBSession().devices(all_devices=True, any_state=False)
    assert len(devices) == 1
    assert "emulator-5554" in devices
    def fake_adb_03(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "devices":
            return 0, "List of devices attached\n" \
                      "* daemon not running; starting now at tcp:5037\n" \
                      "* daemon started successfully\n" \
                      "emulator-5554   device\n" \
                      "emulator-5556   offline\n" \
                      "emulator-5558   device\n"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_03)
    session = ADBSession()
    os.environ["ANDROID_SERIAL"] = "emulator-5558"
    try:
        devices = session.devices(all_devices=False, any_state=False)
    finally:
        os.environ.pop("ANDROID_SERIAL")
    assert len(devices) == 1
    assert "emulator-5558" in devices
    with pytest.raises(ADBSessionError):
        session.devices(all_devices=False, any_state=False)

def test_adb_session_06(mocker):
    """test simple ADBSession.create()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    test_arch = "x86_64"
    test_ip = "localhost"
    test_port = 5555
    test_version = "9"
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            assert cmd[2] == ":".join([test_ip, str(test_port)])
            return 0, ""
        # already Permissive
        if cmd[1] == "shell" and cmd[2] == "getenforce":
            return 0, "Permissive"
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                return 0, "stopped"
            if cmd[3] == "ro.build.version.release":
                return 0, test_version
            if cmd[3] == "ro.product.cpu.abi":
                return 0, test_arch
            if cmd[3] == "sys.boot_completed":
                return 0, "1"
        # already root
        if cmd[1] == "shell" and cmd[2] == "whoami":
            return 0, "root"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    ADBSession._call_adb = fake_adb_call
    session = ADBSession.create(test_ip, test_port)
    assert session is not None
    assert session.connected
    assert session._root
    assert session._cpu_arch == test_arch
    assert session._ip_addr == test_ip
    assert session._os_version == test_version
    assert session._port == test_port

def test_adb_session_07(mocker):
    """test full ADBSession.create()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    test_arch = "x86_64"
    test_ip = "localhost"
    test_port = 5555
    test_version = "9"
    test_enforcing = True
    def fake_adb_call(obj, cmd, timeout=None):
        nonlocal test_enforcing
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            if obj.connected:
                return 0, "already connected"
            assert cmd[2] == ":".join([test_ip, str(test_port)])
            obj.connected = True
            return 0, ""
        if cmd[1] == "disconnect":
            if not obj.connected:
                return 0, "already disconnected"
            assert cmd[2] == ":".join([test_ip, str(test_port)])
            obj.connected = False
            return 0, ""
        if cmd[1] == "reconnect":
            return 0, ""
        if cmd[1] == "root":
            obj._root = True
            obj.connected = False
            return 0, "restarting adbd as root"
        if cmd[1] == "shell" and cmd[2] == "getenforce":
            if test_enforcing:
                return 0, "Enforcing"
            return 0, "Permissive"
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                return 0, "stopped"
            if cmd[3] == "ro.build.version.release":
                return 0, test_version
            if cmd[3] == "ro.product.cpu.abi":
                return 0, test_arch
            if cmd[3] == "sys.boot_completed":
                return 0, "1"
        if cmd[1] == "shell" and cmd[2] == "setenforce":
            test_enforcing = False
            return 0, ""
        if cmd[1] == "shell" and cmd[2] in ("start", "stop"):
            return 0, ""
        if cmd[1] == "shell" and cmd[2] == "whoami":
            if obj._root:
                return 0, "root"
            return 0, "shell"
        if cmd[1] == "unroot":
            obj._root = False
            obj.connected = False
            return 0, "restarting adbd as non root"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession.create(test_ip, test_port)
    assert session is not None
    assert session.connected
    assert session._root
    assert session._cpu_arch == test_arch
    assert session._ip_addr == test_ip
    assert session._os_version == test_version
    assert session._port == test_port
    session.disconnect()
    assert not session.connected
    assert not session._root

def test_adb_session_08(mocker):
    """test ADBSession.create() without IP"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    test_arch = "x86"
    test_version = "7.1.2"
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            obj.connected = True
            return 0, ""
        if cmd[1] == "disconnect":
            obj.connected = False
            return 0, ""
        if cmd[1] == "devices":
            return 0, "\n".join(("List of devices attached",
                                 "* daemon not running; starting now at tcp:5037",
                                 "* daemon started successfully",
                                 "emulator-5554   device"))
        if cmd[1] == "shell" and cmd[2] == "getenforce":
            return 0, "Permissive"
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                return 0, "stopped"
            if cmd[3] == "ro.build.version.release":
                return 0, test_version
            if cmd[3] == "ro.product.cpu.abi":
                return 0, test_arch
            if cmd[3] == "sys.boot_completed":
                return 0, "1"
        if cmd[1] == "shell" and cmd[2] == "whoami":
            return 0, "shell"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession.create(as_root=False)
    assert session is not None
    assert session._ip_addr is None
    assert session._port is None
    assert session.connected
    assert not session._root
    assert session._cpu_arch == test_arch
    assert session._os_version == test_version
    session.disconnect()
    assert not session.connected

def test_adb_session_09(mocker):
    """test ADBSession.connect() no devices available"""
    mocker.patch("grizzly.target.adb_device.adb_session.sleep")  # skip delay after warning message
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            return 1, "unable to connect"
        if cmd[1] == "devices":
            return 0, "\n".join(("List of devices attached",
                                 "* daemon not running; starting now at tcp:5037",
                                 "* daemon started successfully"))
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    assert not ADBSession().connect()
    assert not ADBSession("127.0.0.1").connect()

def test_adb_session_10(mocker):
    """test ADBSession.connect() device in a bad state"""
    mocker.patch("grizzly.target.adb_device.adb_session.sleep")  # skip delays
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            return 0, ""
        if cmd[1] == "devices":
            return 0, "\n"
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                return 0, "stopped"
            if cmd[3] == "sys.boot_completed":
                return 0, "1"
        if cmd[1] == "shell" and cmd[2] == "whoami":
            return 1, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    with pytest.raises(ADBSessionError, match="Device in a bad state, try disconnect & reboot"):
        ADBSession("127.0.0.1").connect()

def test_adb_session_11(mocker):
    """test ADBSession.connect() and ADBSession.disconnect()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            if obj.connected:
                return 0, "already connected"
            obj.connected = True
            return 0, ""
        if cmd[1] == "devices":
            return 0, "\n".join(("List of devices attached",
                                 "* daemon not running; starting now at tcp:5037",
                                 "* daemon started successfully",
                                 "emulator-5554   device"))
        if cmd[1] == "disconnect":
            if not obj.connected:
                return 0, "already disconnected"
            obj.connected = False
            return 0, ""
        if cmd[1] == "root":
            obj._root = True
            obj.connected = False
            return 0, "restarting adbd as root"
        if cmd[1] == "shell" and cmd[2] == "getenforce":
            return 0, "Permissive"
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                return 0, "stopped"
            if cmd[3] == "ro.build.version.release":
                return 0, "9"
            if cmd[3] == "ro.product.cpu.abi":
                return 0, "x86_64"
            if cmd[3] == "sys.boot_completed":
                return 0, "1"
        if cmd[1] == "shell" and cmd[2] == "whoami":
            if obj._root:
                return 0, "root"
            return 0, "shell"
        if cmd[1] == "unroot":
            obj._root = False
            obj.connected = False
            return 0, "restarting adbd as non root"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    assert not session.connected
    assert not session._root
    session.disconnect()
    # connect and enable root
    assert session.connect(max_attempts=1)
    assert session.connected
    assert session._root
    session.disconnect()
    assert not session.connected
    assert not session._root
    # connect and do not enable root
    assert session.connect(as_root=False)
    assert session.connected
    assert not session._root
    session.disconnect()
    assert not session.connected
    assert not session._root
    # connect() x2 (already connected)
    assert session.connect()
    assert session.connected
    assert session.connect()
    assert session.connected
    assert session._root
    session.disconnect()
    assert not session.connected
    assert not session._root

def test_adb_session_12(mocker):
    """test ADBSession.connect() with unavailable device"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            return 1, "unable to connect"
        if cmd[1] == "disconnect":
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    assert not session.connected
    assert not session._root
    session.disconnect()
    # connect and enable root
    assert not session.connect(max_attempts=1, retry_delay=0.01)
    assert not session.connected
    assert not session._root

def test_adb_session_13(mocker):
    """test ADBSession.all() with unknown command"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    mocker.patch(
        "grizzly.target.adb_device.ADBSession._call_adb",
        return_value=(1, "Android Debug Bridge version 1.0.XX"))
    session = ADBSession("127.0.0.1")
    session.connected = True
    session._root = True
    with pytest.raises(ADBCommandError):
        session.call(["unknown-cmd"])

def test_adb_session_14(tmp_path, mocker):
    """test ADBSession.install()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_get_package_name(_):
        with zipfile.ZipFile(apk_file, mode="r") as zfp:
            with zfp.open("package-name.txt", "r") as pfp:
                return pfp.read().strip().decode("utf-8", errors="ignore")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "install":
            assert cmd[2] == "-g"
            assert cmd[3] == "-r"
            if "test.apk" in cmd[4]:
                return 0, "Success"
            return 1, ""
        if cmd[1] == "shell":
            assert cmd[2] == "pm"
            assert cmd[3] == "grant"
            assert cmd[4] == "test-package.blah.foo"
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    mocker.patch("grizzly.target.adb_device.ADBSession.get_package_name", side_effect=fake_get_package_name)
    session = ADBSession("127.0.0.1")
    session.connected = True
    # missing apk
    with pytest.raises(IOError):
        session.install("fake_path")
    # bad apk
    pkg_file = tmp_path / "package-name.txt"
    apk_file = str(tmp_path / "bad.apk")
    pkg_file.write_bytes(b"\n")
    with zipfile.ZipFile(apk_file, mode="w") as z_out:
        z_out.write(str(pkg_file), "package-name.txt")
    with pytest.raises(ADBSessionError):
        session.install(str(apk_file))
    # good apk
    pkg_file = tmp_path / "package-name.txt"
    apk_file = str(tmp_path / "test.apk")
    syms_path = str(tmp_path / "symbols")
    os.makedirs(syms_path)
    pkg_file.write_bytes(b"test-package.blah.foo\n")
    with zipfile.ZipFile(apk_file, mode="w") as z_out:
        z_out.write(str(pkg_file), "package-name.txt")
    assert not session.symbols_path(apk_file)
    assert session.install(apk_file)
    session.symbols[apk_file] = syms_path
    assert session.symbols_path(apk_file) == syms_path
    # TODO: failed to get package name

def test_adb_session_15(mocker):
    """test ADBSession.uninstall()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "uninstall" and cmd[2] == "org.test.preinstalled":
            return 0, "Success"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    assert not session.uninstall("org.test.unknown")
    session.connected = True
    assert session.uninstall("org.test.preinstalled")

def test_adb_session_16(mocker):
    """test ADBSession.get_pid()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "ps":
            output = (
                "USER      PID   PPID  VSIZE  RSS   WCHAN            PC  NAME",
                "test      1337  1772  1024   1024 SyS_epoll_ 00000000 S org.test.preinstalled",
                "root      5847  1     315992 2348  poll_sched 00000000 S /sbin/adbd",
                "u0_a80    9990  1772  1221212 128064 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora",
                "root      5944  5847  6280   2360           0 00000000 R ps",
                "")
            return 0, "\n".join(output)
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    with pytest.raises(ADBCommunicationError, match="ADB session is not connected!"):
        session.get_pid("org.test.unknown")
    session.connected = True
    assert session.get_pid("org.test.unknown") is None
    assert session.get_pid("org.test.preinstalled") == 1337

def test_adb_session_17(mocker):
    """test ADBSession.is_installed()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "pm":
            assert cmd[3] == "list"
            assert cmd[4] == "packages"
            output = (
                "package:org.mozilla.fennec_aurora",
                "package:org.test.preinstalled",
                "package:com.android.phone",
                "package:com.android.shell")
            return 0, "\n".join(output)
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert not session.is_installed("org.test.unknown")
    assert session.is_installed("org.test.preinstalled")

def test_adb_session_18(mocker):
    """test ADBSession.packages()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "pm":
            assert cmd[3] == "list"
            assert cmd[4] == "packages"
            output = (
                "package:org.mozilla.fennec_aurora",
                "package:org.test.preinstalled",
                "package:com.android.phone",
                "package:com.android.shell")
            return 0, "\n".join(output)
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    pkgs = tuple(session.packages)
    assert len(pkgs) == 4
    assert "com.android.phone" in pkgs
    assert "com.android.shell" in pkgs
    assert "org.mozilla.fennec_aurora" in pkgs
    assert "org.test.preinstalled" in pkgs

def test_adb_session_19(mocker):
    """test ADBSession.collect_logs()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "logcat":
            assert cmd[2] == "-d"
            assert cmd[3] == "*:I"
            if len(cmd) == 5:
                assert cmd[-1].startswith("--pid=")
                pid = int(cmd[-1].split("=")[-1])
            else:
                pid = -1
            output = []
            if pid in (-1, 9990):
                output += [
                    "07-27 12:10:15.414  9990  9990 W fake log",
                    "07-27 12:10:15.430  9990  9990 I fake log",
                    "07-27 12:10:15.442  9990  4714 I fake log",
                    "07-27 12:10:15.505  9990  4713 E fake log",
                    "07-27 12:10:15.520  9990  4719 I fake log",
                    "07-27 12:10:15.529  9990  4707 W fake log",
                    "07-27 12:10:15.533  9990  4714 E fake log"]
            if pid == -1:
                output += [
                    "07-27 12:39:27.188  3049  3049 W fake log",
                    "07-27 12:39:27.239  1887  1994 I fake log",
                    "07-27 12:39:27.286  2767  7142 I fake log",
                    "07-27 12:39:27.441  7128  7128 I fake log"]
            return 0, "\n".join(output)
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    # test not connected
    assert session.collect_logs() == ""
    # test connected
    session.connected = True
    assert len(session.collect_logs().splitlines()) == 11
    assert len(session.collect_logs(9990).splitlines()) == 7
    assert not session.collect_logs(1111).splitlines()

def test_adb_session_20(mocker):
    """test ADBSession.open_files()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "lsof":
            if len(cmd) == 5:
                assert cmd[3].startswith("-p")
            output = (
                "COMMAND     PID    USER   FD      TYPE   DEVICE  SIZE/OFF       NODE NAME",
                "init          1    root  cwd   unknown                               /proc/1/cwd (readlink: Permission denied)",
                "lsof      15988   shell  cwd       DIR     0,13       780       4234 /",
                "lsof      15988   shell  txt       REG      8,1    432284    1696174 /system/bin/toybox",
                "lsof      15988   shell    4r      DIR      0,4         0     120901 /proc/15988/fd",
                "a.fennec_  9991  u0_a80   98r      REG      8,1    306672    1696611 /system/fonts/blah.ttf",
                "a.fennec_  9990  u0_a80  cwd       DIR     0,13       780       4234 /",
                "a.fennec_  9990  u0_a80  txt       REG      8,1     17948    1695879 /system/bin/app_process32",
                "a.fennec_  9990  u0_a80  mem   unknown                               /dev/ashmem/dalvik-main space (deleted)",
                "a.fennec_  9990  u0_a80  mem       CHR    10,58                 4485 /dev/binder",
                "a.fennec_  9990  u0_a80  mem   unknown                               /dev/ashmem/dalvik-allocspace zygote / x 0 (deleted)",
                "a.fennec_  9990  u0_a80  mem       REG      8,1    152888    1704079 /system/lib/libexpat.so",
                "a.fennec_  9990  u0_a80   54u      REG      8,1    329632    1769879 /data/data/org.mozilla.fennec_aurora/files/mozilla/a.default/browser.db-wal",
                "a.fennec_  9990  u0_a80   55u     IPv6                0t0      44549 TCP []:49232->[]:443 (ESTABLISHED)",
                "a.fennec_  9990  u0_a80   75w     FIFO      0,9       0t0      44634 pipe:[44634]",
                "a.fennec_  9990  u0_a80   76u     sock                0t0      44659 socket:[44659]",
                "a.fennec_  9990  u0_a80   95u      REG      8,1     98304    1769930 /data/data/org.mozilla.fennec_aurora/files/mozilla/a.default/permissions.sqlite",
                "a.fennec_  9990  u0_a80   98r      REG      8,1    306672    1696611 /system/fonts/Roboto-Regular.ttf",
                "a.fennec_  9990  u0_a80  122u      CHR    10,59       0t0       4498 /dev/ashmem",
                "a.fennec_  9990  u0_a80  123u     IPv4                0t0      44706 UDP :1900->:0",
                "a.fennec_  9990  u0_a80  125u     0000     0,10       0t0       3655 anon_inode:[eventpoll]",
                "a.fennec_  9990  u0_a80  126u     IPv4                0t0      44773 TCP :58190->:443 (ESTABLISHED)",
                "a.fennec_  9990  u0_a80  128u     unix                0t0      44747 socket",
                "a.fennec_  9990  u0_a80  130u     IPv4                0t0      44840 TCP :35274->:443 (SYN_SENT)",
                "")
            return 0, "\n".join(output)
        if cmd[1] == "shell" and cmd[2] == "ps":
            assert cmd[3] == "--ppid"
            assert cmd[4] == "9990"
            output = (
                "USER      PID   PPID  VSIZE  RSS   WCHAN            PC  NAME",
                "u0_a80    9991  9990  3332   3331 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora",
                "")
            return 0, "\n".join(output)
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    # list all open files
    assert len(tuple(session.open_files())) == 7
    # list process specific open files
    assert len(tuple(session.open_files(pid=9990))) == 5
    # list process and children specific open files
    assert len(tuple(session.open_files(pid=9990, children=True))) == 6
    with pytest.raises(AssertionError):
        tuple(session.open_files(pid=None, children=True))

def test_adb_session_21(mocker):
    """test ADBSession._get_procs()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "ps":
            if len(cmd) == 5:
                assert cmd[3] == "--ppid"
                ppid = int(cmd[-1])
            else:
                ppid = None
            output = [
                "USER      PID   PPID  VSIZE  RSS   WCHAN            PC  NAME"]
            if ppid is None:
                output += [
                    "root      1     0     8896   2208  SyS_epoll_ 00000000 S /init",
                    "root      1242  2     0      0         kswapd 00000000 S kswapd0",
                    "test      1337  1772  1024   1024 SyS_epoll_ 00000000 S org.test.preinstalled",
                    "test      1338  1337  1024   1024 SyS_epoll_ 00000000 S org.test.child",
                    "root      1772  1     1620804 122196 poll_sched 00000000 S zygote",
                    "media_rw  2158  1758  0      0              0 00000000 Z sdcard",
                    "audioserver 1773  1     34000  9624  binder_thr 00000000 S /system/bin/audioserver",
                    "root      5847  1     315992 2348  poll_sched 00000000 S /sbin/adbd",
                    "u0_a80    9990  1772  1221212 128064 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora",
                    "root      5944  5847  6280   2360           0 00000000 R ps"]
            elif ppid == 9990:
                output += [
                    "u0_a80    9991  9990  3332   3331 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora"]
            output += [""]
            return 0, "\n".join(output)
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert len(tuple(session._get_procs())) == 10
    dev_procs = tuple(session._get_procs(pid_children=9990))
    assert len(dev_procs) == 1
    assert dev_procs[0].pid == 9991

def test_adb_session_22(tmp_path, mocker):
    """test ADBSession.push()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "push":
            assert "test.txt" in cmd[2]
            assert cmd[3] == "dst"
            return 0, " pushed. "
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    with pytest.raises(IOError):
        session.push("not_a_file", "dst")
    push_file = tmp_path / "test.txt"
    push_file.write_bytes(b"test\n")
    assert session.push(str(push_file), "dst")

def test_adb_session_23(mocker):
    """test ADBSession.pull()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "pull":
            assert cmd[2] == "src"
            assert cmd[3] == "dst"
            return 0, " pulled. "
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.pull("src", "dst")

def test_adb_session_24(mocker):
    """test ADBSession.clear_log()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "logcat":
            assert cmd[2] == "--clear"
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.clear_logs()

def test_adb_session_25(mocker):
    """test ADBSession.listdir()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "ls":
            assert cmd[3] == "-A"
            if cmd[4] == "missing-dir":
                return 1, ""
            return 0, "test"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    with pytest.raises(IOError):
        session.listdir("missing-dir")
    dir_list = session.listdir("fake-dir")
    assert len(dir_list) == 1
    assert "test" in session.listdir("fake-dir")

def test_adb_session_26(mocker):
    """test ADBSession.process_exists()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "ps":
            assert cmd[3] == "9990"
            output = (
                "USER      PID   PPID  VSIZE  RSS   WCHAN            PC  NAME",
                "u0_a80    9990  1772  1221212 128064 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora",
                "")
            return 0, "\n".join(output)
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.process_exists(9990)

def test_adb_session_27(mocker, tmp_path):
    """test ADBSession._aapt_check()"""
    # use system aapt
    mocker.patch("grizzly.target.adb_device.adb_session.ANDROID_SDK_ROOT", Path("/missing"))
    mocker.patch("grizzly.target.adb_device.adb_session.which", return_value="/fake_system/aapt")
    assert ADBSession._aapt_check() == "/fake_system/aapt"
    (tmp_path / "android-9").mkdir()
    fake_aapt = tmp_path / "android-9" / "aapt"
    fake_aapt.touch()
    # use recommended aapt
    mocker.patch("grizzly.target.adb_device.adb_session.ANDROID_SDK_ROOT", tmp_path)
    assert ADBSession._aapt_check() == str(fake_aapt)
    # aapt not installed
    mocker.patch("grizzly.target.adb_device.adb_session.ANDROID_SDK_ROOT", Path("/missing"))
    mocker.patch("grizzly.target.adb_device.adb_session.which", return_value=None)
    with pytest.raises(EnvironmentError, match=r"Please install AAPT"):
        assert ADBSession._aapt_check()

def test_adb_session_28(mocker, tmp_path):
    """test ADBSession._adb_check()"""
    mocker.patch("grizzly.target.adb_device.adb_session.sleep")  # skip delay after warning message
    # use system adb
    mocker.patch("grizzly.target.adb_device.adb_session.ANDROID_SDK_ROOT", Path("/missing"))
    mocker.patch("grizzly.target.adb_device.adb_session.which", return_value="/fake_system/adb")
    assert ADBSession._adb_check() == "/fake_system/adb"
    (tmp_path / "platform-tools").mkdir()
    fake_adb = tmp_path / "platform-tools" / "adb"
    fake_adb.touch()
    # use recommended adb
    mocker.patch("grizzly.target.adb_device.adb_session.ANDROID_SDK_ROOT", tmp_path)
    assert ADBSession._adb_check() == str(fake_adb)
    # adb not installed
    mocker.patch("grizzly.target.adb_device.adb_session.ANDROID_SDK_ROOT", Path("/missing"))
    mocker.patch("grizzly.target.adb_device.adb_session.which", return_value=None)
    with pytest.raises(EnvironmentError, match=r"Please install ADB"):
        assert ADBSession._adb_check()

def test_adb_session_29(mocker, tmp_path):
    """test ADBSession.get_package_name()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._aapt_check", return_value="/fake/aapt")
    mocker.patch("grizzly.target.adb_device.adb_session.check_output", return_value=b"")
    with pytest.raises(IOError):
        ADBSession.get_package_name("/fake/path")
    fake_apk = tmp_path / "fake.apk"
    fake_apk.touch()
    assert ADBSession.get_package_name(str(fake_apk)) is None
    output = (
        b"package: name='org.mozilla.fennec_aurora' versionCode='2015624653' versionName='68.0a1' platformBuildVersionName=''",
        b"install-location:'internalOnly'",
        b"sdkVersion:'16'",
        b"targetSdkVersion:'28'",
        b"uses-permission: name='android.permission.READ_SYNC_SETTINGS'",
        b"uses-permission: name='org.mozilla.fennec_aurora_fxaccount.permission.PER_ACCOUNT_TYPE'",
        b"application-label:'Firefox Nightly'",
        b"application-label-en-GB:'Firefox Nightly'",
        b"application-icon-240:'res/mipmap-anydpi-v26/ic_launcher.xml'",
        b"application-icon-65535:'res/mipmap-anydpi-v26/ic_launcher.xml'",
        b"application: label='Firefox Nightly' icon='res/mipmap-anydpi-v26/ic_launcher.xml'",
        b"application-debuggable",
        b"feature-group: label=''",
        b"  uses-gl-es: '0x20000'",
        b"  uses-feature-not-required: name='android.hardware.audio.low_latency'",
        b"  uses-feature: name='android.hardware.touchscreen'",
        b"  uses-feature: name='android.hardware.location.network'",
        b"  uses-implied-feature: name='android.hardware.location.network' reason='requested android.permission.ACCESS_COARSE_LOCATION permission'",
        b"  uses-feature: name='android.hardware.wifi'",
        b"  uses-implied-feature: name='android.hardware.wifi' reason='requested android.permission.ACCESS_WIFI_STATE permission, and requested android.permission.CHANGE_WIFI_STATE permission'",
        b"provides-component:'app-widget'",
        b"main",
        b"other-activities",
        b"other-receivers",
        b"other-services",
        b"supports-screens: 'small' 'normal' 'large' 'xlarge'",
        b"supports-any-density: 'true'",
        b"locales: '--_--' 'ca' ' 'en-GB' 'zh-HK' 'zh-CN' 'en-IN' 'pt-BR' 'es-US' 'pt-PT' 'en-AU' 'zh-TW'",
        b"densities: '120' '160' '240' '320' '480' '640' '65534' '65535'",
        b"native-code: 'x86'")
    mocker.patch("grizzly.target.adb_device.adb_session.check_output", return_value=b"\n".join(output))
    assert ADBSession.get_package_name(str(fake_apk)) == "org.mozilla.fennec_aurora"

def test_adb_session_30(mocker):
    """test ADBSession.get_enforce()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    mocker.patch("grizzly.target.adb_device.ADBSession.call", return_value=(0, "Enforcing"))
    session = ADBSession("127.0.0.1")
    assert session.get_enforce()
    mocker.patch("grizzly.target.adb_device.ADBSession.call", return_value=(0, "Blah"))
    session = ADBSession("127.0.0.1")
    assert not session.get_enforce()

def test_adb_session_31(mocker):
    """test ADBSession.set_enforce()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    # disable when enabled
    fake_call = mocker.patch("grizzly.target.adb_device.ADBSession.call")
    mocker.patch("grizzly.target.adb_device.ADBSession.get_enforce", return_value=True)
    session = ADBSession("127.0.0.1")
    session.set_enforce(0)
    assert fake_call.call_count == 1
    fake_call.reset_mock()
    # enable when disabled
    mocker.patch("grizzly.target.adb_device.ADBSession.get_enforce", return_value=False)
    session = ADBSession("127.0.0.1")
    session.set_enforce(1)
    assert fake_call.call_count == 1

def test_adb_session_32(mocker):
    """test ADBSession.realpath()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "realpath":
            if cmd[3] == "missing/path":
                return 1, ""
            return 0, "existing/path"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    with pytest.raises(IOError):
        session.realpath("missing/path")
    assert session.realpath("existing/path") == "existing/path"

def test_adb_session_33(mocker):
    """test ADBSession.reverse()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "reverse":
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.reverse(1234, 1235)
    with pytest.raises(AssertionError):
        session.reverse(1, 1235)
    with pytest.raises(AssertionError):
        session.reverse(1234, 1)
    with pytest.raises(AssertionError):
        session.reverse(65536, 1235)
    with pytest.raises(AssertionError):
        session.reverse(1234, 65536)

def test_adb_session_34(mocker):
    """test ADBSession.reverse_remove()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "reverse":
            if cmd[2] == "--remove":
                assert cmd[3].startswith("tcp:")
            elif cmd[2] == "--remove-all":
                pass
            else:
                raise AssertionError("unexpected command %r" % (cmd,))
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.reverse_remove()
    assert session.reverse_remove(remote=1025)
    with pytest.raises(AssertionError):
        session.reverse_remove(remote=65536)
    with pytest.raises(AssertionError):
        session.reverse_remove(remote=1023)

def test_adb_session_35(mocker):
    """test ADBSession.airplane_mode()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "settings":
            if cmd[3] == "get":
                assert cmd[4] == "global"
                assert cmd[5] == "airplane_mode_on"
                return 0, "1"
            if cmd[3] == "put":
                assert cmd[4] == "global"
                assert cmd[5] == "airplane_mode_on"
                assert cmd[6] in "01"
                return 0, ""
        if cmd[1] == "shell" and cmd[2] == "su":
            assert cmd[3] == "root"
            assert cmd[4] == "am"
            assert cmd[5] == "broadcast"
            assert cmd[6] == "-a"
            assert cmd[7] == "android.intent.action.AIRPLANE_MODE"
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    session = ADBSession("127.0.0.1")
    session.connected = True
    session.airplane_mode = False
    session.airplane_mode = True
    assert session.airplane_mode

def test_adb_session_36(mocker):
    """test ADBSession.wait_for_boot()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    fake_sleep = mocker.patch("grizzly.target.adb_device.adb_session.sleep")
    # test timeout
    def fake_adb_01(_, cmd, timeout=None):
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                return 0, ""
            if cmd[3] == "sys.boot_completed":
                return 0, "0"
        raise AssertionError("unexpected command %r" % (cmd,))
    ADBSession._call_adb = fake_adb_01
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert not session.wait_for_boot(timeout=0.01)
    fake_sleep.reset_mock()
    # test already booted
    def fake_adb_02(_, cmd, timeout=None):
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                return 0, "stopped"
            if cmd[3] == "sys.boot_completed":
                return 0, "1"
        raise AssertionError("unexpected command %r" % (cmd,))
    ADBSession._call_adb = fake_adb_02
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.wait_for_boot()
    assert fake_sleep.call_count == 0
    fake_sleep.reset_mock()
    # test boot in progress
    anim_done = False
    boot_done = False
    def fake_adb_03(obj, cmd, timeout=None):
        nonlocal anim_done
        nonlocal boot_done
        if cmd[1] == "shell" and cmd[2] == "getprop":
            if cmd[3] == "init.svc.bootanim":
                if not anim_done:
                    anim_done = True
                    return 0, ""
                return 0, "stopped"
            if cmd[3] == "sys.boot_completed":
                if not boot_done:
                    boot_done = True
                    return 0, "0"
                return 0, "1"
        raise AssertionError("unexpected command %r" % (cmd,))
    ADBSession._call_adb = fake_adb_03
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.wait_for_boot()
    assert fake_sleep.call_count == 3

def test_adb_session_37(mocker):
    """test ADBSession.reboot_device()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_call(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "reboot":
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_call)
    mocker.patch("grizzly.target.adb_device.ADBSession.connect", spec=True)
    session = ADBSession()
    session.connected = True
    with pytest.raises(AssertionError):
        session.reboot_device()

def test_adb_session_38(mocker):
    """test ADBSession.remount()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_adb_01(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "remount":
            return 0, "Permission denied"
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_01)
    session = ADBSession()
    session.connected = True
    session._root = True
    with pytest.raises(ADBSessionError):
        session.remount()
    def fake_adb_02(cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "remount":
            return 0, ""
        raise AssertionError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb", side_effect=fake_adb_02)
    session = ADBSession()
    session.connected = True
    # test as non-root
    with pytest.raises(AssertionError):
        session.remount()
    session._root = True
    # test as root
    session.remount()

def test_adb_session_39():
    """test ADBSession._line_to_info()"""
    # nothing to parse
    assert ADBSession._line_to_info("") is None
    # invalid number of entries
    assert ADBSession._line_to_info(" ".join("a" * 20)) is None
    # invalid data (valid number of entries)
    assert ADBSession._line_to_info(" ".join("a" * 9)) is None
    # valid info
    pinfo = ADBSession._line_to_info("a 1 2 a 3 a a a name")
    assert pinfo is not None
    assert pinfo.memory == 3
    assert pinfo.name == "name"
    assert pinfo.pid == 1
    assert pinfo.ppid == 2

def test_adb_session_40(mocker):
    """test ADBSession.sanitizer_options()"""
    mocker.patch("grizzly.target.adb_device.ADBSession._adb_check", return_value="/fake/adb")
    def fake_install_file(src, dst, **_):
        assert os.path.basename(src) == "asan.options.gecko"
        with open(src, "r") as ofp:
            assert ofp.read() in ("a=1:b=2", "b=2:a=1")
        assert dst == "/data/local/tmp/"
    mocker.patch("grizzly.target.adb_device.ADBSession.install_file", side_effect=fake_install_file)
    session = ADBSession()
    session.sanitizer_options("asan", {"a":"1", "b":"2"})
