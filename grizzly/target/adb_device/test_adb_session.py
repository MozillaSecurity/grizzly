# pylint: disable=protected-access
import os
import subprocess
import zipfile

import pytest

from .adb_session import ADBCommandError, ADBSession, ADBSessionError

def test_adb_session_01(mocker):
    """test ADBSession._call_adb()"""
    def fake_call(cmd, stderr=None, stdout=None):
        assert cmd[0] == "test"
        stderr.write("")
        stdout.write("blah_out")
        return 0
    mocker.patch("subprocess.call", side_effect=fake_call)
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
    mocker.patch("subprocess.Popen")
    subprocess.Popen = FakeProc
    ret, output = ADBSession._call_adb(["test"], timeout=0.5)
    assert ret == 1
    assert "init" in output
    assert "poll" in output
    assert "terminate" in output
    assert "wait" in output

def test_adb_session_02():
    """test creating a session with invalid args"""
    with pytest.raises(ValueError):
        ADBSession("invalid.ip")
    with pytest.raises(ValueError):
        ADBSession("127.0.0.1", port=7)
    with pytest.raises(ValueError):
        ADBSession("127.0.0.1", port="bad")

def test_adb_session_03():
    """test simple ADBSession"""
    test_ip = "127.0.0.1"
    test_port = 5556
    session = ADBSession(test_ip, test_port)
    assert not session.connected
    assert not session._root
    assert session._ip_addr == test_ip
    assert session._port == test_port

def test_adb_session_04():
    """test ADBSession._devices_available()"""
    adb_output = (
        "List of devices attached",
        "* daemon not running; starting now at tcp:5037",
        "* daemon started successfully",
        "emulator-5554   device")
    assert not ADBSession._devices_available("\n".join(adb_output[:-1]))
    assert ADBSession._devices_available("\n".join(adb_output))

def test_adb_session_05(mocker):
    """test simple ADBSession.create()"""
    test_ip = "localhost"
    test_port = 5555
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            assert cmd[2] == ":".join([test_ip, str(test_port)])
            return 0, ""
        # already Permissive
        if cmd[1] == "shell" and cmd[2] == "getenforce":
            return 0, "Permissive"
        # already root
        if cmd[1] == "shell" and cmd[2] == "whoami":
            return 0, "root"
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession.create(test_ip, test_port)
    assert session is not None
    assert session.connected
    assert session._root
    assert session._ip_addr == test_ip
    assert session._port == test_port

def test_adb_session_06(mocker):
    """test full ADBSession.create()"""
    test_ip = "localhost"
    test_port = 5555
    def fake_adb_call(obj, cmd, timeout=None):
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
        if cmd[1] == "root":
            obj._root = True
            obj.connected = False
            return 0, "restarting adbd as root"
        if cmd[1] == "shell" and cmd[2] == "getenforce":
            return 0, "Permissive"
        if cmd[1] == "shell" and cmd[2] == "whoami":
            if obj._root:
                return 0, "root"
            return 0, "shell"
        if cmd[1] == "unroot":
            obj._root = False
            obj.connected = False
            return 0, "restarting adbd as non root"
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession.create(test_ip, test_port)
    assert session is not None
    assert session.connected
    assert session._root
    assert session._ip_addr == test_ip
    assert session._port == test_port
    session.disconnect()
    assert not session.connected
    assert not session._root

def test_adb_session_07(mocker):
    """test ADBSession.create() without IP"""
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
        if cmd[1] == "shell" and cmd[2] == "whoami":
            return 0, "shell"
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession.create(as_root=False)
    assert session is not None
    assert session._ip_addr is None
    assert session._port is None
    assert session.connected
    assert not session._root
    session.disconnect()
    assert not session.connected

def test_adb_session_08(mocker):
    """test ADBSession.connect() and ADBSession.disconnect()"""
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
        if cmd[1] == "shell" and cmd[2] == "whoami":
            if obj._root:
                return 0, "root"
            return 0, "shell"
        if cmd[1] == "unroot":
            obj._root = False
            obj.connected = False
            return 0, "restarting adbd as non root"
        raise RuntimeError("unexpected command %r" % (cmd,))
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

def test_adb_session_09(mocker):
    """test ADBSession.connect() with unavailable device"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "connect":
            return 1, "unable to connect"
        if cmd[1] == "disconnect":
            return 0, ""
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    assert not session.connected
    assert not session._root
    session.disconnect()
    # connect and enable root
    assert not session.connect(max_attempts=1)
    assert not session.connected
    assert not session._root

def test_adb_session_10(mocker):
    """test ADBSession.all() with unknown command"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        return 1, "Android Debug Bridge version 1.0.XX"
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    session._root = True
    with pytest.raises(ADBCommandError):
        session.call(["unknown-cmd"])

def test_adb_session_11(tmp_path, mocker):
    """test ADBSession.install()"""
    def fake_get_package_name(_):
        with zipfile.ZipFile(apk_file, mode="r")as zfp:
            with zfp.open("package-name.txt", "r") as pfp:
                return pfp.read().strip()
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "install":
            assert cmd[2] == "-r"
            assert "test.apk" in cmd[3]
            return 0, "Success"
        if cmd[1] == "shell":
            assert cmd[2] == "pm"
            assert cmd[3] == "grant"
            assert cmd[4] == "test-package.blah.foo"
            return 0, ""
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    session.get_package_name = fake_get_package_name
    with pytest.raises(IOError):
        session.install("fake_path")
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
    # TODO: test failed to install, failed to get package name

def test_adb_session_12(mocker):
    """test ADBSession.uninstall()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "uninstall" and cmd[2] == "org.test.preinstalled":
            return 0, "Success"
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    assert not session.uninstall("org.test.unknown")
    session.connected = True
    #assert session.uninstall("org.test.unknown")
    assert session.uninstall("org.test.preinstalled")

def test_adb_session_13(mocker):
    """test ADBSession.get_pid()"""
    def fake_adb_call(obj, cmd, timeout=None):
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
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    with pytest.raises(ADBSessionError):
        session.get_pid("org.test.unknown")
    session.connected = True
    assert session.get_pid("org.test.unknown") is None
    assert session.get_pid("org.test.preinstalled") == 1337

def test_adb_session_14(mocker):
    """test ADBSession.is_installed()"""
    def fake_adb_call(obj, cmd, timeout=None):
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
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert not session.is_installed("org.test.unknown")
    assert session.is_installed("org.test.preinstalled")

def test_adb_session_15(mocker):
    """test ADBSession.get_packages()"""
    def fake_adb_call(obj, cmd, timeout=None):
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
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    pkgs = session.get_packages()
    assert len(pkgs) == 4
    assert "com.android.phone" in pkgs
    assert "com.android.shell" in pkgs
    assert "org.mozilla.fennec_aurora" in pkgs
    assert "org.test.preinstalled" in pkgs

def test_adb_session_16(mocker):
    """test ADBSession.collect_logs()"""
    def fake_adb_call(obj, cmd, timeout=None):
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
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert len(session.collect_logs().splitlines()) == 11
    assert len(session.collect_logs(9990).splitlines()) == 7
    assert not session.collect_logs(1111).splitlines()

def test_adb_session_17(mocker):
    """test ADBSession.get_packages()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "lsof":
            if len(cmd) == 5:
                assert cmd[3].startswith("-p")
                pids = {int(x) for x in cmd[-1].split(",")}
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
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    # list all open files
    assert len(session.get_open_files()) == 7
    # list process specific open files
    assert len(session.get_open_files(pid=9990)) == 5
    # list process and children specific open files
    assert len(session.get_open_files(pid=9990, children=True)) == 6
    with pytest.raises(AssertionError):
        session.get_open_files(pid=None, children=True)

def test_adb_session_18(mocker):
    """test ADBSession._get_procs()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "ps":
            print(cmd)
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
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert len(session._get_procs()) == 10
    dev_procs = session._get_procs(pid_children=9990)
    assert len(dev_procs) == 1
    assert dev_procs[0].pid == 9991

def test_adb_session_19(tmp_path, mocker):
    """test ADBSession.push()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "push":
            assert "test.txt" in cmd[2]
            assert cmd[3] == "dst"
            return 0, " pushed. "
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    with pytest.raises(IOError):
        session.push("not_a_file", "dst")
    push_file = tmp_path / "test.txt"
    push_file.write_bytes(b"test\n")
    assert session.push(str(push_file), "dst")

def test_adb_session_20(mocker):
    """test ADBSession.pull()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "pull":
            assert cmd[2] == "src"
            assert cmd[3] == "dst"
            return 0, " pulled. "
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.pull("src", "dst")

def test_adb_session_21(mocker):
    """test ADBSession.clear_log()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "logcat":
            assert cmd[2] == "--clear"
            return 0, ""
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.clear_logs()

def test_adb_session_22(mocker):
    """test ADBSession.listdir()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "ls":
            assert cmd[3] == "-A"
            if cmd[4] == "missing-dir":
                return 1, ""
            return 0, "test"
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    with pytest.raises(IOError):
        session.listdir("missing-dir")
    dir_list = session.listdir("fake-dir")
    assert len(dir_list) == 1
    assert "test" in session.listdir("fake-dir")

def test_adb_session_23(mocker):
    """test ADBSession.process_exists()"""
    def fake_adb_call(obj, cmd, timeout=None):
        assert cmd and cmd[0].endswith("adb")
        if cmd[1] == "shell" and cmd[2] == "ps":
            assert cmd[3] == "9990"
            output = (
                "USER      PID   PPID  VSIZE  RSS   WCHAN            PC  NAME",
                "u0_a80    9990  1772  1221212 128064 SyS_epoll_ 00000000 S org.mozilla.fennec_aurora",
                "")
            return 0, "\n".join(output)
        raise RuntimeError("unexpected command %r" % (cmd,))
    mocker.patch("grizzly.target.adb_device.ADBSession._call_adb")
    ADBSession._call_adb = fake_adb_call
    session = ADBSession("127.0.0.1")
    session.connected = True
    assert session.process_exists(9990)

# TODO:
# reverse
