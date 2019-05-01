import logging
import os
import shutil
import tempfile
import unittest
import zipfile

from .device import ADBCommandError, ADBProcess, ADBSession, ADBSessionError, ADBLaunchError
from .fake_adb import FakeADBState

# set output verbosity
if bool(os.getenv("DEBUG")):
    logging.basicConfig(
        format="%(levelname).1s %(name)s [%(asctime)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG)
else:
    logging.basicConfig(
        format="[%(asctime)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO)

CWD = os.path.realpath(os.path.dirname(__file__))

class ADBSessionTests(unittest.TestCase):  # pylint: disable=too-many-public-methods

    def setUp(self):
        ADBSession.BIN_ADB = os.path.join(CWD, "fake_adb.py")
        if os.path.isfile(FakeADBState.STATE_FILE):
            os.remove(FakeADBState.STATE_FILE)
        self.tmpdir = tempfile.mkdtemp(prefix="adbdev_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        if os.path.isfile(FakeADBState.STATE_FILE):
            os.remove(FakeADBState.STATE_FILE)

    def test_01(self):
        "test creating a session with invalid args"
        with self.assertRaises(ValueError):
            ADBSession("invalid.ip")
        with self.assertRaises(ValueError):
            ADBSession("127.0.0.1", port=7)
        with self.assertRaises(ValueError):
            ADBSession("127.0.0.1", port="bad")

    def test_02(self):
        "test simple session"
        test_ip = "127.0.0.1"
        test_port = 5556
        session = ADBSession(test_ip, test_port)
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access
        self.assertEqual(session._ip_addr, test_ip)  # pylint: disable=protected-access
        self.assertEqual(session._port, test_port)  # pylint: disable=protected-access

    def test_03(self):
        "test _devices_available()"
        adb_output = [
            "List of devices attached",
            "* daemon not running; starting now at tcp:5037",
            "* daemon started successfully",
            "emulator-5554   device"]
        self.assertFalse(ADBSession._devices_available("\n".join(adb_output[:-1])))  # pylint: disable=protected-access
        self.assertTrue(ADBSession._devices_available("\n".join(adb_output)))  # pylint: disable=protected-access

    def test_04(self):
        "test create()"
        test_ip = "localhost"
        test_port = 5555
        session = ADBSession.create(test_ip, test_port)
        self.assertIsNotNone(session)
        self.assertTrue(session.connected)
        self.assertTrue(session._root)  # pylint: disable=protected-access
        self.assertEqual(session._ip_addr, test_ip)  # pylint: disable=protected-access
        self.assertEqual(session._port, test_port)  # pylint: disable=protected-access
        session.disconnect()
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access
        # test without IP
        if os.path.isfile(FakeADBState.STATE_FILE):
            os.remove(FakeADBState.STATE_FILE)
        session = ADBSession.create()
        self.assertIsNone(session._ip_addr)  # pylint: disable=protected-access
        self.assertIsNone(session._port)  # pylint: disable=protected-access
        self.assertIsNotNone(session)
        self.assertTrue(session.connected)
        self.assertTrue(session._root)  # pylint: disable=protected-access
        session.disconnect()
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access

    def test_05(self):
        "test connect() and disconnect()"
        session = ADBSession("127.0.0.1")
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access
        session.disconnect()
        # connect and enable root
        state = FakeADBState()
        state.connected = False
        state.root_enabled = False
        state.save()
        self.assertTrue(session.connect(max_attempts=1))
        self.assertTrue(session.connected)
        self.assertTrue(session._root)  # pylint: disable=protected-access
        session.disconnect()
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access
        # connect and do not enable root
        state = FakeADBState()
        state.connected = False
        state.root_enabled = False
        state.save()
        self.assertTrue(session.connect(as_root=False))
        self.assertTrue(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access
        session.disconnect()
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access
        # connect() x2 (already connected)
        state = FakeADBState()
        state.connected = False
        state.root_enabled = False
        state.save()
        self.assertTrue(session.connect())
        self.assertTrue(session.connected)
        self.assertTrue(session.connect())
        self.assertTrue(session.connected)
        self.assertTrue(session._root)  # pylint: disable=protected-access
        session.disconnect()
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access

    def test_06(self):
        "test connect() with unavailable device"
        session = ADBSession("127.0.0.1")
        # connect to
        state = FakeADBState()
        state.connected = False
        state.unavailable = True
        state.save()
        self.assertFalse(session.connect(max_attempts=1))
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access
        session.disconnect()
        self.assertFalse(session.connected)
        self.assertFalse(session._root)  # pylint: disable=protected-access

    def test_07(self):
        "test call() with invalid command"
        session = ADBSession.create("127.0.0.1", 5555)
        with self.assertRaises(ADBCommandError):
            session.call(["unknown-cmd"])  # pylint: disable=protected-access
        session.disconnect()

    def test_08(self):
        "test install()"
        def _fake_get_package_name(apk_path):
            with zipfile.ZipFile(apk_file, mode="r")as zfp:
                with zfp.open("package-name.txt", "r") as pfp:
                    return pfp.read().strip()

        pkg_name = "test-package.blah.foo\n"
        session = ADBSession("127.0.0.1")
        session.get_package_name = _fake_get_package_name
        # connect and do not enable root
        self.assertTrue(session.connect())
        with self.assertRaises(IOError):
            session.install("fake_path")

        pkg_file = os.path.join(self.tmpdir, "package-name.txt")
        apk_file = os.path.join(self.tmpdir, "test.apk")
        syms_path = os.path.join(self.tmpdir, "symbols")
        os.makedirs(syms_path)
        with open(pkg_file, "w") as out_fp:
            out_fp.write(pkg_name)
        with zipfile.ZipFile(apk_file, mode="w")as z_out:
            z_out.write(pkg_file, "package-name.txt")
        self.assertFalse(session.symbols_path(apk_file))
        self.assertTrue(session.install(apk_file))
        session.symbols[apk_file] = syms_path
        self.assertEqual(session.symbols_path(apk_file), syms_path)
        session.disconnect()
        # TODO: test failed to install, failed to get package name

    def test_09(self):
        "test uninstall()"
        session = ADBSession("127.0.0.1")
        self.assertFalse(session.uninstall("org.test.unknown"))
        self.assertTrue(session.connect())
        self.assertTrue(session.uninstall("org.test.unknown"))
        self.assertTrue(session.uninstall("org.test.preinstalled"))
        session.disconnect()

    def test_10(self):
        "test get_pid()"
        session = ADBSession("127.0.0.1")
        with self.assertRaises(ADBSessionError):
            session.get_pid("org.test.unknown")
        self.assertTrue(session.connect())
        self.assertIsNone(session.get_pid("org.test.unknown"))
        self.assertEqual(session.get_pid("org.test.preinstalled"), 1337)
        session.disconnect()

    def test_11(self):
        "test is_installed()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        self.assertFalse(session.is_installed("org.test.unknown"))
        self.assertTrue(session.is_installed("org.test.preinstalled"))
        session.disconnect()

    def test_12(self):
        "test get_packages()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        pkgs = session.get_packages()
        self.assertEqual(len(pkgs), 4)
        self.assertNotIn("org.test.unknown", pkgs)
        self.assertIn("org.test.preinstalled", pkgs)
        session.disconnect()

    def test_13(self):
        "test collect_logs()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        self.assertEqual(len(session.collect_logs().splitlines()), 16)
        self.assertEqual(len(session.collect_logs(9990).splitlines()), 11)
        self.assertEqual(len(session.collect_logs(1111).splitlines()), 0)
        session.disconnect()

    def test_14(self):
        "test get_open_files()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        # list all open files
        self.assertEqual(len(session.get_open_files()), 7)
        # list process specific open files
        self.assertEqual(len(session.get_open_files(pid=9990)), 5)
        # list process and children specific open files
        self.assertEqual(len(session.get_open_files(pid=9990, children=True)), 6)
        with self.assertRaises(AssertionError):
            session.get_open_files(pid=None, children=True)
        session.disconnect()

    def test_15(self):
        "test _get_procs()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        self.assertEqual(len(session._get_procs()), 10)  # pylint: disable=protected-access
        dev_procs = session._get_procs(pid_children=9990)  # pylint: disable=protected-access
        self.assertTrue(len(dev_procs), 1)
        self.assertEqual(dev_procs[0].pid, 9991)
        session.disconnect()

    def test_16(self):
        "test push()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        with self.assertRaises(IOError):
            session.push("not_a_file", "dst")
        self.assertTrue(session.push(ADBSession.BIN_ADB, "dst"))
        session.disconnect()

    def test_17(self):
        "test pull()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        self.assertTrue(session.pull("src", "dst"))
        session.disconnect()

    def test_18(self):
        "test clear_log()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        self.assertTrue(session.clear_logs())
        session.disconnect()

    def test_19(self):
        "test listdir()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        with self.assertRaises(IOError):
            session.listdir("missing-dir")
        dir_list = session.listdir("fake-dir")
        self.assertEqual(len(dir_list), 1)
        self.assertIn("test", session.listdir("fake-dir"))
        session.disconnect()

    def test_20(self):
        "test process_exists()"
        session = ADBSession("127.0.0.1")
        self.assertTrue(session.connect())
        self.assertTrue(session.process_exists(9990))
        session.disconnect()

# TODO:
# reverse


class ADBProcessTests(unittest.TestCase):  # pylint: disable=too-many-public-methods

    def setUp(self):
        ADBSession.BIN_ADB = os.path.join(CWD, "fake_adb.py")
        if os.path.isfile(FakeADBState.STATE_FILE):
            os.remove(FakeADBState.STATE_FILE)
        self.tmpdir = tempfile.mkdtemp(prefix="adbdev_test")
        self.session = ADBSession.create("127.0.0.1", 5566)

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        if os.path.isfile(FakeADBState.STATE_FILE):
            os.remove(FakeADBState.STATE_FILE)
        self.session.disconnect()

    def test_01(self):
        "test creating a simple device"
        test_pkg = "org.test.preinstalled"
        proc = ADBProcess(test_pkg, self.session)
        self.addCleanup(proc.cleanup)
        self.assertTrue(isinstance(proc._session, ADBSession))  # pylint: disable=protected-access
        self.assertEqual(proc._package, test_pkg)  # pylint: disable=protected-access
        self.assertIsNone(proc.logs)
        self.assertIsNone(proc.profile)
        self.assertEqual(proc.reason, proc.RC_CLOSED)
        self.assertIsNone(proc._pid)  # pylint: disable=protected-access
        proc.close()
        self.assertFalse(proc.logs)  # should not have logs

    def test_02(self):
        "test creating device with unknown package"
        with self.assertRaises(ADBSessionError):
            ADBProcess("org.test.unknown", self.session)

    def test_03(self):
        "test failed launch() and is_running()"
        proc = ADBProcess("org.test.preinstalled", self.session)
        self.addCleanup(proc.cleanup)
        self.assertFalse(proc.is_running())
        with self.assertRaises(ADBLaunchError):
            proc.launch("fake.url")
        self.assertFalse(proc.is_running())
        proc.cleanup()
        self.assertIsNone(proc.logs)

    def test_04(self):
        "test launch(), is_running() and is_healthy()"
        proc = ADBProcess("org.mozilla.fennec_aurora", self.session)
        self.addCleanup(proc.cleanup)
        self.assertFalse(proc.is_running())
        self.assertTrue(proc.launch("fake.url"))
        self.assertTrue(proc.is_running())
        self.assertTrue(proc.is_healthy())
        proc.close()
        self.assertIsNone(proc._pid)  # pylint: disable=protected-access
        self.assertGreater(len(proc.logs), 0)

    def test_05(self):
        "test launch() with environment variables"
        proc = ADBProcess("org.mozilla.fennec_aurora", self.session)
        self.addCleanup(proc.cleanup)
        env = {"test1":"1", "test2": "2"}
        self.assertTrue(proc.launch("fake.url", env_mod=env))
        self.assertTrue(proc.is_running())
        proc.close()

    def test_06(self):
        "test wait_on_files()"
        proc = ADBProcess("org.mozilla.fennec_aurora", self.session)
        self.addCleanup(proc.cleanup)
        self.assertTrue(proc.wait_on_files(["not_running"]))
        self.assertTrue(proc.launch("fake.url"))
        self.assertTrue(proc.wait_on_files([]))  # is running but empty list
        self.assertFalse(proc.wait_on_files(
            ["/system/fonts/Roboto-Regular.ttf"],
            poll_rate=0.1,
            timeout=0.3))
        proc.close()

# TODO:
# _process_logs
# save_logs
