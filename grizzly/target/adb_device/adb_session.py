# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import socket
from collections import namedtuple
from logging import getLogger
from os import getenv
from pathlib import Path
from platform import system
from shutil import which
from subprocess import PIPE, STDOUT, TimeoutExpired, check_output, run
from tempfile import TemporaryDirectory
from time import sleep, time

from ...common.utils import grz_tmp

LOG = getLogger("adb_session")

__all__ = ("ADBCommandError", "ADBCommunicationError", "ADBSession", "ADBSessionError")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


DeviceProcessInfo = namedtuple("DeviceProcessInfo", "memory name pid ppid")


def _get_android_sdk():
    if getenv("ANDROID_HOME") is not None:
        android_home = Path(getenv("ANDROID_HOME"))
        if android_home.is_dir():
            return android_home
    if getenv("ANDROID_SDK_ROOT") is not None:
        return Path(getenv("ANDROID_SDK_ROOT"))
    if system() == "Windows" and getenv("LOCALAPPDATA") is not None:
        return Path(getenv("LOCALAPPDATA")) / "Android" / "sdk"
    if system() == "Darwin":
        return Path.home() / "Library" / "Android" / "sdk"
    return Path.home() / "Android" / "Sdk"


ANDROID_SDK_ROOT = _get_android_sdk()


class ADBCommandError(Exception):
    """Raised when an ADB command is invalid or unrecognized"""


class ADBCommunicationError(Exception):
    """Raised when ADB fails to communicate with the device"""


class ADBSessionError(Exception):
    """Raised when an operation fails unexpectedly or session state is invalid"""


# pylint: disable=too-many-public-methods
class ADBSession:
    __slots__ = (
        "_adb_bin",
        "_cpu_arch",
        "_debug_adb",
        "_ip_addr",
        "_os_version",
        "_os_version",
        "_port",
        "_root",
        "connected",
        "symbols",
    )

    def __init__(self, ip_addr=None, port=5555):
        self._adb_bin = self._adb_check()
        self._cpu_arch = None  # Android CPU architecture string
        self._debug_adb = getenv("SHOW_ADB_DEBUG", "0") != "0"  # include ADB output
        self._ip_addr = None  # target device IP address
        self._os_version = None  # Android version string
        self._port = None  # ADB listening port
        self._root = False
        self.connected = False
        self.symbols = dict()

        if ip_addr is not None:
            LOG.debug("creating IP based session")
            try:
                if ip_addr != "localhost":
                    socket.inet_aton(ip_addr)
            except (socket.error, TypeError):
                raise ValueError("Invalid IP Address") from None
            self._ip_addr = ip_addr
            if not isinstance(port, int) or not 0x10000 > port > 1024:
                raise ValueError("Port must be valid integer between 1025 and 65535")
            self._port = port

    @classmethod
    def _aapt_check(cls):
        """Lookup the path for Android Asset Packaging Tool (AAPT).
        An EnvironmentError is raised if the AAPT executable is not found.

        Args:
            None

        Returns:
            str: Path to AAPT binary.
        """
        aapt_bin = ANDROID_SDK_ROOT / "android-9" / "aapt"
        if aapt_bin.is_file():
            LOG.debug("using recommended aapt from '%s'", aapt_bin)
            return str(aapt_bin)
        aapt_bin = which("aapt")
        if aapt_bin is None:
            raise EnvironmentError("Please install AAPT")
        aapt_bin = Path(aapt_bin)
        # TODO: update this to check aapt version
        LOG.warning("Using aapt_bin from '%s'", aapt_bin)
        return str(aapt_bin)

    @classmethod
    def _adb_check(cls):
        """Lookup the path for Android Debug Bridge (ADB).
        An EnvironmentError is raised if the ADB executable is not found.

        Args:
            None

        Returns:
            str: Path to ADB binary.
        """
        adb_bin = ANDROID_SDK_ROOT / "platform-tools" / "adb"
        if adb_bin.is_file():
            LOG.debug("using recommended adb from '%s'", adb_bin)
            return str(adb_bin)
        adb_bin = which("adb")
        if adb_bin is None:
            raise EnvironmentError("Please install ADB")
        adb_bin = Path(adb_bin)
        # TODO: update this to check adb version
        LOG.warning("Using adb from '%s'", adb_bin)
        LOG.warning("You are not using the recommended ADB install!")
        LOG.warning("Either run the setup script or proceed with caution.")
        sleep(5)
        return str(adb_bin)

    @staticmethod
    def _call_adb(cmd, timeout=None):
        """Wrapper to make calls to ADB. Launches ADB in a subprocess and collects
        output. If timeout is specified and elapses the ADB subprocess is terminated.
        This function is only meant to be called directly by ADBSession.call().

        Args:
            cmd (list): List of strings containing full ADB command.
            timeout (float, optional): Seconds to wait for ADB command to complete.

        Returns:
            tuple: Exit code and stderr, stdout of ADB call.
        """
        try:
            result = run(
                cmd,
                encoding="utf-8",
                errors="replace",
                stderr=STDOUT,
                stdout=PIPE,
                timeout=timeout,
            )
        except TimeoutExpired:
            LOG.warning("ADB call timed out!")
            return 1, ""
        return result.returncode, result.stdout.strip()

    def _get_procs(self, pid=None, pid_children=None):
        """Generator function that yields a DeviceProcessInfo object for each running
        process by default. pid and pid_children can be used to filter the results.

        Args:
            pid (int, optional): Process ID to include in lookup.
            pid_children (int, optional): Used to lookup the children of the given PID.

        Yields:
            DeviceProcessInfo: One instance for each process found in lookup.
        """
        cmd = ["ps", "-A", "-o", "pid,ppid,rss,name"]
        if pid is not None:
            assert isinstance(pid, int)
            cmd.append(str(pid))
        if pid_children is not None:
            assert isinstance(pid_children, int)
            cmd += ["--ppid", str(pid_children)]
        for line in self.shell(cmd, timeout=30)[1].splitlines()[1:]:
            try:
                proc_id, ppid, memory, name = line.split()
                yield DeviceProcessInfo(int(memory), name, int(proc_id), int(ppid))
            except ValueError:
                LOG.debug("failed to parse ps line %r", line)

    @property
    def airplane_mode(self):
        """Get the current state of airplane mode.

        Args:
            None

        Returns:
            bool: True if airplane mode is enabled otherwise False.
        """
        return self.shell(["settings", "get", "global", "airplane_mode_on"])[
            1
        ].startswith("1")

    @airplane_mode.setter
    def airplane_mode(self, mode):
        """Enable/disable airplane mode.

        Args:
            mode (bool): True will enable and False will disable airplane mode.

        Returns:
            None
        """
        assert isinstance(mode, bool), "mode must be a bool"
        self.shell(
            ["settings", "put", "global", "airplane_mode_on", "1" if mode else "0"]
        )
        self.shell(
            [
                "su",
                "root",
                "am",
                "broadcast",
                "-a",
                "android.intent.action.AIRPLANE_MODE",
            ]
        )

    def call(self, cmd, device_required=True, timeout=120):
        """Call ADB with arguments provided in cmd.

        Args:
            cmd (list): List of strings to pass as arguments when calling ADB.
            device_required (bool, optional): A device must be available.
            timeout (float, optional): Seconds to wait for ADB call to complete.

        Returns:
            tuple: The first element is an integer containing the exit code of the
            ADB call and the second is a string containing stderr and stdout.
        """
        assert cmd
        cmd = [self._adb_bin] + cmd
        LOG.debug("call %r (%r)", " ".join(cmd[1:]), timeout)
        if not self.connected and cmd[1] not in ("connect", "devices", "disconnect"):
            raise ADBCommunicationError("ADB session is not connected!")
        ret_code, output = self._call_adb(cmd, timeout=timeout)
        if self._debug_adb:
            LOG.debug(
                "=== adb start ===\n%s\n=== adb end, returned %d ===", output, ret_code
            )
        if ret_code != 0:
            if output.startswith("Android Debug Bridge version"):
                raise ADBCommandError("Invalid ADB command '%s'" % (" ".join(cmd[1:]),))
            if output.startswith("adb: usage:"):
                raise ADBCommandError(output)
            if device_required and (
                output.startswith("error: closed")
                or output.startswith("error: device offline")
                or output.startswith("error: no devices/emulators found")
            ):
                self.connected = False
                raise ADBCommunicationError("No device detected!")
        return ret_code, output

    def clear_logs(self):
        """Call 'adb logcat --clear' to wipe logs

        Args:
            None

        Returns:
            None
        """
        return self.call(["logcat", "--clear"], timeout=10)[0] == 0

    def collect_logs(self, pid=None):
        """Collect logs from device with logcat.

        Args:
            pid (int, optional): Process ID to collect logs from. If pid is None
                Logs from all processes will be collected.

        Returns:
            None
        """
        LOG.debug("collect_logs()")
        if not self.connected:
            LOG.debug("device not connected cannot collect logs")
            # TODO: return None if disconnected?
            return ""
        cmd = ["logcat", "-d", "*:I"]
        if pid is not None:
            cmd += ["--pid=%d" % (pid,)]
        return self.call(cmd, timeout=30)[1].encode("utf-8", "ignore")

    def connect(self, as_root=True, boot_timeout=300, max_attempts=60, retry_delay=1):
        """Connect to a device via ADB.

        Args:
            as_root (bool, optional): Attempt to enable root. Default is True.
            boot_timeout (int, optional): Seconds to wait for device boot to complete.
            max_attempts (int, optional): Number of attempt to connect to the device.
            retry_delay (int, optional): Seconds to wait between connection attempts.

        Returns:
            bool: Returns True if connection was established otherwise False.
        """
        assert boot_timeout > 0
        assert max_attempts > 0
        assert retry_delay > 0
        self._cpu_arch = None
        self._os_version = None
        attempt = 0
        root_called = False
        set_enforce_called = False
        while attempt < max_attempts:
            attempt += 1
            if not self.connected:
                if self._ip_addr is not None:
                    addr = ":".join((self._ip_addr, str(self._port)))
                    LOG.debug("connecting to %s", addr)
                    if self.call(["connect", addr], timeout=30)[0] != 0:
                        LOG.warning("connection attempt #%d failed", attempt)
                        sleep(retry_delay)
                        continue
                elif not self.devices():
                    LOG.warning(
                        "No device detected (attempt %d/%d)", attempt, max_attempts
                    )
                    sleep(retry_delay)
                    continue
                self.connected = True
            # verify we are connected
            if not self.wait_for_boot(timeout=boot_timeout):
                raise ADBCommunicationError(
                    "Timeout (%ds) waiting for device to boot" % (boot_timeout,)
                )
            ret_code, user = self.call(
                ["shell", "-T", "-n", "whoami"], device_required=False, timeout=30
            )
            if ret_code != 0 or not user:
                self.connected = False
                if attempt == max_attempts:
                    raise ADBSessionError(
                        "Device in a bad state, try disconnect & reboot"
                    )
                continue
            self._root = user.splitlines()[-1] == "root"
            # collect CPU and OS info
            if self._os_version is None:
                self._os_version = self.shell(["getprop", "ro.build.version.release"])[
                    1
                ]
            if self._cpu_arch is None:
                self._cpu_arch = self.shell(["getprop", "ro.product.cpu.abi"])[1]
            # check SELinux mode
            if self._root:
                if self.get_enforce():
                    if set_enforce_called:
                        raise ADBSessionError("set_enforce(0) failed!")
                    # set SELinux to run in permissive mode
                    self.set_enforce(0)
                    self.shell(["stop"])
                    self.shell(["start"])
                    # put the device in a known state
                    self.call(["reconnect"], timeout=30)
                    self.connected = False
                    set_enforce_called = True
                    attempt -= 1
                    continue
            if not as_root or self._root:
                LOG.debug(
                    "connected device running Android %s (%s)",
                    self._os_version,
                    self._cpu_arch,
                )
                break
            # enable root
            assert as_root, "Should not be here if root is not requested"
            if self.call(["root"], timeout=30)[0] == 0:
                self.connected = False
                # only skip attempt to call root once
                if not root_called:
                    root_called = True
                    attempt -= 1
                    continue
            else:
                LOG.warning("Failed root login attempt")
        if self.connected and as_root and not self._root:
            raise ADBSessionError("Could not enable root")
        return self.connected

    @classmethod
    def create(
        cls, ip_addr=None, port=5555, as_root=True, max_attempts=10, retry_delay=1
    ):
        """Create a ADBSession and connect to a device via ADB.

        Args:
            ip_addr (str, optional): IP address of device to connect to if using TCP/IP.
                                     Defaults to None.
            port (int, optional): Port to use (TCP/IP only). Defaults to 5555.
            as_root (bool, optional): Attempt to enable root. Default is True.
            max_attempts (int, optional): Number of attempts to connect to the device.
            retry_delay (int, optional): Number of seconds to wait between attempts.

        Returns:
            ADBSession: A connected ADBSession object otherwise None
        """
        session = cls(ip_addr, port)
        if session.connect(
            as_root=as_root, max_attempts=max_attempts, retry_delay=retry_delay
        ):
            return session
        return None

    def devices(self, all_devices=False, any_state=True):
        """Devices visible to ADB.

        Args:
            all_devices (bool, optional): Don't filter devices using ANDROID_SERIAL
                                          environment variable.
            any_state (bool, optional): Include devices in a state other than "device".

        Returns:
            dict: A dictionary keyed on device name containing the state.
        """
        ret_code, entries = self.call(["devices"], timeout=30)
        devices = {}
        if ret_code != 0:
            return devices
        target_device = getenv("ANDROID_SERIAL", None) if not all_devices else None
        # skip header on the first line
        for entry in entries.splitlines()[1:]:
            try:
                name, state = entry.split()
            except ValueError:
                continue
            if target_device is not None and name != target_device:
                continue
            if not any_state and state != "device":
                continue
            devices[name] = state
        if target_device is None and not all_devices and len(devices) > 1:
            raise ADBSessionError(
                "Multiple devices available and ANDROID_SERIAL not set"
            )
        return devices

    def disconnect(self, unroot=True):
        """Disconnect.

        Args:
            unroot (bool, optional): Attempt to unroot device.

        Returns:
            None
        """
        if not self.connected:
            LOG.debug("already disconnected")
            return
        if self._root and unroot:
            try:
                if self.call(["unroot"], timeout=30)[0] == 0:
                    self.connected = False
                    self._root = False
                    return
                LOG.warning("'unroot' failed")
            except ADBCommandError:
                LOG.warning("'unroot' not support by ADB")
        elif self._ip_addr is not None:
            self.call(
                ["disconnect", ":".join((self._ip_addr, str(self._port)))], timeout=30
            )
        self.connected = False

    def get_enforce(self):
        """Get SELinux state.

        Args:
            None

        Returns:
            bool: Returns True if "Enforcing" otherwise False.
        """
        status = self.shell(["getenforce"])[1]
        if status == "Enforcing":
            return True
        if status != "Permissive":
            LOG.warning("Unexpected SELinux state '%r'", status)
        return False

    @classmethod
    def get_package_name(cls, apk_path):
        """Retrieve the package name from an APK.

        Args:
            apk_name (str): APK to retrieve the package name from.

        Returns:
            str: String containing the package name otherwise None.
        """
        if not Path(apk_path).is_file():
            raise IOError("APK path must point to a file")
        aapt = cls._aapt_check()
        apk_info = check_output((aapt, "dump", "badging", apk_path))
        for line in apk_info.splitlines():
            if line.startswith(b"package: name="):
                return line.split()[1][5:].strip(b"'").decode("utf-8", errors="ignore")
        return None

    def get_pid(self, package_name):
        """Retrieve process ID for the process with the specified package name.

        Args:
            apk_name (str): APK to to retrieve the package name from.

        Returns:
            int: PID of the process with the specified package name if it exists
                 otherwise None.
        """
        # TODO: _get_procs() is slow, move to pidof ASAP
        # pidof is not supported pre-Android 6... do we care about <6? if so we could
        # just fallback
        pids = [proc.pid for proc in self._get_procs() if proc.name == package_name]
        if not pids:
            return None
        count = len(pids)
        if count > 1:
            LOG.debug("get_pid() %d proc(s) found", count)
            # TODO: get procs and use the ppid of the procs the determine the parent
            # for now we are using the lowest pid...
            pids.sort()
        return pids[0]

    def install(self, apk_path):
        """Install APK on the connected device, grant R/W permissions to /sdcard and
        lookup the name of the installed APK.

        Args:
            apk_name (str): APK to install.

        Returns:
            str: Package name of APK that has been installed.
        """
        LOG.debug("installing %r", apk_path)
        if not Path(apk_path).is_file():
            raise IOError("APK does not exist %r" % (apk_path,))
        # lookup package name
        pkg_name = self.get_package_name(apk_path)
        if pkg_name is None:
            raise ADBSessionError("Could not find APK package name")
        if self.call(["install", "-g", "-r", apk_path], timeout=180)[0] != 0:
            raise ADBSessionError("Failed to install %r" % (apk_path,))
        # set permissions
        self.shell(
            ["pm", "grant", pkg_name, "android.permission.READ_EXTERNAL_STORAGE"]
        )
        self.shell(
            ["pm", "grant", pkg_name, "android.permission.WRITE_EXTERNAL_STORAGE"]
        )
        LOG.debug("installed package %r (%r)", pkg_name, apk_path)
        return pkg_name

    def install_file(self, src, dst, mode=None, context=None):
        """Install file on the device filesystem and set permissions.

        Args:
            src (str): Path to file to install on the device.
            dst (str): Path to location on device to install file.
            mode (int, optional): chmod mode to use.
            context (int, optional): chcon context to use.

        Returns:
            None
        """
        full_dst = str(Path(dst) / Path(src).name)
        self.push(src, full_dst)
        self.shell(["chown", "root.shell", full_dst])
        if mode is not None:
            self.shell(["chmod", mode, full_dst])
        if context is not None:
            self.shell(["chcon", context, full_dst])

    def is_installed(self, package_name):
        """Check if a package is installed on the connected device.

        Args:
            package_name (str): Package name to look up on the device.

        Returns:
            bool: True if the package is installed on the device otherwise False.
        """
        return package_name in self.packages

    def listdir(self, path):
        """List the contents of a directory.

        Args:
            path (str): Directory to list the contents of.

        Returns:
            list: Strings containing names of all items in a directory.
        """
        ret_val, output = self.shell(["ls", "-A", path])
        if ret_val != 0:
            raise IOError("%r does not exist" % (path,))
        return output.splitlines()

    def open_files(self, pid=None, children=False, files=None):
        """Look up open file on the device.

        Args:
            pid (int, optional): Only include files where the process with the matching
                                 PID has an open file handle.
            children (bool, optional): Include file opened by processes with a parent
                                       PID matching pid. pid is required when children
                                       is set to True.
            files (iterable, optional): Limit results to these specific files.

        Yields:
            tuple: PID and path of the open file.
        """
        LOG.debug("open_files(pid=%r, children=%r, files=%r", pid, children, files)
        pids = list()
        if pid is not None:
            pids.append(str(pid))
        if children:
            assert (
                pid is not None
            ), "Cannot request child open files without specifying pid"
            for proc in self._get_procs(pid_children=pid):
                pids.append(str(proc.pid))
        cmd = ["lsof"]
        if pids:
            cmd += ["-p", ",".join(pids)]
        if files:
            cmd.extend(list(files))
        for line in self.shell(cmd)[1].splitlines():
            if line.endswith("Permission denied)"):
                continue
            # I believe we only care about regular files
            if " REG " not in line:
                continue
            try:
                file_info = line.split()
                file_name = file_info[-1]
                if pid is not None and file_info[1] not in pids:
                    continue
                # yield tuple containing pid and filename
                yield (int(file_info[1]), file_name)
            except ValueError:
                pass

    @property
    def packages(self):
        """Look up packages installed on the connected device.

        Args:
            None

        Yields:
            str: Names of the installed packages
        """
        ret_code, output = self.shell(["pm", "list", "packages"])
        if ret_code == 0:
            for line in output.splitlines():
                if line.startswith("package:"):
                    yield line[8:]

    def process_exists(self, pid):
        """Check if a process with a PID matching pid exists on the connected device.

        Args:
            pid (int): Process ID to lookup

        Returns:
            bool: True if the process exists otherwise False
        """
        return any(self._get_procs(pid=pid))

    def pull(self, src, dst):
        """Copy file from connected device.

        Args:
            src (str): Path to file on the device to copy.
            dst (str): Location on the local machine to copy the file to.

        Returns:
            bool: True if successful otherwise False
        """
        LOG.debug("pull(%r, %r)", src, dst)
        return self.call(["pull", src, dst], timeout=180)[0] == 0

    def push(self, src, dst):
        """Copy file to connected device.

        Args:
            src (str): Path to file on the local machine to copy.
            dst (str): Location on the connected device to copy the file to.

        Returns:
            bool: True if successful otherwise False
        """
        LOG.debug("push(%r, %r)", src, dst)
        if not Path(src).exists():
            raise IOError("%r does not exist" % (src,))
        return self.call(["push", src, dst], timeout=180)[0] == 0

    def realpath(self, path):
        """Get canonical path of the specified path.

        Args:
            path (str): Path to file on the connected device.

        Returns:
            str: canonical path of the specified path.
        """
        ret_val, output = self.shell(["realpath", path])
        if ret_val != 0:
            raise IOError("%r does not exist" % (path,))
        return output

    def reboot_device(self, boot_timeout=300, max_attempts=60, retry_delay=1):
        """Reboot the connected device and reconnect.

        Args:
            boot_timeout (int, optional): Seconds to wait for device boot to complete.
            max_attempts (int, optional): Number of attempts to connect to the device.
            retry_delay (int, optional): Seconds to wait between connection attempts.

        Returns:
            None
        """
        was_root = self._root
        self.call(["reboot"])
        self.connected = False
        self.connect(
            as_root=was_root,
            boot_timeout=boot_timeout,
            max_attempts=max_attempts,
            retry_delay=retry_delay,
        )
        assert self.connected, "Device did not connect after reboot"

    def remount(self):
        """Remount system partition as writable.

        Args:
            None

        Returns:
            None
        """
        assert self._root
        code, result = self.call(["remount"])
        if code != 0 or "Permission denied" in result or "remount failed" in result:
            raise ADBSessionError("Remount failed, is '-writable-system' set?")

    def reverse(self, remote, local):
        """

        Args:
            remote (int): Port to bind to on remote device
            local (int): Port to bind to on local machine

        Returns:
            bool: True if successful otherwise False
        """
        assert 1024 < local < 0x10000
        assert 1024 < remote < 0x10000
        cmd = ["reverse", "tcp:%d" % (remote,), "tcp:%d" % (local,)]
        return self.call(cmd, timeout=10)[0] == 0

    def reverse_remove(self, remote=None):
        """

        Args:
            remote (int): Port to unbind from on remote device

        Returns:
            bool: True if successful otherwise False
        """
        cmd = ["reverse"]
        if remote is not None:
            assert 1024 < remote < 0x10000
            cmd.append("--remove")
            cmd.append("tcp:%d" % (remote,))
        else:
            cmd.append("--remove-all")
        return self.call(cmd, timeout=10)[0] == 0

    def sanitizer_options(self, prefix, options):
        """Set sanitizer options.

        Args:
            prefix (str): Prefix to use when setting "<prefix>_OPTIONS".
            options (dict): Option/values to set.

        Returns:
            None
        """
        prefix = prefix.lower()
        assert prefix == "asan", "only ASan is supported atm"
        self.shell(["rm", "-f", "%s.options.gecko" % (prefix,)])
        with TemporaryDirectory(prefix="sanopts_", dir=grz_tmp()) as working_path:
            optfile = Path(working_path) / ("%s.options.gecko" % (prefix,))
            optfile.write_text(":".join("%s=%s" % x for x in options.items()))
            # TODO: use push() instead?
            self.install_file(str(optfile), "/data/local/tmp/", mode="666")

    def set_enforce(self, value):
        """Set SELinux mode.

        Args:
            value (int): 1 to set 'Enforced' or 0 to set 'Permissive'

        Returns:
            None
        """
        assert value in (0, 1)
        if not self._root:
            LOG.warning("set_enforce requires root")
        self.shell(["setenforce", str(value)])

    def shell(self, cmd, timeout=60):
        """Execute an ADB shell command via a non-interactive shell.

        Args:
            cmd (list(str)): List of strings to pass as arguments when calling ADB.
            timeout (float, optional): Seconds to wait for ADB call to complete.

        Returns:
            tuple: The first element is an integer containing the exit code of the
            ADB call and the second is a string containing stderr and stdout.
        """
        assert cmd
        return self.call(["shell", "-T", "-n"] + cmd, timeout=timeout)

    def symbols_path(self, package_name):
        """Lookup path containing symbols for a specified package.

        Args:
            package_name (str): Name of package.

        Returns:
            str: Path containing symbols on the local machine.
        """
        return self.symbols.get(package_name, "")

    def uninstall(self, package):
        """Uninstall package from the connected device.

        Args:
            package (str): Name of package.

        Returns:
            bool: True if successful otherwise False
        """
        if not self.connected:
            LOG.debug("already disconnected")
            return False
        return self.call(["uninstall", package], timeout=60)[0] == 0

    def wait_for_boot(self, timeout=None):
        """Uninstall package from the connected device.

        Args:
            timeout (float or int, optional): Seconds to wait for device to boot.

        Returns:
            bool: True if device booted successfully otherwise False.
        """
        if timeout is not None:
            assert timeout > 0
            deadline = time() + timeout
        else:
            deadline = None
        # first wait for the boot to complete then wait for the boot animation to
        # complete, this will help ensure the device is in a ready state
        anim_chk = ["getprop", "init.svc.bootanim"]
        boot_chk = ["shell", "-T", "-n", "getprop", "sys.boot_completed"]
        attempts = 0
        booted = False
        while True:
            if not booted:
                booted = self.call(boot_chk, device_required=False)[1] == "1"
                attempts += 1
            # we need to verify that boot is complete before checking the animation is
            # stopped because the animation can be in the stopped state early in the
            # boot process
            if booted and self.shell(anim_chk)[1] == "stopped":
                if attempts > 1:
                    # the device was booting so give it additional time
                    LOG.debug("device boot was detected")
                    sleep(5)
                return True
            if deadline and time() >= deadline:
                LOG.debug("wait_for_boot() timeout %r exceeded", timeout)
                break
            LOG.debug("waiting for device to boot")
            sleep(0.5)
        return False
