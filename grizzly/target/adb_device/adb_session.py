# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from collections import namedtuple
import glob
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import time

log = logging.getLogger("adb_session")  # pylint: disable=invalid-name

__all__ = ("ADBCommandError", "ADBCommunicationError", "ADBSession", "ADBSessionError")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


DeviceProcessInfo = namedtuple("DeviceProcessInfo", "memory name pid ppid")


class ADBCommandError(Exception):
    """Raised when an ADB command is invalid or unrecognized"""

class ADBCommunicationError(Exception):
    """Raised when ADB fails to communicate with the device"""

class ADBSessionError(Exception):
    """Raised when an operation fails unexpectedly or session state is invalid"""


class ADBSession(object):
    SANITIZER_LOG_PREFIX = "/sdcard/sanitizer_logs/report.log"

    def __init__(self, ip_addr=None, port=5555):
        self._adb_bin = self._adb_check()
        self._cpu_arch = None  # Android CPU architecture string
        self._debug_adb = int(os.getenv("SHOW_ADB_DEBUG", "0")) != 0  # include ADB output in debug logs
        self._ip_addr = None  # target device IP address
        self._os_version = None  # Android version string
        self._port = None  # ADB listening port
        self._root = False
        self.connected = False
        self.symbols = dict()

        if ip_addr is not None:
            log.debug("creating IP based session")
            try:
                if ip_addr != "localhost":
                    socket.inet_aton(ip_addr)
            except (socket.error, TypeError):
                raise ValueError("Invalid IP Address")
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
        aapt_bin = os.path.expanduser("~/.android/sdk/android-9/aapt")
        if os.path.isfile(aapt_bin):
            log.debug("using recommended aapt from %r", aapt_bin)
            return aapt_bin
        try:
            aapt_bin = subprocess.check_output(("which", "aapt"))
        except subprocess.CalledProcessError:
            raise EnvironmentError("Please install AAPT")
        aapt_bin = aapt_bin.strip().decode("utf-8", errors="ignore")
        # TODO: update this to check aapt version
        log.warning("Using aapt_bin from %r", aapt_bin)
        return aapt_bin

    @classmethod
    def _adb_check(cls):
        """Lookup the path for Android Debug Bridge (ADB).
        An EnvironmentError is raised if the ADB executable is not found.

        Args:
            None

        Returns:
            str: Path to ADB binary.
        """
        adb_bin = os.path.expanduser("~/.android/sdk/platform-tools/adb")
        if os.path.isfile(adb_bin):
            log.debug("using recommended adb from %r", adb_bin)
            return adb_bin
        try:
            adb_bin = subprocess.check_output(("which", "adb"))
        except subprocess.CalledProcessError:
            raise EnvironmentError("Please install ADB")
        adb_bin = adb_bin.strip().decode("utf-8", errors="ignore")
        # TODO: update this to check adb version
        log.warning("Using adb from %r", adb_bin)
        log.warning("You are not using the recommended ADB install!")
        log.warning("Either run the setup script or proceed with caution.")
        time.sleep(5)
        return adb_bin

    @staticmethod
    def _call_adb(cmd, timeout=None):
        """Wrapper to make calls to ADB. Launches ADB in a subprocess and collects output.
        If timeout is specified and elapses the ADB subprocess is terminated.
        This function is only meant to be called directly by ADBSession.call().

        Args:
            cmd (list): List of strings containing full ADB command.
            timeout (float, optional): Number of seconds to wait for ADB command to complete.

        Returns:
            tuple: Exit code and stderr, stdout of ADB call.
        """
        with tempfile.TemporaryFile() as out_fp:
            if timeout is not None:
                assert timeout > 0
                end_time = time.time() + timeout
                adb_proc = subprocess.Popen(cmd, stderr=out_fp, stdout=out_fp)
                while adb_proc.poll() is None:
                    time.sleep(0.05)
                    if time.time() > end_time:
                        log.warning("adb call timeout!")
                        adb_proc.terminate()
                        break
                ret_code = adb_proc.wait()
            else:
                ret_code = subprocess.call(cmd, stderr=out_fp, stdout=out_fp)
            out_fp.seek(0)
            return ret_code, out_fp.read().decode("utf-8", "ignore").strip()

    def _get_procs(self, pid=-1, pid_children=-1):
        """Generator function that yields a DeviceProcessInfo object for each running
        process by default. pid and pid_children can be used to filter the results.

        Args:
            pid (int, optional): Process ID to include in lookup.
            pid_children (int, optional): Used to lookup the children of the given PID.

        Yields:
            DeviceProcessInfo: One instance for each process found in lookup.
        """
        assert isinstance(pid, int)
        assert isinstance(pid_children, int)
        cmd = ["shell", "ps"]
        if pid > -1:
            cmd.append(str(pid))
        if pid_children > -1:
            cmd += ["--ppid", str(pid_children)]
        for line in self.call(cmd)[1].splitlines()[1:]:
            pinfo = self._line_to_info(line)
            if pinfo is not None:
                yield pinfo

    @staticmethod
    def _line_to_info(ps_line):
        """Create a DeviceProcessInfo from the string output of ps.

        Args:
            ps_line (str): Line of output from ps.

        Returns:
            DeviceProcessInfo: new instance.
        """
        try:
            _, pid, ppid, _, memory, _, _, _, name = ps_line.split()
            return DeviceProcessInfo(int(memory), name, int(pid), int(ppid))
        except ValueError:
            log.debug("invalid ps line %r", ps_line)
        return None

    @property
    def airplane_mode(self):
        """Get the current state of airplane mode.

        Args:
            None

        Returns:
            bool: True if airplane mode is enabled otherwise False.
        """
        return self.call(["shell", "settings", "get", "global", "airplane_mode_on"])[1].startswith("1")

    @airplane_mode.setter
    def airplane_mode(self, mode):
        """Enable/disable airplane mode.

        Args:
            mode (bool): True will enable and False will disable airplane mode.

        Returns:
            None
        """
        assert isinstance(mode, bool), "mode must be a bool"
        self.call(["shell", "settings", "put", "global", "airplane_mode_on", "1" if mode else "0"])
        self.call(["shell", "su", "root", "am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE"])

    def call(self, cmd, device_required=True, timeout=None):
        """Call ADB with arguments provided in cmd.

        Args:
            cmd (list): List of strings to pass as arguments when calling ADB.
            device_required (bool, optional): A device must be available for call.
            timeout (float, optional): Amount of time in seconds to wait for ADB cal to complete.

        Returns:
            tuple: The first element is an integer containing the exit code of the
            ADB call and the second is a string containing stderr and stdout.
        """
        assert isinstance(cmd, list) and cmd
        cmd = [self._adb_bin] + cmd
        log.debug("calling: %s", " ".join(cmd))
        if not self.connected and cmd[1] not in ("connect", "devices", "disconnect"):
            raise ADBCommunicationError("ADB session is not connected!")
        ret_code, output = self._call_adb(cmd, timeout=timeout)
        if self._debug_adb:
            log.debug("=== adb start ===\n%s\n=== adb end, returned %d ===", output, ret_code)
        if ret_code != 0:
            if output.startswith("Android Debug Bridge version"):
                raise ADBCommandError("Invalid ADB command '%s'" % (" ".join(cmd[1:]),))
            if output.startswith("adb: usage:"):
                raise ADBCommandError(output.strip())
            if device_required and (output.startswith("error: closed") or
                                    output.startswith("error: device offline") or
                                    output.startswith("error: no devices/emulators found")):
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
        log.debug("clear_logs()")
        return self.call(["logcat", "--clear"], timeout=10)[0] == 0

    def collect_logs(self, pid=None):
        """Collect logs from device with logcat.

        Args:
            pid (int, optional): Process ID to collect logs from. If pid is None
                Logs from all processes will be collected.

        Returns:
            None
        """
        log.debug("collect_logs()")
        if not self.connected:
            log.debug("device not connected cannot collect logs")
            return ""
        cmd = ["logcat", "-d", "*:I"]
        if pid is not None:
            cmd += ["--pid=%d" % (pid,)]
        return self.call(cmd, timeout=10)[1].encode("utf-8", "ignore")

    def connect(self, as_root=True, boot_timeout=300, max_attempts=60, retry_delay=1):
        """Connect to a device via ADB.

        Args:
            as_root (bool, optional): Attempt to enable root. Default is True.
            boot_timeout (int, optional): Number of seconds to wait for device boot to complete.
            max_attempts (int, optional): Number of attempts to make to try to connect to the device.
            retry_delay (int, optional): Number of seconds to wait between connection attempts.

        Returns:
            bool: Returns True if connection was established successfully otherwise False.
        """
        assert isinstance(boot_timeout, int) and boot_timeout > 0
        assert isinstance(max_attempts, int) and max_attempts > 0
        assert isinstance(retry_delay, (int, float)) and retry_delay > 0
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
                    log.debug("connecting to %s", addr)
                    if self.call(["connect", addr])[0] != 0:
                        log.warning("connection attempt #%d failed", attempt)
                        time.sleep(retry_delay)
                        continue
                elif not self.devices():
                    log.warning("No device detected (attempt %d/%d)", attempt, max_attempts)
                    time.sleep(retry_delay)
                    continue
                self.connected = True
            # verify we are connected
            if not self.wait_for_boot(timeout=boot_timeout):
                raise ADBCommunicationError("Timeout (%ds) waiting for device to boot" % (boot_timeout,))
            ret_code, user = self.call(["shell", "whoami"], device_required=False)
            if ret_code != 0 or not user:
                self.connected = False
                if attempt == max_attempts:
                    raise ADBSessionError("Device in a bad state, try disconnect & reboot")
                continue
            self._root = user.splitlines()[-1] == "root"
            # collect CPU and OS info
            if self._os_version is None:
                self._os_version = self.call(["shell", "getprop", "ro.build.version.release"])[1]
            if self._cpu_arch is None:
                self._cpu_arch = self.call(["shell", "getprop", "ro.product.cpu.abi"])[1]
            # check SELinux mode
            if self._root:
                if self.get_enforce():
                    if set_enforce_called:
                        raise ADBSessionError("set_enforce(0) failed!")
                    # set SELinux to run in permissive mode
                    self.set_enforce(0)
                    self.call(["shell", "stop"])
                    self.call(["shell", "start"])
                    # put the device in a known state
                    self.call(["reconnect"])
                    self.connected = False
                    set_enforce_called = True
                    attempt -= 1
                    continue
            if not as_root or self._root:
                log.debug("connected device running Android %s (%s)", self._os_version, self._cpu_arch)
                break
            # enable root
            assert as_root, "Should not be here if root is not requested"
            if self.call(["root"])[0] == 0:
                self.connected = False
                # only skip attempt to call root once
                if not root_called:
                    root_called = True
                    attempt -= 1
                    continue
            else:
                log.warning("Failed root login attempt")
        if self.connected and as_root and not self._root:
            raise ADBSessionError("Could not enable root")
        return self.connected

    @classmethod
    def create(cls, ip_addr=None, port=5555, as_root=True, max_attempts=10):
        """Create a ADBSession and connect to a device via ADB.

        Args:
            ip_addr (str, optional): IP address of device to connect to if using TCP/IP. Defaults to None.
            port (int, optional): Port to use (TCP/IP only). Defaults to 5555.
            as_root (bool, optional): Attempt to enable root. Default is True.
            max_attempt (int, optional): Number of attempts to make to try to connect to the device.

        Returns:
            ADBSession: A connected ADBSession object otherwise None
        """
        session = cls(ip_addr, port)
        if session.connect(as_root=as_root, max_attempts=max_attempts):
            return session
        return None

    def devices(self, all_devices=False, any_state=True):
        """Devices visible to ADB.

        Args:
            all_devices (bool, optional): Don't filter devices using ANDROID_SERIAL environment variable.
            any_state (bool, optional): Include devices in a state other than "device".

        Returns:
            dict: A dictionary keyed on device name containing the state.
        """
        ret_code, entries = self.call(["devices"])
        devices = {}
        if ret_code != 0:
            return devices
        target_device = os.getenv("ANDROID_SERIAL", None) if not all_devices else None
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
            raise ADBSessionError("Multiple devices available and ANDROID_SERIAL not set")
        return devices

    def disconnect(self, unroot=True):
        """Disconnect.

        Args:
            unroot (bool, optional): Attempt to unroot device.

        Returns:
            None
        """
        if not self.connected:
            log.debug("already disconnected")
            return
        if self._root and unroot:
            try:
                if self.call(["unroot"])[0] == 0:
                    self.connected = False
                    self._root = False
                    return
                log.warning("'unroot' failed")
            except ADBCommandError:
                log.warning("'unroot' not support by ADB")
        elif self._ip_addr is not None:
            self.call(["disconnect", ":".join((self._ip_addr, str(self._port)))])
        self.connected = False

    def get_enforce(self):
        """Get SELinux state.

        Args:
            None

        Returns:
            bool: Returns True if "Enforcing" otherwise False.
        """
        status = self.call(["shell", "getenforce"])[1]
        if status == "Enforcing":
            return True
        if status != "Permissive":
            log.warning("Unexpected SELinux state '%r'", status)
        return False

    @classmethod
    def get_package_name(cls, apk_path):
        """Retrieve the package name from an APK.

        Args:
            apk_name (str): APK to retrieve the package name from.

        Returns:
            str: String containing the package name otherwise None.
        """
        if not os.path.isfile(apk_path):
            raise IOError("APK path must point to a file")
        aapt = cls._aapt_check()
        apk_info = subprocess.check_output((aapt, "dump", "badging", apk_path))
        for line in apk_info.splitlines():
            if line.startswith(b"package: name="):
                return line.split()[1][5:].strip(b"'").decode("utf-8", errors="ignore")
        return None

    def get_pid(self, package_name):
        """Retrieve process ID for the process with the specified package name.

        Args:
            apk_name (str): APK to to retrieve the package name from.

        Returns:
            int: PID of the process with the specified package name if it exists otherwise None.
        """
        # TODO: _get_procs() is slow, move to pidof ASAP
        # pidof is not supported pre-Android 6... do we care about <6? if so we could just fall back
        pids = [proc.pid for proc in self._get_procs() if proc.name == package_name]
        if not pids:
            return None
        count = len(pids)
        if count > 1:
            log.debug("get_pid() %d proc(s) found", count)
            # TODO: get procs and use the ppid of the procs the determine the parent
            # for now we are using the lowest pid...
            pids.sort()
        return pids[0]

    def install(self, apk_path):
        """Install APK on the connected device, grant R/W permissions to /sdcard and lookup
        the name of the installed APK.

        Args:
            apk_name (str): APK to install.

        Returns:
            str: Package name of APK that has been installed.
        """
        log.debug("installing %r", apk_path)
        if not os.path.isfile(apk_path):
            raise IOError("APK does not exist %r" % (apk_path,))
        # lookup package name
        pkg_name = self.get_package_name(apk_path)
        if pkg_name is None:
            raise ADBSessionError("Could not find APK package name")
        if self.call(["install", "-g", "-r", apk_path], timeout=120)[0] != 0:
            raise ADBSessionError("Failed to install %r" % (apk_path,))
        log.debug("installed package %r (%r)", pkg_name, apk_path)
        return pkg_name

    def install_asan(self, ndk_path, extra_options=None):
        """Install Address Sanitizer libraries, llvm-sanitizer and create scripts to wrap app_process.
        NOTE: SELinux must be set to permissive for this to work.

        Args:
            ndk_path (str): Path to the NDK that contains ASan libraries.
            extra_options (dict, optional): Extra options to add to ASAN_OPTIONS

        Returns:
            None
        """
        if not os.path.isdir(ndk_path):
            raise IOError("NDK does not exist %r" % (ndk_path,))
        clang_path = os.path.join(
            ndk_path, "toolchains", "llvm", "prebuilt", "linux-x86_64", "lib64",
            "clang", "*", "lib", "linux")
        for cpath in glob.glob(clang_path):
            asan_rt = os.path.join(cpath, "libclang_rt.asan-i686-android.so")
            asan_rt64 = os.path.join(cpath, "libclang_rt.asan-x86_64-android.so")
            if os.path.isfile(asan_rt) and os.path.isfile(asan_rt64):
                break
        else:
            raise IOError("Cannot find libclang_rt.asan-*-android.so")
        self.remount()
        ctx = "u:object_r:zygote_exec:s0"
        if self.call(["shell", "ls", "/system/bin/app_process32.real"]) != 0:
            self.call(["shell", "mv", "/system/bin/app_process32", "/system/bin/app_process32.real"])
            self.call(["shell", "chcon", ctx, "/system/bin/app_process32.real"])
        if self.call(["shell", "ls", "/system/bin/app_process64.real"]) != 0:
            self.call(["shell", "mv", "/system/bin/app_process64", "/system/bin/app_process64.real"])
            self.call(["shell", "chcon", ctx, "/system/bin/app_process64.real"])
        # TODO: should we force overwrite here?
        self.install_file(asan_rt, "/system/lib", "644")
        self.install_file(asan_rt64, "/system/lib64", "644")
        # create sanitizer logging directory
        sanitizer_logs = os.path.dirname(self.SANITIZER_LOG_PREFIX)
        self.call(["shell", "mkdir", "-p", sanitizer_logs])
        self.call(["shell", "chmod", "666", sanitizer_logs])
        # set default ASAN_OPTIONS
        options = [
            "abort_on_error=0",  # avoid tombstones
            "alloc_dealloc_mismatch=0",  # here until ASAN_OPTIONS set in mozglue are set properly
            "allocator_may_return_null=1",  # here until ASAN_OPTIONS set in mozglue are set properly
            "allow_user_segv_handler=1",  # here until ASAN_OPTIONS set in mozglue are set properly
            "detect_leaks=0",  # here until ASAN_OPTIONS set in mozglue are set properly
            "fast_unwind_on_check=1",
            "fast_unwind_on_fatal=1",
            "handle_sigill=1",  # here until ASAN_OPTIONS set in mozglue are set properly
            #"log_path='%s'" % (self.SANITIZER_LOG_PREFIX,),
            "use_sigaltstack=1",
            "start_deactivated=1"]
        if extra_options:
            options += [opt for opt in extra_options.split(":") if opt]
        # create and install app_process wrappers
        tmpd = tempfile.mkdtemp()
        try:
            fname = os.path.join(tmpd, "app_process32")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh\n")
                out_fp.write("ASAN_OPTIONS=%s \\\n" % (":".join(options),))
                #out_fp.write("ASAN_ACTIVATION_OPTIONS=include_if_exists=/sdcard/asan.options \\\n")
                out_fp.write("LD_PRELOAD=/system/lib/libclang_rt.asan-i686-android.so \\\n")
                out_fp.write("exec /system/bin/app_process32.real \"$@\"\n")
            self.install_file(fname, "/system/bin", "755", ctx)
            fname = os.path.join(tmpd, "app_process64")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh\n")
                out_fp.write("ASAN_OPTIONS=%s \\\n" % (":".join(options),))
                #out_fp.write("ASAN_ACTIVATION_OPTIONS=include_if_exists=/sdcard/asan.option \\\n")
                out_fp.write("LD_PRELOAD=/system/lib64/libclang_rt.asan-x86_64-android.so \\\n")
                out_fp.write("exec /system/bin/app_process64.real \"$@\"\n")
            self.install_file(fname, "/system/bin", "755", ctx)
            fname = os.path.join(tmpd, "asanwrapper32")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh\n")
                out_fp.write("LD_PRELOAD=/system/lib/libclang_rt.asan-i686-android.so \\\n")
                out_fp.write("exec \"$@\"\n")
            self.install_file(fname, "/system/bin", "755")
            fname = os.path.join(tmpd, "asanwrapper64")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh\n")
                out_fp.write("LD_PRELOAD=/system/lib64/libclang_rt.asan-x86_64-android.so \\\n")
                out_fp.write("exec \"$@\"\n")
            self.install_file(fname, "/system/bin", "755")
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)
        # install llvm-symbolizer
        llvm_symer = os.path.join(
            ndk_path, "prebuilt", "android-x86_64", "llvm-symbolizer", "llvm-symbolizer")
        self.install_file(llvm_symer, "/system/bin", "755", ctx)
        # restart zygote process
        self.call(["shell", "stop"])
        self.call(["shell", "start"])
        # put the device in a known state
        self.call(["reconnect"])
        self.wait_for_boot()

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
        full_dst = os.path.join(dst, os.path.basename(src))
        self.push(src, full_dst)
        self.call(["shell", "chown", "root.shell", full_dst])
        if mode is not None:
            self.call(["shell", "chmod", mode, full_dst])
        if context is not None:
            self.call(["shell", "chcon", context, full_dst])

    def is_installed(self, package_name):
        """Check if a package is installed on the connected device.

        Args:
            package_name (str): Package name to look up on the device.

        Returns:
            bool: Returns True if the package is installed on the device otherwise False.
        """
        return package_name in self.packages

    def listdir(self, path):
        """List the contents of a directory.

        Args:
            path (str): Directory to list the contents of.

        Returns:
            list: list of strings containing names of all items in a directory.
        """
        log.debug("listdir(%r)", path)
        ret_val, output = self.call(["shell", "ls", "-A", path])
        if ret_val != 0:
            raise IOError("%r does not exist" % (path,))
        return output.splitlines()

    def open_files(self, pid=None, children=False, files=None):
        """Look up open file on the device.

        Args:
            pid (int, optional): Only include files where the process with the matching PID
                has an open file handle.
            children (bool, optional): Include file opened by processes with a parent PID matching pid.
                pid is required when children is set to True
            files (iterable, optional): Limit results to these specific files.

        Yields:
            tuple: The first element is the PID and the second is the path of the open file.
        """
        log.debug("open_files(pid=%r, children=%r, files=%r", pid, children, files)
        pids = list()
        if pid is not None:
            pids.append(str(pid))
        if children:
            assert pid is not None, "Cannot request child open files without specifying pid"
            for proc in self._get_procs(pid_children=pid):
                pids.append(str(proc.pid))
        cmd = ["shell", "lsof"]
        if pids:
            cmd += ["-p", ",".join(pids)]
        if files:
            cmd.extend(list(files))
        for line in self.call(cmd)[1].splitlines():
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
        ret_code, output = self.call(["shell", "pm", "list", "packages"])
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
        log.debug("pull(%r, %r)", src, dst)
        return self.call(["pull", src, dst])[0] == 0

    def push(self, src, dst):
        """Copy file to connected device.

        Args:
            src (str): Path to file on the local machine to copy.
            dst (str): Location on the connected device to copy the file to.

        Returns:
            bool: True if successful otherwise False
        """
        log.debug("push(%r, %r)", src, dst)
        if not os.path.exists(src):
            raise IOError("%r does not exist" % (src,))
        return self.call(["push", src, dst])[0] == 0

    def realpath(self, path):
        """Get canonical path of the specified path.

        Args:
            path (str): Path to file on the connected device.

        Returns:
            str: canonical path of the specified path.
        """
        log.debug("realpath(%r)", path)
        ret_val, output = self.call(["shell", "realpath", path])
        if ret_val != 0:
            raise IOError("%r does not exist" % (path,))
        return output.strip()

    def reboot_device(self, boot_timeout=300, max_attempts=60, retry_delay=1):
        """Reboot the connected device and reconnect.

        Args:
            boot_timeout (int, optional): Number of seconds to wait for device boot to complete.
            max_attempts (int, optional): Number of attempts to make to try to connect to the device.
            retry_delay (int, optional): Number of seconds to wait between connection attempts.

        Returns:
            None
        """
        was_root = self._root
        log.debug("calling reboot...")
        self.call(["reboot"])
        self.connected = False
        self.connect(
            as_root=was_root,
            boot_timeout=boot_timeout,
            max_attempts=max_attempts,
            retry_delay=retry_delay)
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
        assert isinstance(local, int) and 1024 < local < 0x10000
        assert isinstance(remote, int) and 1024 < remote < 0x10000
        return self.call(["reverse", "tcp:%d" % (remote,), "tcp:%d" % (local,)])[0] == 0

    def reverse_remove(self, remote=None):
        """

        Args:
            remote (int): Port to unbind from on remote device

        Returns:
            bool: True if successful otherwise False
        """
        cmd = ["reverse"]
        if remote is not None:
            assert isinstance(remote, int) and 1024 < remote < 0x10000
            cmd.append("--remove")
            cmd.append("tcp:%d" % (remote,))
        else:
            cmd.append("--remove-all")
        return self.call(cmd)[0] == 0

    def set_enforce(self, value):
        """Set SELinux mode.

        Args:
            value (int): 1 to set 'Enforced' or 0 to set 'Permissive'

        Returns:
            None
        """
        assert value in (0, 1)
        if not self._root:
            log.warning("set_enforce requires root")
        self.call(["shell", "setenforce", str(value)])

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
            log.debug("already disconnected")
            return False
        return self.call(["uninstall", package], timeout=60)[0] == 0

    def wait_for_boot(self, timeout=None):
        """Uninstall package from the connected device.

        Args:
            timeout (float or int, optional): Number of seconds to wait for device to boot.

        Returns:
            bool: True if device booted successfully otherwise False.
        """
        if timeout is not None:
            assert isinstance(timeout, (int, float)) and timeout > 0
            deadline = time.time() + timeout
        else:
            deadline = None
        # first wait for the boot to complete then wait for the boot animation to complete
        # this will help ensure the device is in a ready state
        anim_chk = ["shell", "getprop", "init.svc.bootanim"]
        boot_chk = ["shell", "getprop", "sys.boot_completed"]
        attempts = 0
        booted = False
        while True:
            if not booted:
                booted = self.call(boot_chk, device_required=False)[1] == "1"
                attempts += 1
            # we need to verify that boot is complete before checking the animation is stopped because
            # the animation can be in the stopped state early in the boot process
            if booted and self.call(anim_chk)[1] == "stopped":
                if attempts > 1:
                    # the device was booting so give it additional time
                    log.debug("device was boot was detected")
                    time.sleep(5)
                return True
            if deadline and time.time() >= deadline:
                log.debug("wait_for_boot() timeout %r exceeded", timeout)
                break
            log.debug("waiting for device to boot")
            time.sleep(0.5)
        return False
