import logging
import os
import socket
import subprocess
import tempfile
import time


log = logging.getLogger("adb_session")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class DeviceProcessInfo(object):
    def __init__(self, memory, name, pid, ppid):
        self.memory = memory
        self.name = name
        self.pid = pid
        self.ppid = ppid

    @classmethod
    def from_ps_line(cls, line):
        try:
            _, pid, ppid, _, memory, _, _, _, name = line.split()
        except ValueError:
            log.debug("invalid ps line %r", line)
            return None
        try:
            return cls(int(memory), name, int(pid), int(ppid))
        except ValueError:
            log.debug("invalid ps line values")
            return None


class ADBCommandError(Exception):
    pass

class ADBSessionError(Exception):
    pass

class ADBNoDevice(ADBSessionError):
    pass


class ADBSession(object):
    def __init__(self, ip_addr=None, port=5555):
        self.connected = False
        self.symbols = dict()
        self._adb_bin = self._adb_check()
        self._cpu_arch = None  # Android CPU architecture string
        self._ip_addr = None  # target device IP address
        self._os_version = None  # Android version string
        self._port = None  # ADB listening port
        self._root = False

        log.debug("creating IP based session: %r", ip_addr is not None)
        if ip_addr is not None:
            try:
                if ip_addr != "localhost":
                    socket.inet_aton(ip_addr)
            except (socket.error, TypeError):
                raise ValueError("IP Address is invalid")
            self._ip_addr = ip_addr
            if not isinstance(port, int) or not 0x10000 > port > 1024:
                raise ValueError("Port must be valid integer between 1025 and 65535")
            self._port = port

    @classmethod
    def _aapt_check(cls):
        aapt_bin = os.path.expanduser("~/.android/sdk/android-9/aapt")
        if os.path.isfile(aapt_bin):
            log.debug("using recommended aapt from %r", aapt_bin)
            return aapt_bin
        try:
            aapt_bin = subprocess.check_output(["which", "aapt"])
        except subprocess.CalledProcessError:
            raise EnvironmentError("Please install AAPT")
        aapt_bin = aapt_bin.strip().decode("utf-8", errors="ignore")
        # TODO: update this to check aapt version
        log.warning("Using aapt_bin from %r", aapt_bin)
        return aapt_bin

    @classmethod
    def _adb_check(cls):
        adb_bin = os.path.expanduser("~/.android/sdk/platform-tools/adb")
        if os.path.isfile(adb_bin):
            log.debug("using recommended adb from %r", adb_bin)
            return adb_bin
        try:
            adb_bin = subprocess.check_output(["which", "adb"])
        except subprocess.CalledProcessError:
            raise EnvironmentError("Please install ADB")
        adb_bin = adb_bin.strip().decode("utf-8", errors="ignore")
        # TODO: update this to check adb version
        log.warning("Using adb from %r", adb_bin)
        log.warning("You are not using the recommended ADB install!")
        log.warning("Either run the setup script or proceed with caution.")
        time.sleep(5)
        return adb_bin

    @classmethod
    def create(cls, ip_addr=None, port=5555, as_root=True, max_attempts=10):
        session = cls(ip_addr, port)
        if session.connect(as_root=as_root, max_attempts=max_attempts):
            return session
        return None

    @staticmethod
    def _call_adb(cmd, timeout=None):
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

    def call(self, cmd, require_device=True, timeout=None):
        assert isinstance(cmd, list) and cmd
        cmd = [self._adb_bin] + cmd
        log.debug("calling: %s", " ".join(cmd))
        if not self.connected and cmd[1] not in ("connect", "devices", "disconnect"):
            raise ADBSessionError("ADB session is not connected!")
        ret_code, output = self._call_adb(cmd, timeout=timeout)
        log.debug("=== adb start ===\n%s\n=== adb end, returned %d ===", output, ret_code)
        if ret_code != 0:
            if output.startswith("Android Debug Bridge version"):
                raise ADBCommandError("Invalid ADB command '%s'" % " ".join(cmd[1:]))
            if output.startswith("adb: usage:"):
                raise ADBCommandError(output.strip())
            if require_device and (output.startswith("error: closed") or
                                   output.startswith("error: device offline") or
                                   output.startswith("error: no devices/emulators found")):
                self.connected = False
                raise ADBNoDevice("No device detected!")
        return (ret_code, output)

    def clear_logs(self):
        log.debug("clear_logs()")
        return self.call(["logcat", "--clear"], timeout=10)[0] == 0

    def connect(self, as_root=True, boot_timeout=300, max_attempts=10, retry_delay=1):
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
                    addr = ":".join([self._ip_addr, str(self._port)])
                    log.debug("connecting to %s", addr)
                    if self.call(["connect", addr])[0] != 0:
                        log.warning("connection attempt #%d failed", attempt)
                        time.sleep(retry_delay)
                        continue
                elif not self._devices_available(self.call(["devices"])[1]):
                    log.warning("No device detected (attempt %d/%d)", attempt, max_attempts)
                    time.sleep(retry_delay)
                    continue
                self.connected = True

            # verify we are connected
            if not self.wait_for_boot(timeout=boot_timeout):
                raise ADBSessionError("Timeout (%ds) waiting for device boot to complete" % boot_timeout)
            ret_code, user = self.call(["shell", "whoami"], require_device=False)
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
                    set_enforce_called = True
                    self.connected = False
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

    def collect_logs(self, pid=None):
        log.debug("collect_logs()")
        if not self.connected:
            log.debug("device not connected cannot collect logs")
            return ""
        cmd = ["logcat", "-d", "*:I"]
        if pid is not None:
            cmd += ["--pid=%d" % pid]
        return self.call(cmd, timeout=10)[1].encode("utf-8", "ignore")

    @staticmethod
    def _devices_available(adb_output):
        entries = adb_output.strip().splitlines()
        if len(entries) < 2:
            return False
        return entries[-1].endswith("device")

    def disconnect(self, unroot=True):
        if not self.connected:
            log.debug("already disconnected")
            return True
        if self._root and unroot:
            try:
                if self.call(["unroot"])[0] == 0:
                    self.connected = False
                    self._root = False
                    return True
                log.warning("'unroot' failed")
            except ADBCommandError:
                log.warning("'unroot' not support by ADB")
        elif self._ip_addr is not None:
            self.call(["disconnect", ":".join([self._ip_addr, str(self._port)])])
        self.connected = False
        return True

    def listdir(self, path):
        log.debug("listdir(%r)", path)
        ret_val, output = self.call(["shell", "ls", "-A", path])
        if ret_val != 0:
            raise IOError("%r does not exist" % path)
        return output.splitlines()

    def realpath(self, path):
        log.debug("realpath(%r)", path)
        ret_val, output = self.call(["shell", "realpath", path])
        if ret_val != 0:
            raise IOError("%r does not exist" % path)
        return output.strip()

    def reverse(self, remote, local):
        # remote->device, local->desktop
        assert isinstance(local, int) and 1024 < local < 0x10000
        assert isinstance(remote, int) and 1024 < remote < 0x10000
        return self.call(["reverse", "tcp:%d" % remote, "tcp:%d" % local])[0] == 0

    def reverse_remove(self, remote=None):
        # remote->device
        cmd = ["reverse"]
        if remote is not None:
            assert isinstance(remote, int) and 1024 < remote < 0x10000
            cmd.append("--remove")
            cmd.append("tcp:%d" % remote)
        else:
            cmd.append("--remove-all")
        return self.call(cmd)[0] == 0

    def uninstall(self, package):
        if not self.connected:
            log.debug("already disconnected")
            return False
        return self.call(["uninstall", package], timeout=60)[0] == 0

    def install(self, apk_path):
        log.debug("installing %r", apk_path)
        if not os.path.isfile(apk_path):
            raise IOError("APK does not exist %r" % apk_path)
        # check if package is installed
        if self.call(["install", "-r", apk_path], timeout=120)[0] != 0:
            raise ADBSessionError("Failed to install %r" % apk_path)
        # unpack and lookup package name
        package_name = self.get_package_name(apk_path)
        # set permissions
        self.call(["shell", "pm", "grant", package_name, "android.permission.READ_EXTERNAL_STORAGE"])
        self.call(["shell", "pm", "grant", package_name, "android.permission.WRITE_EXTERNAL_STORAGE"])
        log.debug("installed package %r (%r)", package_name, apk_path)
        return package_name

    # This is no longer required and I *think* it can be removed
    #def install_file(self, src, dst, mode=None, context=None):
    #    basename = os.path.basename(src)
    #    full_dst = os.path.join(dst, basename)
    #    self.push(src, full_dst)
    #    self.call(["shell", "chown", "root.shell", full_dst])
    #    if mode is not None:
    #        self.call(["shell", "chmod", mode, full_dst])
    #    if context is not None:
    #        self.call(["shell", "chcon", context, full_dst])

    def get_enforce(self):
        status = self.call(["shell", "getenforce"])[1]
        if status == "Enforcing":
            return True
        if status != "Permissive":
            log.warning("Unexpected SELinux state '%r'", status)
        return False

    @classmethod
    def get_package_name(cls, apk_path):
        aapt = cls._aapt_check()
        apk_info = subprocess.check_output([aapt, "dump", "badging", apk_path])
        for line in apk_info.splitlines():
            if line.startswith(b"package: name="):
                package_name = line.split()[1][5:].strip(b"'").decode("utf-8", errors="ignore")
                break
        else:
            raise RuntimeError("Could not find APK package name")
        return package_name

    def get_packages(self):
        # TODO: should this be by pid or package?
        cmd = ["shell", "pm", "list", "packages"]
        return [line[8:] for line in self.call(cmd)[1].splitlines() if line.startswith("package:")]

    def get_open_files(self, pid=None, children=False, files=None):
        log.debug("get_open_files(pid=%r, children=%r, files=%r", pid, children, files)
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
        open_files = list()
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
                # add tuple containing pid and filename
                open_files.append((int(file_info[1]), file_name))
            except ValueError:
                pass

        return open_files

    def get_pid(self, package_name):
        # NOTE: pidof is not supported pre-Android 6
        procs = self._get_procs()
        pids = [proc.pid for proc in procs if proc.name == package_name]
        if not pids:
            return None
        count = len(pids)
        if count > 1:
            log.debug("get_pid() %d proc(s) found", count)
            # TODO: use procs and use the ppid of the procs the determine the parent
            pids.sort()
        return int(pids[0])

    def process_exists(self, pid):
        return bool(self._get_procs(pid=pid))

    def _get_procs(self, pid=None, pid_children=None):
        # default list all procs
        cmd = ["shell", "ps"]
        if pid is not None:
            cmd.append(str(pid))
        if pid_children is not None:
            cmd += ["--ppid", str(pid_children)]
        procs = list()
        for line in self.call(cmd)[1].splitlines()[1:]:
            pinfo = DeviceProcessInfo.from_ps_line(line)
            if pinfo is not None:
                procs.append(pinfo)
        return procs

    def is_installed(self, package_name):
        return package_name in self.get_packages()

    def pull(self, src, dst):
        log.debug("pull(%r, %r)", src, dst)
        return self.call(["pull", src, dst])[0] == 0

    def push(self, src, dst):
        log.debug("push(%r, %r)", src, dst)
        if not os.path.exists(src):
            raise IOError("%r does not exist" % src)
        return self.call(["push", src, dst])[0] == 0

    def symbols_path(self, package_name):
        return self.symbols.get(package_name, "")

    def set_airplane_mode(self, mode=True):
        self.call(["shell", "settings", "put", "global", "airplane_mode_on", "1" if mode else "0"])
        self.call(["shell", "su", "root", "am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE"])

    def set_enforce(self, value):
        assert value in (0, 1)
        if not self._root:
            log.warning("set_enforce requires root")
        self.call(["shell", "setenforce", str(value)])

    def wait_for_boot(self, timeout=None):
        if timeout is not None:
            assert isinstance(timeout, (int, float)) and timeout > 0
            deadline = time.time() + timeout
        else:
            deadline = None
        attempts = 0
        booted = False
        # first wait for the boot to complete then wait for the boot animation to complete
        # this will help ensure the device is in a ready state
        while True:
            if not booted:
                booted = self.call(["shell", "getprop", "sys.boot_completed"], require_device=False)[1] == "1"
                attempts += 1
            # we need to verify that boot is complete before checking the animation is stopped because
            # the animation can be in the stopped state early in the boot process
            if booted and self.call(["shell", "getprop", "init.svc.bootanim"])[1] == "stopped":
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
