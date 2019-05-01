import argparse
import glob
import logging
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from ffpuppet.helpers import append_prefs, Bootstrapper, create_profile
from ffpuppet.minidump_parser import process_minidumps
from ffpuppet.puppet_logger import PuppetLogger

log = logging.getLogger("adb_device")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


# TODO:
# - Add ability to collect ASan logs


class DeviceProcess(object):
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


class ADBCommandError(RuntimeError):
    pass

class ADBSessionError(RuntimeError):
    pass

class ADBLaunchError(ADBSessionError):
    pass

class ADBNoDevice(ADBSessionError):
    pass


class ADBSession(object):
    BIN_AAPT = None
    BIN_ADB = None

    def __init__(self, ip_addr=None, port=5555):
        self.connected = False
        self.symbols = dict()
        self._root = False
        self._ip_addr = None  # target device IP address
        self._port = None  # ADB listening port

        log.debug("creating IP based session: %r", ip_addr is not None)
        if ip_addr is not None:
            try:
                if ip_addr != "localhost":
                    socket.inet_aton(ip_addr)
            except (socket.error, TypeError):
                raise ValueError("IP Address is invalid")
            self._ip_addr = ip_addr
            if not isinstance(port, int) or not (port > 1024 and port < 0x10000):
                raise ValueError("Port must be valid integer between 1025 and 65535")
            self._port = port

        suggested_adb = os.path.expanduser("~/.android/sdk/platform-tools/adb")
        if self.BIN_ADB is None:
            if os.path.isfile(suggested_adb):
                self.BIN_ADB = suggested_adb
            else:
                try:
                    self.BIN_ADB = subprocess.check_output(["which", "adb"]).strip()
                except subprocess.CalledProcessError:
                    raise EnvironmentError("Please install ADB")
            # TODO: update this to check adb version
            if os.path.realpath(self.BIN_ADB) != os.path.realpath(suggested_adb):
                log.warning("You are not using the recommended ADB install!")
                log.warning("Either run the setup script or proceed with caution.")
                time.sleep(5)


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
        cmd = [self.BIN_ADB] + cmd
        log.debug("calling: %s", " ".join(cmd))
        if not self.connected and cmd[1] not in ("connect", "devices", "disconnect"):
            raise ADBSessionError("ADB session is not connected!")
        ret_code, output = self._call_adb(cmd, timeout=timeout)
        log.debug("=== adb start ===\n%s\n=== adb end, returned %d ===", output, ret_code)
        if ret_code != 0:
            if output.startswith("Android Debug Bridge version"):
                raise ADBCommandError("Invalid ADB command '%s'" % " ".join(cmd[1:]))
            elif output.startswith("adb: usage:"):
                raise ADBCommandError(output.strip())
            elif require_device and (output.startswith("error: closed") or
                                     output.startswith("error: device offline") or
                                     output.startswith("error: no devices/emulators found")):
                self.connected = False
                raise ADBNoDevice("No device detected!")
        return (ret_code, output)


    def clear_logs(self):
        log.debug("clear_logs()")
        return self.call(["logcat", "--clear"], timeout=10)[0] == 0


    def connect(self, as_root=True, max_attempts=10):
        max_attempts = max(1, max_attempts)
        attempt = 0
        root_called = False
        while attempt < max_attempts:
            attempt += 1
            if not self.connected and self._ip_addr is not None:
                addr = ":".join([self._ip_addr, str(self._port)])
                log.debug("connecting to %s", addr)
                if self.call(["connect", addr])[0] != 0:
                    log.warning("connection attempt #%d failed", attempt)
                    time.sleep(0.25)
                    continue
            elif not self._devices_available(self.call(["devices"])[1]):
                log.warning("No device detected (attempt %d/%d)", attempt, max_attempts)
                time.sleep(1)
                continue
            self.connected = True

            # verify we are connected
            ret_code, user = self.call(["shell", "whoami"], require_device=False)
            if (ret_code != 0 or not user) and attempt < max_attempts:
                time.sleep(0.25)
                continue

            if ret_code != 0 or not user:
                raise ADBSessionError("Device in a bad state, try disconnect & reboot")
            user = user.splitlines()[-1]
            if user == "root":
                self._root = True

            if not as_root or self._root:
                break  # connected

            # enable root
            assert as_root, "Should not be here if root is not requested"
            if self.call(["root"])[0] == 0:
                self.connected = False
                if not root_called:
                    root_called = True
                    attempt -= 1  # remove attempt used to call root
                    continue

            time.sleep(0.25)  # wait for adbd to restart on device

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
        assert isinstance(local, int) and local > 1024 and local < 0x10000
        assert isinstance(remote, int) and remote > 1024 and remote < 0x10000
        return self.call(["reverse", "tcp:%d" % remote, "tcp:%d" % local])[0] == 0


    def reverse_remove(self, remote=None):
        # remote->device
        cmd = ["reverse"]
        if remote is not None:
            assert isinstance(remote, int) and remote > 1024 and remote < 0x10000
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


    def install_asan(self, ndk_base, asan_options=None):
        if not os.path.isdir(ndk_base):
            raise IOError("NDK does not exist %r" % ndk_base)
        self.call(["remount"])

        clang_path = os.path.join(
            ndk_base, "toolchains", "llvm", "prebuilt", "linux-x86_64", "lib64",
            "clang", "*", "lib", "linux")
        for cpath in glob.glob(clang_path):
            asan_rt = os.path.join(cpath, "libclang_rt.asan-i686-android.so")
            asan_rt64 = os.path.join(cpath, "libclang_rt.asan-x86_64-android.so")
            if os.path.isfile(asan_rt) and os.path.isfile(asan_rt64):
                break
        else:
            raise IOError("Cannot find libclang_rt.asan-*-android.so")

        ctx = "u:object_r:zygote_exec:s0"
        self.call(["shell", "setenforce", "0"])

        self.call(["shell", "mv", "/system/bin/app_process32.real", "/system/bin/app_process32"])
        self.call(["shell", "mv", "/system/bin/app_process32", "/system/bin/app_process32.real"])
        self.call(["shell", "chcon", ctx, "/system/bin/app_process32.real"])
        self.call(["shell", "mv", "/system/bin/app_process64.real", "/system/bin/app_process64"])
        self.call(["shell", "mv", "/system/bin/app_process64", "/system/bin/app_process64.real"])
        self.call(["shell", "chcon", ctx, "/system/bin/app_process64.real"])

        self.install_file(asan_rt, "/system/lib", "644")
        self.install_file(asan_rt64, "/system/lib64", "644")

        addition_options = [
            "allow_user_segv_handler=1",
            "detect_container_overflow=0",
            "malloc_context_size=0",
            "start_deactivated=1"]
        if asan_options:
            existing_opts = [opt for opt in asan_options.split(":") if opt]
        else:
            existing_opts = []
        asan_options = ":".join(existing_opts + addition_options)

        tmpd = tempfile.mkdtemp()
        try:
            fname = os.path.join(tmpd, "app_process32")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh-from-zygote\n")
                out_fp.write("ASAN_OPTIONS=%s \\\n" % asan_options)
                out_fp.write("ASAN_ACTIVATION_OPTIONS=include_if_exists=/data/local/tmp/asan.options.%b \\\n")
                out_fp.write("LD_PRELOAD=symlink-to-libclang_rt.asan \\\n")
                out_fp.write("exec /system/bin/app_process32.real \"$@\"\n")
            self.install_file(fname, "/system/bin", "755", ctx)

            fname = os.path.join(tmpd, "app_process64")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh-from-zygote\n")
                out_fp.write("ASAN_OPTIONS=%s \\\n" % asan_options)
                out_fp.write("ASAN_ACTIVATION_OPTIONS=include_if_exists=/data/local/tmp/asan.options.%b \\\n")
                out_fp.write("LD_PRELOAD=symlink-to-libclang_rt.asan \\\n")
                out_fp.write("exec /system/bin/app_process64.real \"$@\"\n")
            self.install_file(fname, "/system/bin", "755", ctx)

            fname = os.path.join(tmpd, "asanwrapper")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh\n")
                out_fp.write("LD_PRELOAD=symlink-to-libclang_rt.asan \\\n")
                out_fp.write("exec \"$@\"\n")
            self.install_file(fname, "/system/bin", "755")

            fname = os.path.join(tmpd, "asanwrapper64")
            with open(fname, "w") as out_fp:
                out_fp.write("#!/system/bin/sh\n")
                out_fp.write("LD_PRELOAD=symlink-to-libclang_rt.asan \\\n")
                out_fp.write("exec \"$@\"\n")
            self.install_file(fname, "/system/bin", "755")
        finally:
            shutil.rmtree(tmpd, ignore_errors=True)

        llvm_symer = os.path.join(
            ndk_base, "toolchains", "llvm", "prebuilt", "android-x86_64",
            "llvm-symbolizer", "llvm-symbolizer")
        self.install_file(llvm_symer, "/system/bin", "755", ctx)

        # set-up asan symlinks
        self.call(["shell", "ln", "-s", "/system/lib/libclang_rt.asan-i686-android.so", "/system/lib/symlink-to-libclang_rt.asan"])
        self.call(["shell", "ln", "-s", "/system/lib64/libclang_rt.asan-x86_64-android.so", "/system/lib64/symlink-to-libclang_rt.asan"])

        self.call(["shell", "cp", "/system/bin/sh", "/system/bin/sh-from-zygote"])
        self.call(["shell", "chcon", ctx, "/system/bin/sh-from-zygote"])

        self.call(["shell", "setenforce", "1"])
        self.call(["shell", "stop"])
        self.call(["shell", "start"])


    def install_file(self, src, dst, mode=None, context=None):
        basename = os.path.basename(src)
        full_dst = os.path.join(dst, basename)
        self.push(src, full_dst)
        self.call(["shell", "chown", "root.shell", full_dst])
        if mode is not None:
            self.call(["shell", "chmod", mode, full_dst])
        if context is not None:
            self.call(["shell", "chcon", context, full_dst])


    @staticmethod
    def get_package_name(apk_path):
        # unpack and lookup package name
        aapt = ADBSession.BIN_AAPT
        if aapt is None:
            aapt = os.path.expanduser("~/.android/sdk/android-9/aapt")
            if not os.path.isfile(aapt):
                # fall back to system version
                aapt = subprocess.check_output(["which", "aapt"]).strip()
        apk_info = subprocess.check_output([aapt, "dump", "badging", apk_path])
        for line in apk_info.splitlines():
            if line.startswith("package: name="):
                package_name = line.split()[1][5:].strip("'")
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
        return True if self._get_procs(pid=pid) else False


    def _get_procs(self, pid=None, pid_children=None):
        # default list all procs
        cmd = ["shell", "ps"]
        if pid is not None:
            cmd.append(str(pid))
        if pid_children is not None:
            cmd += ["--ppid", str(pid_children)]
        procs = list()
        for line in self.call(cmd)[1].splitlines()[1:]:
            proc = DeviceProcess.from_ps_line(line)
            if proc is not None:
                procs.append(proc)
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
        cmd = ["shell", "settings", "put", "global", "airplane_mode_on"]
        cmd += ["1" if mode else "0"]
        self.call(cmd)
        cmd = ["shell", "su", "root", "am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE"]
        self.call(cmd)



class ADBProcess(object):
    # TODO: reason codes match FFPuppet
    RC_ALERT = "ALERT"  # target crashed/aborted/triggered an assertion failure etc...
    RC_CLOSED = "CLOSED"  # target was closed by call to FFPuppet close()
    RC_EXITED = "EXITED"  # target exited
    #RC_WORKER = "WORKER"  # target was closed by worker thread
    # TODO: 
    #  def save_logs(self, *args, **kwargs):
    #  def clone_log(self, log_id, offset=0):
    #  def log_data(self, log_id, offset=0):
    #  def log_length(self, log_id):... likely not going to happen because of overhead
    def __init__(self, package_name, session, use_profile=None):
        assert isinstance(session, ADBSession), "Expecting ADBSession"
        if not session.is_installed(package_name):
            raise ADBSessionError("Package %r not installed" % package_name)
        self._launches = 0  # number of successful browser launches
        self._package = package_name  # package to use as target process
        self._pid = None  # pid of current target process
        self._profile_template = use_profile  # profile that is used as a template
        self._session = session  # ADB session with device
        self._working_path = "/sdcard/ADBProc_%08X" % random.getrandbits(32)
        self.logs = None
        self.profile = None
        self.reason = self.RC_CLOSED


    def cleanup(self):
        if self._launches < 0:
            log.debug("clean_up() call ignored")
            return
        if self.reason is None:
            self.close()
        self._remove_logs()
        # negative 'self._launches' indicates clean_up() has been called
        self._launches = -1


    def clone_log(self):
        # TODO: dump logs for all browser processes
        if self._session is None:
            # TODO: better error?
            return "ADB session does not exist!"
        return self._session.collect_logs(pid=self._pid)


    def close(self):
        assert self._launches > -1, "clean_up() has been called"
        if self.reason is not None:
            log.debug("already closed!")
            return
        try:
            if self._session is not None:
                crash_reports = self.find_crashreports()
                # set reason code
                if crash_reports:
                    self.reason = self.RC_ALERT
                    self.wait_on_files(crash_reports)
                elif self.is_running():
                    self.reason = self.RC_CLOSED
                else:
                    self.reason = self.RC_EXITED
                self._terminate()
                self.wait()
                self._process_logs(crash_reports)
                self._session.call(["shell", "rm", "-rf", self._working_path])
        except ADBSessionError:
            log.warning("No device detected while closing process")
        self._pid = None
        self.profile = None
        if self.reason is None:
            self.reason = self.RC_CLOSED


    def find_crashreports(self):
        reports = list()
        # TODO: Add ASan support
        if self.profile:
            # check for minidumps
            md_path = os.path.join(self.profile, "minidumps")
            try:
                contents = self._session.listdir(md_path)
                md_path
                for fname in contents:
                    if ".dmp" in fname or ".extra" in fname:
                        reports.append(os.path.join(md_path, fname))
            except IOError:
                log.debug("%s does not exist", md_path)

        return reports


    def is_healthy(self):
        if not self.is_running():
            return False
        return not self.find_crashreports()


    def is_running(self):
        assert self._session, "Device not connected"
        assert self._package, "Package not specified"
        if self._pid is None or self.reason is not None:
            return False
        return self._session.process_exists(self._pid)


    def launch(self, url, env_mod=None, extension=None, prefs_js=None):
        log.debug("launching %r", url)
        assert self._launches > -1, "clean_up() has been called"
        assert self._session, "Device not connected"
        assert self._package, "Package not specified"
        assert self._pid is None, "Process is already running"
        assert self.reason is not None, "Process is already running"

        self._session.clear_logs()
        self._remove_logs()
        self.reason = None
        local_profile = create_profile(
            extension=extension,
            prefs_js=prefs_js,
            template=self._profile_template)

        bootstrapper = Bootstrapper(poll_wait=0.5)
        try:
            try:
                prefs = {
                    "capability.policy.policynames": "'localfilelinks'",
                    "capability.policy.localfilelinks.sites": "'%s'" % bootstrapper.location,
                    "capability.policy.localfilelinks.checkloaduri.enabled": "'allAccess'"}
                append_prefs(local_profile, prefs)
                self.profile = "/".join([self._working_path, os.path.basename(local_profile)])
                if os.listdir(local_profile):
                    if not self._session.push(local_profile, self.profile):
                        raise ADBLaunchError("Could not upload %r" % local_profile)
                else:
                    log.debug("creating empty profile on device: %s", self.profile)
                    self._session.call(["shell", "mkdir", "-p", self.profile])
            finally:
                if os.path.exists(local_profile):
                    shutil.rmtree(local_profile) # TODO: temporary

            # TODO: Is call needed and if so should it happen somewhere else?
            # disable selinux
            self._session.call(["shell", "setenforce", "0"])
            if not self._session.reverse(bootstrapper.port, bootstrapper.port):
                raise ADBLaunchError("Could not reverse port: %d" % bootstrapper.port)
            cmd = [
                "shell", "am", "start", "-W", "-n",
                "/".join([self._package, "org.mozilla.gecko.BrowserApp"]),
                "-a", "android.intent.action.VIEW", "-d", bootstrapper.location,
                "--es", "args", "-profile\\ %s" % self.profile]

            env_mod = dict(env_mod or {})
            env_mod.setdefault("MOZ_SKIA_DISABLE_ASSERTS", "1")
            for var_num, (var_name, var_val) in enumerate(env_mod.items()):
                if var_val is None:
                    continue
                cmd.append("--es")
                cmd.append("env%d" % var_num)
                cmd.append("%s=%s" % (var_name, var_val))

            if "Status: ok" not in self._session.call(cmd)[1].splitlines():
                raise ADBLaunchError("Could not launch %r" % self._package)
            self._pid = self._session.get_pid(self._package)
            bootstrapper.wait(self.is_healthy, url=url)
        finally:
            self._session.reverse_remove(bootstrapper.port)
            bootstrapper.close()
        self._launches += 1

        return self._pid is not None


    @property
    def launches(self):
        """
        Get the number of successful launches

        @rtype: int
        @return: successful launch count
        """

        assert self._launches > -1, "clean_up() has been called"
        return self._launches


    def _process_logs(self, crash_reports):
        assert self.logs is None
        self.logs = tempfile.mkdtemp(prefix="adb_logs_")
        unprocessed = os.path.join(self.logs, "unprocessed")
        os.mkdir(unprocessed)

        with open(os.path.join(self.logs, "log_logcat.txt"), "wb") as log_fp:
            # TODO: should this filter by pid or not?
            log_fp.write(self._session.collect_logs())
            #log_fp.write(self._session.collect_logs(pid=self._pid))

        if not crash_reports:
            return

        # copy crash logs from the device
        for fname in crash_reports:
            self._session.pull(fname, unprocessed)

        logger = PuppetLogger()
        try:
            syms_path = self._session.symbols_path(self._package)
            process_minidumps(unprocessed, syms_path, logger.add_log)
            logger.close()
            logger.save_logs(self.logs)
        finally:
            logger.clean_up()


    def _remove_logs(self):
        if self.logs is not None and os.path.isdir(self.logs):
            shutil.rmtree(self.logs)
            self.logs = None


    @staticmethod
    def _split_logcat(log_path):
        # Roughly split out stderr and stdout from logcat
        # This is to support FuzzManager. The original logcat output is also
        # included in the report so nothing is lost.
        logcat = os.path.join(log_path, "log_logcat.txt")
        if not os.path.isfile(logcat):
            log.warning("log_logcat.txt does not exist!")
            return None
        err_log = os.path.join(log_path, "log_stderr.txt")
        if os.path.isfile(err_log):
            log.warning("log_stderr.txt already exist! Overwriting...")
        out_log = os.path.join(log_path, "log_stdout.txt")
        if os.path.isfile(out_log):
            log.warning("log_stdout.txt already exist! Overwriting...")
        with open(logcat, "rb") as lc_fp, open(err_log, "w") as e_fp, open(out_log, "w") as o_fp:
            for line in lc_fp:
                if b"Gecko" not in line and b"MOZ_" not in line:
                    continue
                line = line[33:].decode("ascii", "ignore")
                if line.startswith("GeckoDump"):
                    o_fp.write(line.split(": ", 1)[-1])
                elif line.startswith("Gecko") or line.startswith("MOZ_"):
                    e_fp.write(line.split(": ", 1)[-1])


    def save_logs(self, log_path, meta=False):
        assert self.logs is not None
        assert self.reason is not None, "Call close() first!"
        assert self._launches > -1, "clean_up() has been called"
        # copy logs to location specified by log_file
        if not os.path.isdir(log_path):
            os.makedirs(log_path)
        log_path = os.path.abspath(log_path)

        for fname in os.listdir(self.logs):
            full_name = os.path.join(self.logs, fname)
            # skip directories
            if not os.path.isfile(full_name):
                continue
            shutil.copy(full_name, log_path)
        self._split_logcat(log_path)


    def wait_on_files(self, wait_files, poll_rate=0.5, timeout=60):
        assert poll_rate >= 0, "Invalid poll_rate %d, must be greater than or equal to 0" % poll_rate
        assert timeout >= 0, "Invalid timeout %d, must be greater than or equal to 0" % timeout
        assert poll_rate <= timeout, "poll_rate must be less then or equal to timeout"
        wait_end = time.time() + timeout
        wait_files = set(self._session.realpath(x) for x in wait_files)

        while wait_files:
            open_files = set(x for _, x in self._session.get_open_files())
            # check if any open files are in the wait file list
            if not wait_files.intersection(open_files):
                break
            elif wait_end <= time.time():
                log.debug("Timeout waiting for: %s", ", ".join(x for x in open_files if x in wait_files))
                return False
            time.sleep(poll_rate)
        return True


    def _terminate(self):
        assert self._package is not None
        assert self._session, "Device not connected"
        # TODO: is this the best way???
        self._session.call(["shell", "am", "force-stop", self._package])


    def wait(self):
        while self.is_running():
            time.sleep(0.25)


def main(argv=None):  # pylint: disable=missing-docstring
    parser = argparse.ArgumentParser(description="ADB Device Wrapper")
    parser.add_argument(
        "--airplane-mode", default=None, type=int,
        help="Enable(1) or disable(0) airplane mode")
    parser.add_argument(
        "--install", help="Path to APK to install")
    parser.add_argument(
        "--install-asan", help="Path to NDK")
    parser.add_argument(
        "--launch", help="Path to APK to launch")
    parser.add_argument(
        "--logs", help="Location to save logs")
    parser.add_argument(
        "--ip", help="IP address of target device")
    parser.add_argument(
        "--port", default=5555, type=int,
        help="ADB listening port on target device")
    args = parser.parse_args(argv)

    log.info("Opening a session")
    session = ADBSession.create(args.ip, args.port, as_root=True)
    if session is None:
        log.error("Failed to connect to IP:%r port:%r", args.ip, args.port)
        return 1

    if args.install is not None:
        log.info("Installing %r ...", args.install)
        package = session.install(args.install)
        if not package:
            log.error("Could not install %r", args.install)
            return 1
        log.info("Installed %r", package)
    elif args.install_asan is not None:
        log.info("Installing ASan from %r ...", args.install_asan)
        session.install_asan(args.install_asan)
        log.info("Device reboot required")
    elif args.airplane_mode is not None:
        session.set_airplane_mode(mode=args.airplane_mode > 0)
    elif args.launch:
        package = ADBSession.get_package_name(args.launch)
        if not package:
            log.error("APK not installed")
            return 1
        proc = ADBProcess(package, session)
        try:
            proc.launch("about:blank")
            assert proc.is_running(), "browser not running?!"
            log.info("Launched")
            proc.wait()
        finally:
            proc.close()
            if args.logs:
                proc.save_logs(args.logs)
            proc.cleanup()
    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())
