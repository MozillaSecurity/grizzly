import logging
import os
import random
import re
import shutil
import tempfile
import time

from ffpuppet.bootstrapper import Bootstrapper
from ffpuppet.helpers import append_prefs, create_profile
from ffpuppet.minidump_parser import process_minidumps
from ffpuppet.puppet_logger import PuppetLogger

from .adb_session import ADBSession, ADBSessionError

log = logging.getLogger("adb_process")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class ADBLaunchError(ADBSessionError):
    pass


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
        self.profile = None  # profile path on device
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
                # TODO: this should be temporary until ASAN_OPTIONS=log_file is working
                if "log_asan.txt" in os.listdir(self.logs):
                    self.reason = self.RC_ALERT

        except ADBSessionError:
            log.warning("No device detected while closing process")
        self._pid = None
        self.profile = None
        if self.reason is None:
            self.reason = self.RC_CLOSED

    def find_crashreports(self):
        reports = list()
        # TODO: scan for ASan logs once ASAN_OPTIONS=log_path is working
        if self.profile:
            # check for minidumps
            md_path = os.path.join(self.profile, "minidumps")
            try:
                contents = self._session.listdir(md_path)
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

    def launch(self, url, env_mod=None, extension=None, launch_timeout=60, prefs_js=None):
        log.debug("launching %r", url)
        assert self._launches > -1, "clean_up() has been called"
        assert self._session, "Device not connected"
        assert self._package, "Package not specified"
        assert self._pid is None, "Process is already running"
        assert self.reason is not None, "Process is already running"

        self._session.clear_logs()
        self._remove_logs()
        sanitizer_logs = os.path.dirname(self._session.SANITIZER_LOG_PREFIX)
        self._session.call(["shell", "rm", "-r", sanitizer_logs])
        self._session.call(["shell", "mkdir", "-p", sanitizer_logs])
        self._session.call(["shell", "chmod", "666", sanitizer_logs])
        self.reason = None
        # setup bootstrapper and reverse port
        # reverse does fail occasionally so use a retry loop
        for _ in range(10):
            bootstrapper = Bootstrapper(poll_wait=0.5)
            if not self._session.reverse(bootstrapper.port, bootstrapper.port):
                bootstrapper.close()
                log.debug("failed to reverse port, retrying...")
                time.sleep(0.25)
                continue
            break
        else:
            raise ADBLaunchError("Could not reverse port")
        try:
            profile = create_profile(extension=extension, prefs_js=prefs_js, template=self._profile_template)
            try:
                prefs = {
                    "capability.policy.policynames": "'localfilelinks'",
                    "capability.policy.localfilelinks.sites": "'%s'" % bootstrapper.location,
                    "capability.policy.localfilelinks.checkloaduri.enabled": "'allAccess'"}
                append_prefs(profile, prefs)
                self.profile = "/".join([self._working_path, os.path.basename(profile)])
                if not self._session.push(profile, self.profile):
                    raise ADBLaunchError("Could not upload profile %r" % profile)
            finally:
                shutil.rmtree(profile, True)
            cmd = [
                "shell", "am", "start", "-W", "-n",
                "/".join([self._package, "org.mozilla.geckoview_example.GeckoViewActivity"]),
                "-a", "android.intent.action.VIEW", "-d", bootstrapper.location,
                "--es", "args", "-profile\\ %s" % self.profile]
            # add environment variables to launch command
            env_mod = dict(env_mod or {})
            env_mod.setdefault("MOZ_SKIA_DISABLE_ASSERTS", "1")
            for var_num, (var_name, var_val) in enumerate(env_mod.items()):
                if var_val is None:
                    continue
                cmd.append("--es")
                cmd.append("env%d" % var_num)
                cmd.append("%s=%s" % (var_name, var_val))

            if "Status: ok" not in self._session.call(cmd, timeout=launch_timeout)[1].splitlines():
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
        self._split_logcat(self.logs, self._package)
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
    def _split_logcat(log_path, package_name):
        # Roughly split out stderr and stdout from logcat
        # This is to support FuzzManager. The original logcat output is also
        # included in the report so nothing is lost.
        logcat = os.path.join(log_path, "log_logcat.txt")
        if not os.path.isfile(logcat):
            log.warning("log_logcat.txt does not exist!")
            return
        err_log = os.path.join(log_path, "log_stderr.txt")
        if os.path.isfile(err_log):
            log.warning("log_stderr.txt already exist! Overwriting...")
        out_log = os.path.join(log_path, "log_stdout.txt")
        if os.path.isfile(out_log):
            log.warning("log_stdout.txt already exist! Overwriting...")
        assert package_name
        if not isinstance(package_name, bytes):
            package_name = package_name.encode("utf-8")
        # create set of filter pids
        # this will include any line that mentions "Gecko", "MOZ_" or the package name
        asan_tid = None
        filter_pids = set()
        re_id = re.compile(br"^\d+-\d+\s+(\d+[:.]){3}\d+\s+(?P<pid>\d+)\s+(?P<tid>\d+)")
        with open(logcat, "rb") as lc_fp:
            for line in lc_fp:
                if b"Gecko" not in line and b"MOZ_" not in line and package_name not in line:
                    continue
                m_id = re_id.match(line)
                if m_id is None:
                    continue
                filter_pids.add(m_id.group("pid"))
                if asan_tid is None and b": AddressSanitizer:" in line:
                    asan_tid = m_id.group("tid")
        log.debug("%d interesting pid(s) found in logcat output", len(filter_pids))
        # filter logs
        with open(logcat, "rb") as lc_fp, open(err_log, "wb") as e_fp, open(out_log, "wb") as o_fp:
            for line in lc_fp:
                # quick check if pid is in the line
                if not any(pid in line for pid in filter_pids):
                    continue
                # verify the line pid is in set of filter pids
                m_id = re_id.match(line)
                if m_id is None:
                    continue
                line_pid = m_id.group("pid")
                if not any(pid == line_pid for pid in filter_pids):
                    continue
                # strip logger info ... "07-27 12:10:15.442  9990  4234 E "
                line = re.sub(br".+?\s[ADEIVW]\s+", b"", line)
                if line.startswith(b"GeckoDump"):
                    o_fp.write(line.split(b": ", 1)[-1])
                else:
                    e_fp.write(line.split(b": ", 1)[-1])
        # Break out ASan logs (to be removed when ASAN_OPTIONS=log_path works)
        # This could be merged into the above block but it is kept separate
        # so it can be removed easily in the future.
        if asan_tid is not None:
            asan_log = os.path.join(log_path, "log_asan.txt")
            if os.path.isfile(asan_log):
                log.warning("log_asan.txt already exist! Overwriting...")
            found_log = False
            with open(logcat, "rb") as lc_fp, open(asan_log, "wb") as o_fp:
                for line in lc_fp:
                    # quick check if thread id is in the line
                    if asan_tid not in line:
                        continue
                    # verify the line tid matches ASan thread id
                    m_id = re_id.match(line)
                    if m_id is None or m_id.group("tid") != asan_tid:
                        continue
                    # filter noise before the crash
                    if not found_log:
                        if b": AddressSanitizer:" not in line:
                            continue
                        found_log = True
                    # strip logger info ... "07-27 12:10:15.442  9990  4234 E "
                    line = re.sub(br".+?\s[ADEIVW]\s+", b"", line)
                    o_fp.write(line.split(b": ", 1)[-1])

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

    def wait_on_files(self, wait_files, poll_rate=0.5, timeout=60):
        assert poll_rate >= 0, "Invalid poll_rate %d, must be greater than or equal to 0" % poll_rate
        assert timeout >= 0, "Invalid timeout %d, must be greater than or equal to 0" % timeout
        assert poll_rate <= timeout, "poll_rate must be less then or equal to timeout"
        wait_end = time.time() + timeout
        wait_files = set(self._session.realpath(x) for x in wait_files)

        while wait_files:
            open_files = set(x for _, x in self._session.open_files())
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
