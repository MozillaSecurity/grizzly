import os
import re
from enum import Enum, unique
from logging import getLogger
from pathlib import Path
from random import getrandbits
from shutil import copy, rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from time import sleep, time

from ffpuppet.bootstrapper import Bootstrapper
from ffpuppet.minidump_parser import process_minidumps
from ffpuppet.puppet_logger import PuppetLogger
from yaml import safe_dump

from grizzly.common.utils import grz_tmp

from .adb_session import ADBSession, ADBSessionError

LOG = getLogger("adb_process")

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


# Note: This was taken from FFPuppet.
@unique
class Reason(Enum):
    """Indicates why the browser process was terminated"""

    # target crashed, aborted, triggered an assertion failure, etc...
    ALERT: int = 0
    # target was closed by call to ADBProcess.close() or has not been launched
    CLOSED: int = 1
    # target exited
    EXITED: int = 2


class ADBLaunchError(ADBSessionError):
    pass


class ADBProcess:
    # TODO:
    #  def save_logs(self, *args, **kwargs):
    #  def clone_log(self, log_id, offset=0):
    #  def log_data(self, log_id, offset=0):
    #  def log_length(self, log_id):... likely not going to happen because of overhead

    __slots__ = (
        "_launches",
        "_package",
        "_pid",
        "_profile_template",
        # "_sanitizer_logs",
        "_session",
        "_working_path",
        "logs",
        "profile",
        "reason",
    )

    def __init__(self, package_name, session, use_profile=None):
        assert isinstance(session, ADBSession), "Expecting ADBSession"
        if not session.is_installed(package_name):
            raise ADBSessionError("Package %r is not installed" % (package_name,))
        self._launches = 0  # number of successful browser launches
        self._package = package_name  # package to use as target process
        self._pid = None  # pid of current target process
        self._profile_template = use_profile  # profile that is used as a template
        self._session = session  # ADB session with device
        # Note: geckview_example fails to read a profile from /sdcard/ atm
        # self._working_path = "/sdcard/ADBProc_%08X" % (getrandbits(32),)
        self._working_path = "/data/local/tmp/ADBProc_%08X" % (getrandbits(32),)
        # self._sanitizer_logs = "%s/sanitizer_logs" % (self._working_path,)
        self.logs = None
        self.profile = None  # profile path on device
        self.reason = Reason.CLOSED

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def cleanup(self):
        if self._launches < 0:
            LOG.debug("clean_up() call ignored")
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
            LOG.debug("already closed!")
            return
        try:
            if self._session is not None:
                crash_reports = self.find_crashreports()
                # set reason code
                if crash_reports:
                    self.reason = Reason.ALERT
                    self.wait_on_files(crash_reports)
                elif self.is_running():
                    self.reason = Reason.CLOSED
                else:
                    self.reason = Reason.EXITED
                self._terminate()
                self.wait()
                self._process_logs(crash_reports)
                # remove remote working path
                self._session.shell(["rm", "-rf", self._working_path])
                # remove remote config yaml
                cfg_file = "/data/local/tmp/%s-geckoview-config.yaml" % (self._package,)
                self._session.shell(["rm", "-rf", cfg_file])
                # TODO: this should be temporary until ASAN_OPTIONS=log_file is working
                if "log_asan.txt" in os.listdir(self.logs):
                    self.reason = Reason.ALERT

        except ADBSessionError:
            LOG.warning("No device detected while closing process")
        self._pid = None
        self.profile = None
        if self.reason is None:
            self.reason = Reason.CLOSED

    def find_crashreports(self):
        reports = list()
        # look for logs from sanitizers
        # for fname in self._session.listdir(self._sanitizer_logs):
        #    reports.append(os.path.join(self._sanitizer_logs, fname))

        if self.profile:
            # check for minidumps
            md_path = os.path.join(self.profile, "minidumps")
            try:
                for fname in self._session.listdir(md_path):
                    if ".dmp" in fname or ".extra" in fname:
                        reports.append(os.path.join(md_path, fname))
            except IOError:
                LOG.debug("%s does not exist", md_path)

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

    def launch(self, url, env_mod=None, launch_timeout=60, prefs_js=None):
        LOG.debug("launching %r", url)
        assert self._launches > -1, "clean_up() has been called"
        assert self._session, "Device not connected"
        assert self._package, "Package not specified"
        assert self._pid is None, "Process is already running"
        assert self.reason is not None, "Process is already running"

        self._session.clear_logs()
        self._remove_logs()
        self.reason = None

        if ".fenix" in self._package:
            app = "%s/org.mozilla.fenix.IntentReceiverActivity" % (self._package,)
        elif ".geckoview_example" in self._package:
            app = "%s/org.mozilla.geckoview_example.GeckoViewActivity" % (self._package)
        else:
            raise ADBLaunchError("Unsupported package %r" % (self._package,))

        # check app is not previously running
        if self._session.get_pid(self._package) is not None:
            raise ADBLaunchError("%r is already running" % (self._package,))

        # load prefs from prefs.js
        prefs = self.prefs_to_dict(prefs_js) if prefs_js else dict()
        if prefs is None:
            raise ADBLaunchError("Invalid prefs.js file (%s)" % (prefs_js,))

        # setup bootstrapper and reverse port
        # reverse does fail occasionally so use a retry loop
        for _ in range(10):
            bootstrapper = Bootstrapper()
            if not self._session.reverse(bootstrapper.port, bootstrapper.port):
                bootstrapper.close()
                LOG.debug("failed to reverse port, retrying...")
                sleep(0.25)
                continue
            break
        else:
            raise ADBLaunchError("Could not reverse port")
        try:
            # add additional prefs
            prefs.update(
                {
                    "capability.policy.localfilelinks.checkloaduri.enabled": (
                        "allAccess"
                    ),
                    "capability.policy.localfilelinks.sites": bootstrapper.location,
                    "capability.policy.policynames": "localfilelinks",
                    "network.proxy.allow_bypass": False,
                    "network.proxy.failover_direct": False,
                    "privacy.partition.network_state": False,
                }
            )
            # create location to store sanitizer logs
            # self._session.shell(["mkdir", "-p", self._sanitizer_logs])
            # create empty profile
            self.profile = "%s/gv_profile_%08X" % (self._working_path, getrandbits(32))
            self._session.shell(["mkdir", "-p", self.profile])
            # add environment variables
            env_mod = dict(env_mod or {})
            env_mod.setdefault("MOZ_SKIA_DISABLE_ASSERTS", "1")
            self._session.sanitizer_options(
                "asan",
                {
                    "abort_on_error": "1",
                    "color": "0",
                    "external_symbolizer_path": "'/data/local/tmp/llvm-symbolizer'",
                    # "log_path": "'%s/log_san.txt'" % (self._sanitizer_logs,),
                    "symbolize": "1",
                },
            )

            # build *-geckoview-config.yaml
            # https://firefox-source-docs.mozilla.org/mobile/android/geckoview/...
            # consumer/automation.html#configuration-file-format
            cfg_file = "%s-geckoview-config.yaml" % (self._package,)
            with NamedTemporaryFile("w+t") as cfp:
                cfp.write(
                    safe_dump(
                        {
                            "args": ["--profile", self.profile],
                            "env": env_mod,
                            "prefs": prefs,
                        }
                    )
                )
                cfp.flush()
                if not self._session.push(cfp.name, "/data/local/tmp/%s" % (cfg_file,)):
                    raise ADBLaunchError("Could not upload %r" % (cfg_file,))
            cmd = [
                "am",
                "start",
                "-W",
                "-n",
                app,
                "-a",
                "android.intent.action.VIEW",
                "-d",
                bootstrapper.location,
            ]
            if "Status: ok" not in self._session.shell(cmd, timeout=launch_timeout)[1]:
                raise ADBLaunchError("Could not launch %r" % (self._package,))
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

    @staticmethod
    def prefs_to_dict(prefs_file):
        pattern = re.compile(r"user_pref\((?P<name>.+?),\s*(?P<value>.+)\);")
        out = dict()
        with open(prefs_file, "r") as in_fp:
            for line in in_fp:
                pref = pattern.match(line)
                if not pref:
                    continue
                # parse name
                name = pref.group("name")
                if name[0] == "'" == name[-1]:
                    name = name.strip("'")
                elif name[0] == '"' == name[-1]:
                    name = name.strip('"')
                else:
                    LOG.error("Pref name is not quoted (%s)", name)
                    return None
                if not name:
                    LOG.error("Pref name is missing")
                    return None
                # parse value
                value = pref.group("value")
                if value in ("false", "true"):
                    out[name] = value == "true"
                elif value[0] == "'" == value[-1]:
                    out[name] = value.strip("'")
                elif value[0] == '"' == value[-1]:
                    out[name] = value.strip('"')
                else:
                    try:
                        out[name] = int(value)
                    except ValueError:
                        LOG.error("Pref %r has invalid value %r", name, value)
                        return None
        return out

    def _process_logs(self, crash_reports):
        assert self.logs is None
        self.logs = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
        unprocessed = Path(self.logs) / "unprocessed"
        unprocessed.mkdir(exist_ok=True)

        with (Path(self.logs) / "log_logcat.txt").open("wb") as log_fp:
            # TODO: should this filter by pid or not?
            log_fp.write(self._session.collect_logs())
            # log_fp.write(self._session.collect_logs(pid=self._pid))
        self._split_logcat(self.logs, self._package)
        if not crash_reports:
            return

        # copy crash logs from the device
        for fname in crash_reports:
            self._session.pull(fname, str(unprocessed))

        with PuppetLogger() as logger:
            if any(unprocessed.glob("*.dmp")):
                process_minidumps(
                    unprocessed,
                    Path(self._session.symbols_path(self._package)),
                    logger.add_log,
                )
            logger.close()
            logger.save_logs(self.logs)

    def _remove_logs(self):
        if self.logs is not None and os.path.isdir(self.logs):
            rmtree(self.logs)
            self.logs = None

    @staticmethod
    def _split_logcat(log_path, package_name):
        # Roughly split out stderr and stdout from logcat
        # This is to support FuzzManager. The original logcat output is also
        # included in the report so nothing is lost.
        logcat = os.path.join(log_path, "log_logcat.txt")
        if not os.path.isfile(logcat):
            LOG.warning("log_logcat.txt does not exist!")
            return
        err_log = os.path.join(log_path, "log_stderr.txt")
        if os.path.isfile(err_log):
            LOG.warning("log_stderr.txt already exist! Overwriting...")
        out_log = os.path.join(log_path, "log_stdout.txt")
        if os.path.isfile(out_log):
            LOG.warning("log_stdout.txt already exist! Overwriting...")
        assert package_name
        if not isinstance(package_name, bytes):
            package_name = package_name.encode("utf-8")
        # create set of filter pids
        # this will include any line that mentions "Gecko", "MOZ_" or the package name
        asan_tid = None
        filter_pids = set()
        re_id = re.compile(rb"^\d+-\d+\s+(\d+[:.]){3}\d+\s+(?P<pid>\d+)\s+(?P<tid>\d+)")
        with open(logcat, "rb") as lc_fp:
            for line in lc_fp:
                if (
                    b"Gecko" not in line
                    and b"MOZ_" not in line
                    and package_name not in line
                    and b"wrap.sh" not in line
                ):
                    continue
                m_id = re_id.match(line)
                if m_id is None:
                    continue
                filter_pids.add(m_id.group("pid"))
                if asan_tid is None and b": AddressSanitizer:" in line:
                    asan_tid = m_id.group("tid")
        LOG.debug("%d interesting pid(s) found in logcat output", len(filter_pids))
        # filter logs
        with open(logcat, "rb") as lc_fp, open(err_log, "wb") as e_fp, open(
            out_log, "wb"
        ) as o_fp:
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
                line = re.sub(rb".+?\s[ADEIVW]\s+", b"", line)
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
                LOG.warning("log_asan.txt already exist! Overwriting...")
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
                    line = re.sub(rb".+?\s[ADEIVW]\s+", b"", line)
                    o_fp.write(line.split(b": ", 1)[-1])

    def save_logs(self, log_path, meta=False):  # pylint: disable=unused-argument
        assert self.reason is not None, "Call close() first!"
        assert self._launches > -1, "clean_up() has been called"
        if self.logs is None:
            LOG.warning("No logs available to save.")
            return
        # copy logs to location specified by log_file
        if not os.path.isdir(log_path):
            os.makedirs(log_path)
        log_path = os.path.abspath(log_path)

        for fname in os.listdir(self.logs):
            full_name = os.path.join(self.logs, fname)
            # skip directories
            if not os.path.isfile(full_name):
                continue
            copy(full_name, log_path)

    def wait_on_files(self, wait_files, poll_rate=0.5, timeout=60):
        assert poll_rate >= 0
        assert timeout >= 0
        assert poll_rate <= timeout
        wait_end = time() + timeout
        wait_files = set(self._session.realpath(x) for x in wait_files)

        while wait_files:
            open_files = set(x for _, x in self._session.open_files())
            # check if any open files are in the wait file list
            if not wait_files.intersection(open_files):
                break
            if wait_end <= time():
                LOG.debug(
                    "Timeout waiting for: %s",
                    ", ".join(x for x in open_files if x in wait_files),
                )
                return False
            sleep(poll_rate)
        return True

    def _terminate(self):
        assert self._package is not None
        assert self._session, "Device not connected"
        # TODO: is this the best way???
        self._session.shell(["am", "force-stop", self._package])

    def wait(self):
        while self.is_running():
            sleep(0.25)
