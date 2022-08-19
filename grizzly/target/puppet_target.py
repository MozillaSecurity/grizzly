# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from itertools import chain
from logging import getLogger
from os import kill
from os.path import isfile
from pathlib import Path
from platform import system
from signal import SIGABRT

try:
    from signal import SIGUSR1
except ImportError:
    SIGUSR1 = None
from tempfile import TemporaryDirectory, mkdtemp
from time import sleep, time

from ffpuppet import BrowserTimeoutError, Debugger, FFPuppet, LaunchError, Reason
from ffpuppet.sanitizer_util import SanitizerOptions
from prefpicker import PrefPicker
from psutil import AccessDenied, NoSuchProcess, Process, process_iter, wait_procs

from ..common.reporter import Report
from ..common.utils import grz_tmp
from .target import Result, Target, TargetLaunchError, TargetLaunchTimeout
from .target_monitor import TargetMonitor

__all__ = ("PuppetTarget",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


class PuppetTarget(Target):
    SUPPORTED_ASSETS = (
        # file containing line separated list of tokens to scan stderr/out for
        "abort-tokens",
        # xpi or directory containing the unpacked extension
        "extension",
        # LSan suppression list file
        "lsan-suppressions",
        # prefs.js file to use
        "prefs",
        # TSan suppression list file
        "tsan-suppressions",
        # UBSan suppression list file
        "ubsan-suppressions",
    )

    TRACKED_ENVVARS = (
        "ASAN_OPTIONS",
        "LSAN_OPTIONS",
        "TSAN_OPTIONS",
        "UBSAN_OPTIONS",
        "GNOME_ACCESSIBILITY",
        "MOZ_CHAOSMODE",
        "XPCOM_DEBUG_BREAK",
    )

    __slots__ = ("use_valgrind", "_extension", "_prefs", "_puppet")

    def __init__(self, binary, launch_timeout, log_limit, memory_limit, **kwds):
        super().__init__(
            binary,
            launch_timeout,
            log_limit,
            memory_limit,
            assets=kwds.pop("assets", None),
        )
        # TODO: clean up handling debuggers
        debugger = Debugger.NONE
        if kwds.pop("pernosco", False):
            debugger = Debugger.PERNOSCO
        if kwds.pop("rr", False):
            debugger = Debugger.RR
        if kwds.pop("valgrind", False):
            self.use_valgrind = True
            debugger = Debugger.VALGRIND
        self._extension = None
        self._prefs = None

        # create Puppet object
        self._puppet = FFPuppet(
            debugger=debugger,
            headless=kwds.pop("headless", None),
            working_path=grz_tmp("target"),
        )
        if kwds:
            LOG.warning(
                "PuppetTarget ignoring unsupported arguments: %s", ", ".join(kwds)
            )

    def _cleanup(self):
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.clean_up()

    def close(self, force_close=False):
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.close(force_close=force_close)

    @property
    def closed(self):
        return self._puppet.reason is not None

    def create_report(self, is_hang=False):
        logs = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
        self.save_logs(logs)
        return Report(logs, self.binary, is_hang=is_hang)

    def filtered_environ(self):
        # remove context specific entries from environment
        filtered = dict(self.environ)
        opts = SanitizerOptions()
        # iterate over *SAN_OPTIONS entries
        for san in (x for x in filtered if x.endswith("SAN_OPTIONS")):
            opts.load_options(filtered[san])
            # remove entries specific to the current environment
            opts.pop("external_symbolizer_path")
            opts.pop("log_path")
            opts.pop("strip_path_prefix")
            opts.pop("suppressions")
            filtered[san] = opts.options
        # remove empty entries
        return {k: v for k, v in filtered.items() if v}

    def is_idle(self, threshold):
        for _, cpu in self._puppet.cpu_usage():
            if cpu >= threshold:
                return False
        return True

    @property
    def monitor(self):
        if self._monitor is None:

            class _PuppetMonitor(TargetMonitor):
                # pylint: disable=no-self-argument,protected-access
                def clone_log(_, log_id, offset=0):
                    return self._puppet.clone_log(log_id, offset=offset)

                def is_running(_):
                    return self._puppet.is_running()

                def is_healthy(_):
                    return self._puppet.is_healthy()

                @property
                def launches(_):
                    return self._puppet.launches

                def log_length(_, log_id):
                    return self._puppet.log_length(log_id)

            self._monitor = _PuppetMonitor()
        return self._monitor

    def check_result(self, ignored):
        result = Result.NONE
        # check if there has been a crash, hangs will appear as SIGABRT
        if not self._puppet.is_healthy():
            self.close()
            # something has happened figure out what
            if self._puppet.reason == Reason.CLOSED:
                LOG.debug("target.close() was called")
            elif self._puppet.reason == Reason.EXITED:
                LOG.debug("target closed itself")
            elif (
                self._puppet.reason == Reason.WORKER
                and "memory" in ignored
                and "ffp_worker_memory_usage" in self._puppet.available_logs()
            ):
                result = Result.IGNORED
                LOG.debug("memory limit exceeded")
            elif (
                self._puppet.reason == Reason.WORKER
                and "log-limit" in ignored
                and "ffp_worker_log_size" in self._puppet.available_logs()
            ):
                result = Result.IGNORED
                LOG.debug("log size limit exceeded")
            else:
                # crash or hang (forced SIGABRT) has been detected
                LOG.debug("result detected (%s)", self._puppet.reason.name)
                result = Result.FOUND
        return result

    def handle_hang(self, ignore_idle=True):
        was_idle = False
        if self._puppet.is_healthy():
            proc_usage = sorted(self._puppet.cpu_usage(), key=lambda x: x[1])
            if proc_usage:
                pid, cpu = proc_usage.pop()
                if ignore_idle and cpu < 15:
                    # don't send SIGABRT if process is idle
                    LOG.debug("ignoring idle hang (%0.1f%%)", cpu)
                    was_idle = True
                elif system() == "Linux":
                    # sending SIGABRT is only supported on Linux for now
                    # TODO: add/test on other OSs
                    LOG.debug("sending SIGABRT to %r (%0.1f%%)", pid, cpu)
                    try:
                        kill(pid, SIGABRT)
                    except OSError:
                        LOG.warning("Failed to send SIGABRT to pid %d", pid)
                    self._puppet.wait(timeout=10)
        # always call close() since this function should only/always
        # be called when there has been a timeout
        self.close()
        return was_idle

    def dump_coverage(self, timeout=90):
        assert SIGUSR1 is not None
        pid = self._puppet.get_pid()
        if pid is None or not self._puppet.is_healthy():
            LOG.debug("Skipping coverage dump (target is not in a good state)")
            return
        # If at this point, the browser is in a good state, i.e. no crashes
        # or hangs, so signal the browser to dump coverage.
        signaled_pids = list()
        try:
            # send SIGUSR1 to browser processes
            parent_proc = Process(pid)
            running_procs = 0
            for proc in chain([parent_proc], parent_proc.children(recursive=True)):
                # avoid sending SIGUSR1 to non-browser processes
                if Path(proc.exe()).name.startswith("firefox"):
                    LOG.debug(
                        "Sending SIGUSR1 to %d (%s)",
                        proc.pid,
                        "parent" if proc.pid == pid else "child",
                    )
                    try:
                        kill(proc.pid, SIGUSR1)
                        signaled_pids.append(proc.pid)
                    except OSError:
                        LOG.warning("Failed to send SIGUSR1 to pid %d", proc.pid)
                if proc.is_running():
                    running_procs += 1
        except (AccessDenied, NoSuchProcess):  # pragma: no cover
            pass
        if not signaled_pids:
            LOG.warning(
                "SIGUSR1 not sent, no browser processes found (%d process(es) running)",
                running_procs,
            )
            return
        start_time = time()
        gcda_found = False
        delay = 0.1
        # wait for processes to write .gcda files (typically takes <1 second)
        while True:
            for proc in process_iter(attrs=["pid", "open_files"]):
                # scan signaled processes for open .gcda files
                if (
                    proc.info["pid"] in signaled_pids
                    and proc.info["open_files"]
                    and any(x.path.endswith(".gcda") for x in proc.info["open_files"])
                ):
                    gcda_found = True
                    # collect pid of process with open .gcda file
                    gcda_open = proc.info["pid"]
                    break
            else:
                gcda_open = None
            elapsed = time() - start_time
            if gcda_found:
                if gcda_open is None:
                    # success
                    LOG.debug("gcda dump took %0.2fs", elapsed)
                    break
                if elapsed >= timeout:
                    # timeout waiting for .gnco file to be written
                    LOG.warning(
                        "gcda file open by pid %d after %0.2fs", gcda_open, elapsed
                    )
                    try:
                        kill(gcda_open, SIGABRT)
                        wait_procs([Process(gcda_open)], timeout=15)
                    except (AccessDenied, NoSuchProcess, OSError):  # pragma: no cover
                        pass
                    self.close()
                    break
                if delay < 1.0:
                    # increase delay to a maximum of 1 second
                    # it is increased when waiting for the .gcno files to be written
                    # this decreases the number of calls to process_iter()
                    delay = min(1.0, delay + 0.1)
            elif elapsed >= 10:
                # assume we missed the process writing .gcda files
                LOG.warning("No gcda files seen after %0.2fs", elapsed)
                break
            if not self._puppet.is_healthy():
                LOG.warning("Browser failure during dump_coverage()")
                break
            sleep(delay)

    def launch(self, location):
        # setup environment
        env_mod = dict(self.environ)
        # do not allow network connections to non local endpoints
        env_mod["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1"
        env_mod["MOZ_CRASHREPORTER_SHUTDOWN"] = "1"
        try:
            self._puppet.launch(
                self.binary,
                launch_timeout=self.launch_timeout,
                location=location,
                log_limit=self.log_limit,
                memory_limit=self.memory_limit,
                prefs_js=self._prefs,
                extension=self._extension,
                env_mod=env_mod,
            )
        except LaunchError as exc:
            LOG.error("FFPuppet LaunchError: %s", str(exc))
            self.close()
            if isinstance(exc, BrowserTimeoutError):
                raise TargetLaunchTimeout(str(exc)) from None
            raise TargetLaunchError(str(exc), self.create_report()) from None

    def log_size(self):
        return self._puppet.log_length("stderr") + self._puppet.log_length("stdout")

    def process_assets(self):
        self._extension = self.assets.get("extension")
        self._prefs = self.assets.get("prefs")
        # generate temporary prefs.js with prefpicker
        if self._prefs is None:
            LOG.debug("using prefpicker to generate prefs.js")
            with TemporaryDirectory(dir=grz_tmp("target")) as tmp_path:
                prefs = Path(tmp_path) / "prefs.js"
                template = PrefPicker.lookup_template("browser-fuzzing.yml")
                PrefPicker.load_template(template).create_prefsjs(prefs)
                self._prefs = self.assets.add("prefs", str(prefs), copy=False)
        abort_tokens = self.assets.get("abort-tokens")
        if abort_tokens:
            LOG.debug("loading 'abort tokens' from %r", abort_tokens)
            with open(abort_tokens, "r") as in_fp:
                for line in in_fp:
                    line = line.strip()
                    if line:
                        self._puppet.add_abort_token(line)

        # configure sanitizer suppressions
        opts = SanitizerOptions()
        for sanitizer in ("lsan", "tsan", "ubsan"):
            asset = "%s-suppressions" % (sanitizer,)
            # load existing sanitizer options from environment
            var_name = "%s_OPTIONS" % (sanitizer.upper(),)
            opts.load_options(self.environ.get(var_name, ""))
            if self.assets.get(asset):
                # use suppression file if provided as asset
                opts.add("suppressions", repr(self.assets.get(asset)), overwrite=True)
            elif opts.get("suppressions"):
                supp_file = opts.pop("suppressions")
                if SanitizerOptions.is_quoted(supp_file):
                    supp_file = supp_file[1:-1]
                if isfile(supp_file):
                    # use environment specified suppression file
                    LOG.debug("using %r from environment", asset)
                    opts.add(
                        "suppressions",
                        repr(self.assets.add(asset, supp_file)),
                        overwrite=True,
                    )
                else:
                    LOG.warning("Missing %s suppressions file %r", sanitizer, supp_file)
            else:
                # nothing to do
                continue
            # update sanitized *SAN_OPTIONS
            LOG.debug("updating suppressions in %r", var_name)
            self.environ[var_name] = opts.options

    def save_logs(self, *args, **kwargs):
        self._puppet.save_logs(*args, **kwargs)
