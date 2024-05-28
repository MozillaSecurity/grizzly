# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from itertools import chain
from logging import getLogger
from os import kill
from pathlib import Path
from platform import system
from signal import SIGABRT, Signals
from tempfile import TemporaryDirectory, mkdtemp
from time import sleep, time
from typing import Any, Dict, Optional, Set, cast

try:
    from signal import SIGUSR1  # pylint: disable=ungrouped-imports

    COVERAGE_SIG: Optional[Signals] = SIGUSR1
except ImportError:
    COVERAGE_SIG = None

from ffpuppet import BrowserTimeoutError, Debugger, FFPuppet, LaunchError, Reason
from ffpuppet.helpers import certutil_available, certutil_find
from ffpuppet.sanitizer_util import SanitizerOptions
from prefpicker import PrefPicker
from psutil import AccessDenied, NoSuchProcess, Process, process_iter, wait_procs

from sapphire import CertificateBundle

from ..common.report import Report
from ..common.utils import grz_tmp
from .target import Result, Target, TargetLaunchError, TargetLaunchTimeout
from .target_monitor import TargetMonitor

__all__ = ("PuppetTarget",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


class PuppetMonitor(TargetMonitor):
    def __init__(self, puppet: FFPuppet) -> None:
        self._puppet = puppet

    def clone_log(self, log_id: str, offset: int = 0) -> Optional[Path]:
        return self._puppet.clone_log(log_id, offset=offset)

    def is_healthy(self) -> bool:
        return self._puppet.is_healthy()

    def is_idle(self, threshold: int) -> bool:
        # assert 0 <= threshold <= 100
        for _, cpu in self._puppet.cpu_usage():
            if cpu >= threshold:
                return False
        return True

    def is_running(self) -> bool:
        return self._puppet.is_running()

    @property
    def launches(self) -> int:
        return self._puppet.launches

    def log_length(self, log_id: str) -> int:
        return self._puppet.log_length(log_id) or 0


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
        "MOZ_FUZZ_CRASH_ON_LARGE_ALLOC",
        "MOZ_FUZZ_LARGE_ALLOC_LIMIT",
        "XPCOM_DEBUG_BREAK",
    )

    __slots__ = ("use_valgrind", "_debugger", "_extension", "_prefs", "_puppet")

    def __init__(
        self,
        binary: Path,
        launch_timeout: int,
        log_limit: int,
        memory_limit: int,
        **kwds: Dict[str, Any],
    ) -> None:
        certs = cast(Optional[CertificateBundle], kwds.pop("certs", None))
        # only pass certs to FFPuppet if certutil is available
        # otherwise certs can't be used
        if certs and not certutil_available(certutil_find(binary)):
            LOG.warning("HTTPS support requires NSS certutil.")
            certs = None

        super().__init__(
            binary,
            launch_timeout,
            log_limit,
            memory_limit,
            certs=certs,
        )
        self._https = certs is not None

        # TODO: clean up handling debuggers
        self._debugger = Debugger.NONE
        if kwds.pop("pernosco", False):
            self._debugger = Debugger.PERNOSCO
        if kwds.pop("rr", False):
            self._debugger = Debugger.RR
        if kwds.pop("valgrind", False):
            self.use_valgrind = True
            self._debugger = Debugger.VALGRIND
        self._extension: Optional[Path] = None
        self._prefs: Optional[Path] = None

        # create Puppet object
        self._puppet = FFPuppet(
            debugger=self._debugger,
            headless=cast(Optional[str], kwds.pop("headless", None)),
            working_path=str(grz_tmp("target")),
        )
        if kwds:
            LOG.debug("PuppetTarget ignoring unsupported kwargs: %s", ", ".join(kwds))

    def _cleanup(self) -> None:
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.clean_up()

    def close(self, force_close: bool = False) -> None:
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.close(force_close=force_close)

    @property
    def closed(self) -> bool:
        return self._puppet.reason is not None

    def create_report(self, is_hang: bool = False, unstable: bool = False) -> Report:
        logs = Path(mkdtemp(prefix="logs_", dir=grz_tmp("logs")))
        self.save_logs(logs)
        return Report(logs, self.binary, is_hang=is_hang, unstable=unstable)

    def filtered_environ(self) -> Dict[str, str]:
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
            filtered[san] = str(opts)
        # remove empty entries
        return {k: v for k, v in filtered.items() if v}

    @property
    def monitor(self) -> PuppetMonitor:
        if self._monitor is None:
            self._monitor = PuppetMonitor(self._puppet)
        return cast(PuppetMonitor, self._monitor)

    def check_result(self, ignored: Set[str]) -> Result:
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
                assert self._puppet.reason is not None
                # crash or hang (forced SIGABRT) has been detected
                LOG.debug("result detected (%s)", self._puppet.reason.name)
                result = Result.FOUND
        return result

    def handle_hang(
        self, ignore_idle: bool = True, ignore_timeout: bool = False
    ) -> bool:
        # only send SIGABRT in certain case
        send_abort = (
            not ignore_timeout
            and system() == "Linux"
            and self._debugger == Debugger.NONE
        )
        was_idle = False
        if self._puppet.is_healthy():
            proc_usage = sorted(self._puppet.cpu_usage(), key=lambda x: x[1])
            if proc_usage:
                pid, cpu = proc_usage.pop()
                if ignore_idle and cpu < 15:
                    # don't send SIGABRT if process is idle
                    LOG.debug("ignoring idle hang (%0.1f%%)", cpu)
                    was_idle = True
                elif send_abort:
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

    def https(self) -> bool:
        return self._https

    def dump_coverage(self, timeout: int = 5) -> None:
        if system() != "Linux":
            LOG.debug("dump_coverage() only supported on Linux")
            return

        assert COVERAGE_SIG is not None
        pid = self._puppet.get_pid()
        if pid is None or not self._puppet.is_healthy():
            LOG.debug("Skipping coverage dump (target is not in a good state)")
            return
        # If at this point, the browser is in a good state, i.e. no crashes
        # or hangs, so signal the browser to dump coverage.
        running_procs = 0
        signaled_pids: Set[int] = set()
        try:
            # send COVERAGE_SIG (SIGUSR1) to browser processes
            # TODO: this should use FFPuppet.processes()
            parent_proc = Process(pid)
            for proc in chain([parent_proc], parent_proc.children(recursive=True)):
                # avoid sending signal to non-browser processes
                if Path(proc.exe()).name.startswith("firefox"):
                    LOG.debug(
                        "Sending signal to %d (%s)",
                        proc.pid,
                        "parent" if proc.pid == pid else "child",
                    )
                    try:
                        kill(proc.pid, COVERAGE_SIG)
                        signaled_pids.add(proc.pid)
                    except OSError:
                        LOG.warning("Failed to send signal to pid %d", proc.pid)
                if proc.is_running():
                    running_procs += 1
        except (AccessDenied, NoSuchProcess):  # pragma: no cover
            pass
        if not signaled_pids:
            LOG.warning(
                "Signal not sent, no browser processes found (%d process(es) running)",
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
                    # TODO: collect all process with open files
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
                    # timeout waiting for .gcda file to be written
                    LOG.warning(
                        "gcda file open by pid %d after %0.2fs", gcda_open, elapsed
                    )
                    try:
                        kill(gcda_open, SIGABRT)
                        # wait for logs
                        wait_procs([Process(gcda_open)], timeout=5)
                    except (AccessDenied, NoSuchProcess, OSError):  # pragma: no cover
                        pass
                    self.close()
                    break
                if delay < 1.0:
                    # increase delay to a maximum of 1 second
                    # it is increased when waiting for the .gcda files to be written
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

    def launch(self, location: str) -> None:
        # setup environment
        env_mod = dict(self.environ)
        # do not allow network connections to non local endpoints
        env_mod["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1"
        # we always want the browser to exit when a crash is detected
        env_mod["MOZ_CRASHREPORTER_SHUTDOWN"] = "1"
        try:
            self._puppet.launch(
                self.binary,
                launch_timeout=self.launch_timeout,
                location=location,
                log_limit=self.log_limit,
                memory_limit=self.memory_limit,
                prefs_js=self._prefs,
                extension=[self._extension] if self._extension else None,
                env_mod=cast(Dict[str, Optional[str]], env_mod),
                cert_files=[self.certs.root] if self.certs else None,
            )
        except LaunchError as exc:
            self.close()
            if isinstance(exc, BrowserTimeoutError):
                raise TargetLaunchTimeout(str(exc)) from None
            raise TargetLaunchError(
                str(exc), self.create_report(unstable=True)
            ) from None

    def log_size(self) -> int:
        total = 0
        for log in ("stderr", "stdout"):
            length = self._puppet.log_length(log)
            if length:
                total += length
        return total

    def merge_environment(self, extra: Dict[str, str]) -> None:
        output = dict(extra)
        if self.environ:
            # prioritize existing environment variables
            output.update(self.environ)
            # merge contents of *SAN_OPTIONS
            org = SanitizerOptions()
            out = SanitizerOptions()
            for san in ("ASAN", "LSAN", "TSAN", "UBSAN"):
                opts = f"{san}_OPTIONS"
                org.load_options(self.environ.get(opts, ""))
                if not org:
                    # nothing to add from original
                    continue
                out.load_options(extra.get(opts, ""))
                for opt, value in org:  # pylint: disable=not-an-iterable
                    out.add(opt, value, overwrite=True)
                output[opts] = str(out)
        self.environ = output

    def process_assets(self) -> None:
        self._extension = self.asset_mgr.get("extension")
        self._prefs = self.asset_mgr.get("prefs")
        # generate temporary prefs.js with prefpicker
        if self._prefs is None:
            LOG.debug("using prefpicker to generate prefs.js")
            with TemporaryDirectory(dir=grz_tmp("target")) as tmp_path:
                prefs = Path(tmp_path) / "prefs.js"
                template = PrefPicker.lookup_template("browser-fuzzing.yml")
                assert template
                PrefPicker.load_template(template).create_prefsjs(prefs)
                self._prefs = self.asset_mgr.add("prefs", prefs, copy=False)
        abort_tokens = self.asset_mgr.get("abort-tokens")
        if abort_tokens:
            LOG.debug("loading 'abort tokens' from '%s'", abort_tokens)
            with (self.asset_mgr.path / abort_tokens).open() as in_fp:
                for line in in_fp:
                    line = line.strip()
                    if line:
                        self._puppet.add_abort_token(line)

        # configure sanitizer suppressions
        opts = SanitizerOptions()
        for sanitizer in ("lsan", "tsan", "ubsan"):
            asset = f"{sanitizer}-suppressions"
            # load existing sanitizer options from environment
            var_name = f"{sanitizer.upper()}_OPTIONS"
            opts.load_options(self.environ.get(var_name, ""))
            if self.asset_mgr.get(asset):
                # use suppression file if provided as asset
                opts.add(
                    "suppressions", f"'{self.asset_mgr.get(asset)}'", overwrite=True
                )
            elif opts.get("suppressions"):
                suppressions = opts.pop("suppressions")
                assert suppressions
                path = Path(suppressions.strip("\"'"))
                if path.is_file():
                    # use environment specified suppression file
                    LOG.debug("using %r from environment", asset)
                    opts.add(
                        "suppressions",
                        f"'{self.asset_mgr.add(asset, path)}'",
                        overwrite=True,
                    )
                else:
                    LOG.warning("Missing %s suppressions file '%s'", sanitizer, path)
            else:
                LOG.debug("%r does not contain suppressions", var_name)
                continue
            # update sanitized *SAN_OPTIONS
            LOG.debug("updating suppressions in %r", var_name)
            self.environ[var_name] = str(opts)

    def save_logs(self, dst: Path) -> None:
        self._puppet.save_logs(dst)
