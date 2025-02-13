# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from hashlib import sha1
from logging import getLogger
from os import getpid, kill
from pathlib import Path
from platform import system
from shutil import copytree, rmtree
from signal import SIGABRT
from tempfile import TemporaryDirectory, mkdtemp
from typing import TYPE_CHECKING, Any

from ffpuppet import BrowserTimeoutError, Debugger, FFPuppet, LaunchError, Reason
from ffpuppet.display import DisplayMode
from ffpuppet.helpers import certutil_available, certutil_find
from ffpuppet.profile import Profile
from ffpuppet.sanitizer_util import SanitizerOptions
from prefpicker import PrefPicker

from ..common.cache import add_cached, find_cached
from ..common.report import Report
from ..common.utils import grz_tmp, package_version
from .target import Result, Target, TargetLaunchError, TargetLaunchTimeout
from .target_monitor import TargetMonitor

if TYPE_CHECKING:
    from sapphire import CertificateBundle

__all__ = ("PuppetTarget",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


class PuppetMonitor(TargetMonitor):
    def __init__(self, puppet: FFPuppet) -> None:
        self._puppet = puppet

    def clone_log(self, log_id: str, offset: int = 0) -> Path | None:
        return self._puppet.clone_log(log_id, offset=offset)

    def is_healthy(self) -> bool:
        return self._puppet.is_healthy()

    def is_idle(self, threshold: int) -> bool:
        # assert 0 <= threshold <= 100
        return all(cpu < threshold for _, cpu in self._puppet.cpu_usage())

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
        "MOZ_FUZZ_HAS_GPU",
        "MOZ_FUZZ_LARGE_ALLOC_LIMIT",
        "XPCOM_DEBUG_BREAK",
    )

    __slots__ = (
        "_debugger",
        "_extension",
        "_monitor",
        "_prefs",
        "_profile_template",
        "_puppet",
        "use_valgrind",
    )

    def __init__(
        self,
        binary: Path,
        launch_timeout: int,
        log_limit: int,
        memory_limit: int,
        certs: CertificateBundle | None = None,
        display_mode: str = "default",
        pernosco: bool = False,
        rr: bool = False,
        valgrind: bool = False,
        **kwds: dict[str, Any],
    ) -> None:
        super().__init__(
            binary,
            launch_timeout,
            log_limit,
            memory_limit,
        )
        LOG.debug("ffpuppet version: %s", package_version("ffpuppet"))
        # only pass certs to FFPuppet if certutil is available
        # otherwise certs can't be used
        self._https = False
        self._monitor: PuppetMonitor | None = None
        self._profile_template = None
        if certs is not None:
            certutil = certutil_find(binary)
            if certutil_available(certutil):
                self._https = True
                self._profile_template = self._get_certdb(certs.root, certutil)
            else:
                LOG.warning("HTTPS support requires NSS certutil.")

        # TODO: clean up handling debuggers
        self._debugger = Debugger.NONE
        if pernosco:
            self._debugger = Debugger.PERNOSCO
        if rr:
            self._debugger = Debugger.RR
        if valgrind:
            # TODO: replace use_valgrind with something debugger generic
            self.use_valgrind = True
            self._debugger = Debugger.VALGRIND
        self._extension: Path | None = None
        self._prefs: Path | None = None

        # create FFPuppet object
        self._puppet = FFPuppet(
            debugger=self._debugger,
            display_mode=DisplayMode[display_mode.upper()],
            use_profile=self._profile_template,
            working_path=str(grz_tmp("target")),
        )
        if kwds:
            LOG.debug("PuppetTarget ignoring unsupported kwargs: %s", ", ".join(kwds))

    def _cleanup(self) -> None:
        # prevent parallel calls to FFPuppet.close() and/or FFPuppet.clean_up()
        with self._lock:
            self._puppet.clean_up()
        if self._profile_template is not None:
            rmtree(self._profile_template)

    @staticmethod
    def _get_certdb(cert_file: Path, certuil: str) -> Path:
        """Load or create a certdb to use with Firefox. This will search for a cached
        certificate and certdb before generating and caching a new bundle.
        The cache allows reuse across processes.

        Args:
            cert_file: Certificate to install into the newly created certdb.
            certutil: certutil binary.

        Returns:
            Directory containing the certdb files.
        """
        cached = find_cached("crypto")
        # certs and certdb are dependent on each other
        # use the hash of the cert file to ensure this
        db_path = (
            f"certdb_{sha1(cert_file.read_bytes(), usedforsecurity=False).hexdigest()}"
        )
        if cached is None or not (cached / db_path).exists():
            with TemporaryDirectory() as tmp_path:
                certdb = Path(tmp_path) / db_path
                certdb.mkdir(parents=True)
                Profile.init_cert_db(certdb, certuil)
                Profile.install_cert(certdb, cert_file, certuil)
                # add certdb to cache
                cached = add_cached("crypto", certdb)
        # copy data from cache
        path = grz_tmp("certdb") / str(getpid())
        copytree(cached / db_path, path)
        return path

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

    def filtered_environ(self) -> dict[str, str]:
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
        return self._monitor

    def check_result(self, ignored: set[str]) -> Result:
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

    def dump_coverage(self, timeout: int = 15) -> None:
        if self._puppet.is_healthy():
            self._puppet.dump_coverage(timeout=timeout)

    def launch(self, location: str) -> None:
        # setup environment
        env_mod: dict[str, str | None] = dict(self.environ)
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
                env_mod=env_mod,
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

    def merge_environment(self, extra: dict[str, str]) -> None:
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
