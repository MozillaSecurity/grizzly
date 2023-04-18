# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from collections import namedtuple
from hashlib import sha1
from logging import getLogger
from os import SEEK_END
from pathlib import Path
from platform import machine, system
from re import DOTALL, VERBOSE
from re import compile as re_compile
from shutil import copyfileobj, move, rmtree
from tempfile import mkstemp
from time import strftime

# import FuzzManager utilities
from Collector.Collector import Collector
from fasteners.process_lock import InterProcessLock
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo, CrashSignature

from .stack_hasher import Stack
from .utils import grz_tmp

__all__ = ("Report",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)

# NOTE: order matters, aux -> stderr -> stdout
LogMap = namedtuple("LogMap", "aux stderr stdout")


class Report:
    DEFAULT_MAJOR = "NO_STACK"
    DEFAULT_MINOR = "NO_STACK"
    HANG_STACK_HEIGHT = 10
    MAX_LOG_SIZE = 1_048_576  # 1MB

    __slots__ = (
        "_crash_info",
        "_logs",
        "_signature",
        "_target_binary",
        "is_hang",
        "path",
        "prefix",
        "stack",
    )

    def __init__(self, log_path, target_binary, is_hang=False, size_limit=MAX_LOG_SIZE):
        assert isinstance(log_path, Path)
        assert isinstance(target_binary, Path)
        self._crash_info = None
        self._logs = self._select_logs(log_path)
        assert self._logs is not None
        self._signature = None
        self._target_binary = target_binary
        self.is_hang = is_hang
        self.path = log_path
        # tail files in log_path if needed
        if size_limit < 1:
            LOG.warning("No limit set on report log size!")
        else:
            for log in log_path.iterdir():
                if log.is_file() and log.stat().st_size > size_limit:
                    Report.tail(log, size_limit)
        # look through logs one by one until we find a stack
        for log_file in (x for x in self._logs if x is not None):
            stack = Stack.from_text(log_file.read_text("utf-8", errors="ignore"))
            if stack.frames:
                assert stack.minor is not None
                # limit the hash calculations to the first n frames if a hang
                # was detected to attempt to help local bucketing
                stack.height_limit = self.HANG_STACK_HEIGHT if is_hang else None
                self.prefix = f"{stack.minor[:8]}_{strftime('%Y-%m-%d_%H-%M-%S')}"
                self.stack = stack
                break
        else:
            self.prefix = f"{self.DEFAULT_MINOR}_{strftime('%Y-%m-%d_%H-%M-%S')}"
            self.stack = None

    @staticmethod
    def calc_hash(signature):
        """Create unique hash from a signature.

        Args:
            None

        Returns:
            str: Hash of the raw signature.
        """
        if signature is None:
            return "NO_SIGNATURE"
        return sha1(signature.rawSignature.encode("utf-8")).hexdigest()[:16]

    def cleanup(self):
        """Remove Report data from filesystem.

        Args:
            None

        Returns:
            None
        """
        if self.path and self.path.is_dir():
            rmtree(self.path)
        self.path = None

    @property
    def crash_hash(self):
        """Create unique hash from a signature.

        Args:
            None

        Returns:
            str: Hash of the raw signature of the crash.
        """
        return self.calc_hash(self.crash_signature)

    @property
    def crash_info(self):
        """Create CrashInfo object from logs.

        Args:
            None

        Returns:
            CrashInfo: CrashInfo based on log data.
        """
        if self._crash_info is None:
            assert self.path is not None
            # create ProgramConfiguration that can be reported to a FM server
            if Path(f"{self._target_binary}.fuzzmanagerconf").is_file():
                # attempt to use "<target_binary>.fuzzmanagerconf"
                fm_cfg = ProgramConfiguration.fromBinary(self._target_binary)
            else:
                LOG.debug("'%s.fuzzmanagerconf' does not exist", self._target_binary)
                LOG.debug("creating ProgramConfiguration")
                cpu = machine().lower()
                fm_cfg = ProgramConfiguration(
                    self._target_binary.name,
                    "x86_64" if cpu == "amd64" else cpu,
                    system(),
                )
            # read the log files and create a CrashInfo object
            self._crash_info = CrashInfo.fromRawCrashData(
                self._load_log(self._logs.stdout),
                self._load_log(self._logs.stderr),
                fm_cfg,
                auxCrashData=self._load_log(self._logs.aux),
            )
        return self._crash_info

    @property
    def crash_signature(self):
        """Create CrashSignature object from CrashInfo.

        Args:
            None

        Returns:
            CrashSignature: CrashSignature based on log data.
        """
        if self._signature is None:
            collector = Collector()
            if collector.sigCacheDir and Path(collector.sigCacheDir).is_dir():
                with InterProcessLock(str(grz_tmp() / "fm_sigcache.lock")):
                    cache_sig, _ = collector.search(self.crash_info)
                    if cache_sig:
                        LOG.debug("signature loaded from cache file %r", cache_sig)
                        self._signature = CrashSignature.fromFile(cache_sig)
            # if cache lookup failed generate a crash signature
            if self._signature is None:
                self._signature = self.crash_info.createCrashSignature(
                    maxFrames=self.crash_signature_max_frames(self.crash_info)
                )
            if self._signature is None:
                LOG.debug("failed to create FM signature")
        return self._signature

    @staticmethod
    def crash_signature_max_frames(crash_info, suggested_frames=8):
        """Determine how many stack frames should be used when creating a signature.

        Args:
            crash_info (CrashInfo): Data to analyse.
            suggested_frames (int): Minimum number of frames to use when creating a
                                    signature.

        Returns:
            int: Number of frames to use when creating a signature.
        """
        if any(
            entry.startswith("std::panicking") or entry.startswith("alloc::alloc")
            for entry in crash_info.backtrace
        ):
            # Rust panics add frames of noise to the top of the stack (std::panicking)
            # Sanitizer heap profile also have more noise on the stack (alloc::alloc)
            suggested_frames += 6
        return suggested_frames

    @staticmethod
    def _find_ffpuppet_worker(logs):
        """Search through list of log files for a ffpuppet worker log.

        Args:
            logs (list(Path)): List of log files to search.

        Returns:
            Path: Log file if a match is found otherwise None.
        """
        found = None
        for log_file in (x for x in logs if "ffp_worker" in x.name):
            if found is not None:
                # we only expect one log here...
                LOG.warning("overwriting previously selected '%s'", log_file)
            found = log_file
        return found

    @staticmethod
    def _find_minidump(logs):
        """Search through list of log files for a minidump log.

        Args:
            logs (list(Path)): List of log files to search.

        Returns:
            Path: Log file if a match is found otherwise None.
        """
        re_dump_req = re_compile(
            r"\d+\|0\|.+?\|google_breakpad::ExceptionHandler::WriteMinidump"
        )
        for log_file in (x for x in logs if "minidump" in x.name):
            with log_file.open() as log_fp:
                data = log_fp.read(65536)
                # this will select log that contains "Crash|SIGSEGV|" or
                # the desired "DUMP_REQUESTED" log
                # TODO: review this it may be too strict
                # see mozilla-central/source/accessible/ipc/DocAccessibleParent.cpp#452
                if "Crash|DUMP_REQUESTED|" not in data or re_dump_req.search(data):
                    return log_file
        return None

    @staticmethod
    def _find_sanitizer(logs):
        """Search through list of log files for a sanitizer (ASan, UBSan, etc...) log.

        Args:
            logs (list(Path)): List of log files to search.

        Returns:
            Path: Log file if a match is found otherwise None.
        """
        # pattern to identify the ASan crash triggered when the parent process goes away
        # TODO: this may no longer be required
        re_e10s_forced = re_compile(
            r"""
            ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
            #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
            """,
            DOTALL | VERBOSE,
        )
        # this is a list of Sanitizer error reports to prioritize
        # Sanitizer reports not included below are deprioritized
        prioritize_tokens = (
            "use-after-",
            "-buffer-overflow on",
            ": data race ",
            ": SEGV on ",
            "access-violation on ",
            "attempting free on ",
            "negative-size-param",
            "-param-overlap",
        )
        fallback = None
        found = None
        for log_file in (x for x in logs if "asan" in x.name):
            with log_file.open() as log_fp:
                data = log_fp.read(65536)
            # look for interesting crash info in the log
            if "==ERROR:" in data or "WARNING:" in data:
                # check for e10s forced crash
                if re_e10s_forced.search(data) is not None:
                    continue
                # make sure there is something that looks like a stack frame
                if "#0 " in data:
                    found = log_file
                    if any(x in data for x in prioritize_tokens):
                        # this is the likely cause of the crash
                        break
            if found is None:
                # UBSan error (non-ASan builds)
                if ": runtime error: " in data:
                    found = log_file
                # catch all (choose the one with info for now)
                elif data:
                    fallback = log_file
        return found or fallback

    @staticmethod
    def _find_valgrind(logs):
        """Search through log files for a Valgrind log. Empty files are ignored.

        Args:
            logs (list(Path)): List of log files to search.

        Returns:
            Path: Log file if a match is found otherwise None.
        """
        for log_file in logs:
            if "valgrind" in log_file.name and log_file.stat().st_size:
                return log_file
        return None

    @staticmethod
    def _load_log(path):
        """Load and sanitize text from a file for use with CrashInfo.fromRawCrashData().

        Args:
            path (Path): Log file to load.

        Returns:
            list(str): Text data sanitized and split into lines or None if path is None.
        """
        if not path:
            return None
        return path.read_text("utf-8", errors="replace").replace("\0", "?").splitlines()

    @property
    def major(self):
        """The inclusive bucketing hash based on the stack trace
        data found in logs.

        Args:
            None

        Returns:
            str: major hash string.
        """
        if self.stack and self.stack.major is not None:
            return self.stack.major
        return self.DEFAULT_MAJOR

    @property
    def minor(self):
        """The specific bucketing hash based on the stack trace
        data found in logs.

        Args:
            None

        Returns:
            str: minor hash string.
        """
        if self.stack and self.stack.minor is not None:
            return self.stack.minor
        return self.DEFAULT_MINOR

    @property
    def preferred(self):
        """Log file containing most relevant data.

        Args:
            None

        Returns:
            Path: Log file.
        """
        return self._logs.aux or self._logs.stderr

    @classmethod
    def _select_logs(cls, path):
        """Scan path for file containing stderr, stdout and other (aux)
        data and build a LogMap.

        Args:
            path (Path): Location to scan for log files.

        Returns:
            LogMap: A LogMap pointing to log files or None if path is empty.
        """
        files = (x for x in path.iterdir() if x.is_file())
        # order by date hopefully the oldest log is the cause of the issue
        to_scan = sorted(files, key=lambda x: x.stat().st_mtime)
        if not to_scan:
            LOG.warning("No files found in %r", path)
            return None
        # look for file to use as aux log
        log_aux = cls._find_sanitizer(to_scan)
        if log_aux is None:
            log_aux = cls._find_valgrind(to_scan)
        if log_aux is None:
            log_aux = cls._find_minidump(to_scan)
        if log_aux is None:
            log_aux = cls._find_ffpuppet_worker(to_scan)
        # look for stderr and stdout log files
        log_err = None
        log_out = None
        for log_files in to_scan:
            if "stderr" in log_files.name:
                log_err = log_files
            elif "stdout" in log_files.name:
                log_out = log_files
        result = LogMap(log_aux, log_err, log_out)
        return result if any(result) else None

    @staticmethod
    def tail(in_file, size_limit):
        """Tail the given file. WARNING: This is destructive!

        Args:
            in_file (Path): File to work with.
            size_limit (int): Maximum size of file after tail operation.

        Returns:
            None
        """
        assert size_limit > 0
        with in_file.open("rb") as in_fp:
            in_fp.seek(0, SEEK_END)
            end = in_fp.tell()
            if end <= size_limit:
                return
            dump_pos = end - size_limit
            in_fp.seek(dump_pos)
            out_fd, out_file = mkstemp(prefix="taillog_", dir=grz_tmp())
            with open(out_fd, "wb") as out_fp:
                out_fp.write(b"[LOG TAILED]\n")
                copyfileobj(in_fp, out_fp, 0x10000)  # 64KB chunks
        in_file.unlink()
        move(out_file, in_file)
