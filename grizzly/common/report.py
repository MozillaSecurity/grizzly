# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from collections import namedtuple
from hashlib import sha1
from logging import getLogger
from os import SEEK_END, scandir, stat, unlink
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
    DEFAULT_MINOR = "0"
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
        assert isinstance(target_binary, str)
        self._crash_info = None
        self._logs = self.select_logs(log_path)
        assert self._logs is not None
        self._signature = None
        self._target_binary = Path(target_binary)
        self.is_hang = is_hang
        self.path = Path(log_path)
        # tail files in log_path if needed
        if size_limit < 1:
            LOG.warning("No limit set on report log size!")
        else:
            for log in scandir(path=log_path):
                if log.is_file() and log.stat().st_size > size_limit:
                    Report.tail(log.path, size_limit)
        # look through logs one by one until we find a stack
        for log_file in (x for x in self._logs if x is not None):
            with open(log_file, "rb") as log_fp:
                stack = Stack.from_text(log_fp.read().decode("utf-8", errors="ignore"))
            if stack.frames:
                # limit the hash calculations to the first n frames if a hang
                # was detected to attempt to help local bucketing
                stack.height_limit = self.HANG_STACK_HEIGHT if is_hang else None
                self.prefix = "%s_%s" % (stack.minor[:8], strftime("%Y-%m-%d_%H-%M-%S"))
                self.stack = stack
                break
        else:
            self.prefix = "%s_%s" % (self.DEFAULT_MINOR, strftime("%Y-%m-%d_%H-%M-%S"))
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
            rmtree(str(self.path))
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
            # read in the log files and create a CrashInfo object
            if self._logs.aux is not None:
                with open(self._logs.aux, "rb") as log_fp:
                    aux_data = (
                        log_fp.read().decode("utf-8", errors="ignore").splitlines()
                    )
            else:
                aux_data = None
            # create ProgramConfiguration that can be reported to a FM server
            if Path("%s.fuzzmanagerconf" % (self._target_binary,)).is_file():
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
            with open(self._logs.stderr, "rb") as err_fp, open(
                self._logs.stdout, "rb"
            ) as out_fp:
                self._crash_info = CrashInfo.fromRawCrashData(
                    out_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    err_fp.read().decode("utf-8", errors="ignore").splitlines(),
                    fm_cfg,
                    auxCrashData=aux_data,
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
            with InterProcessLock(str(Path(grz_tmp()) / "fm_sigcache.lock")):
                if collector.sigCacheDir:
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
        if set(crash_info.backtrace) & {
            "std::panicking::rust_panic",
            "std::panicking::rust_panic_with_hook",
        }:
            # rust panic adds 5-6 frames of noise at the top of the stack
            suggested_frames += 6
        return suggested_frames

    @staticmethod
    def _find_ffpuppet_worker(logs):
        """Search through list of log files for a ffpuppet worker log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
        """
        found = None
        for fname in (x for x in logs if "ffp_worker" in x):
            if found is not None:
                # we only expect one log here...
                LOG.warning("overwriting previously selected %r", found)
            found = fname
        return found

    @staticmethod
    def _find_minidump(logs):
        """Search through list of log files for a minidump log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
        """
        re_dump_req = re_compile(
            r"\d+\|0\|.+?\|google_breakpad::ExceptionHandler::WriteMinidump"
        )
        for fname in (x for x in logs if "minidump" in x):
            with open(fname, "r") as log_fp:
                data = log_fp.read(65536)
                # this will select log that contains "Crash|SIGSEGV|" or
                # the desired "DUMP_REQUESTED" log
                # TODO: review this it may be too strict
                # see mozilla-central/source/accessible/ipc/DocAccessibleParent.cpp#452
                if "Crash|DUMP_REQUESTED|" not in data or re_dump_req.search(data):
                    return fname
        return None

    @staticmethod
    def _find_sanitizer(logs):
        """Search through list of log files for a sanitizer (ASan, UBSan, etc...) log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
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
        for fname in (x for x in logs if "asan" in x):
            with open(fname, "r") as log_fp:
                data = log_fp.read(65536)
            # look for interesting crash info in the log
            if "==ERROR:" in data or "WARNING:" in data:
                # check for e10s forced crash
                if re_e10s_forced.search(data) is not None:
                    continue
                # make sure there is something that looks like a stack frame
                if "#0 " in data:
                    found = fname
                    if any(x in data for x in prioritize_tokens):
                        # this is the likely cause of the crash
                        break
            if found is None:
                # UBSan error (non-ASan builds)
                if ": runtime error: " in data:
                    found = fname
                # catch all (choose the one with info for now)
                elif data:
                    fallback = fname
        return found or fallback

    @staticmethod
    def _find_valgrind(logs):
        """Search through list of log files for a Valgrind worker log.

        Args:
            logs (list(str)): List of log files to search.

        Returns:
            str: The full file path if a match is found otherwise None.
        """
        for fname in (x for x in logs if "valgrind" in x):
            if stat(fname).st_size:
                return fname
        return None

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
            str: Name of log.
        """
        return self._logs.aux or self._logs.stderr

    @classmethod
    def select_logs(cls, path):
        """Scan path for file containing stderr, stdout and other (aux)
        data and build a LogMap.

        Args:
            path (str): Path to scan for log files.

        Returns:
            LogMap: A LogMap pointing to log files or None if path is empty.
        """
        files = (x for x in scandir(path=path) if x.is_file())
        # order by date hopefully the oldest log is the cause of the issue
        to_scan = [x.path for x in sorted(files, key=lambda x: x.stat().st_mtime)]
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
        for fname in to_scan:
            if "stderr" in fname:
                log_err = fname
            elif "stdout" in fname:
                log_out = fname
        result = LogMap(log_aux, log_err, log_out)
        return result if any(result) else None

    @staticmethod
    def tail(in_file, size_limit):
        """Tail the given file. WARNING: This is destructive!

        Args:
            in_file (str): Path to file to work with.
            size_limit (int): Maximum size of file after tail operation.

        Returns:
            None
        """
        assert size_limit > 0
        with open(in_file, "rb") as in_fp:
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
        unlink(in_file)
        move(out_file, in_file)
