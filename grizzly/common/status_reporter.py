#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from __future__ import annotations

from abc import ABC, abstractmethod
from argparse import ArgumentParser
from collections import defaultdict
from dataclasses import astuple, fields
from datetime import timedelta
from functools import partial
from itertools import zip_longest
from logging import DEBUG, INFO, basicConfig, getLogger
from mmap import ACCESS_READ, mmap
from os import getenv
from pathlib import Path
from platform import system
from re import match
from time import gmtime, localtime, strftime
from typing import Callable, Generator, Iterable

from psutil import cpu_count, cpu_percent, disk_usage, getloadavg, virtual_memory

from .status import (
    REPORT_RATE,
    STATUS_DB_FUZZ,
    STATUS_DB_REDUCE,
    ReadOnlyStatus,
    ReductionStatus,
    ReductionStep,
)

__all__ = ("StatusReporter",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class TracebackReport:
    """Read Python tracebacks from log files and store it in a manner that is helpful
    when generating reports.
    """

    MAX_LINES = 16  # should be no less than 6
    READ_LIMIT = 0x20000  # 128KB

    def __init__(
        self,
        log_file: Path,
        lines: list[str],
        is_kbi: bool = False,
        prev_lines: list[str] | None = None,
    ) -> None:
        self.is_kbi = is_kbi
        self.lines = lines
        self.log_file = log_file
        self.prev_lines = prev_lines or []

    @classmethod
    def from_file(
        cls, log_file: Path, max_preceding: int = 5, ignore_kbi: bool = False
    ) -> TracebackReport | None:
        """Create TracebackReport from a text file containing a Python traceback.
        Only the first traceback in the file will be parsed.

        Args:
            log_file: File to parse.
            max_preceding: Number of lines to collect leading up to the traceback.
            ignore_kbi: Skip/ignore KeyboardInterrupt.

        Returns:
            TracebackReport containing data from given log file.
        """
        token = b"Traceback (most recent call last):"
        assert len(token) < cls.READ_LIMIT
        try:
            with log_file.open("rb") as lfp:
                with mmap(lfp.fileno(), 0, access=ACCESS_READ) as lmm:
                    idx = lmm.find(token)
                    if idx == -1:
                        # no traceback here, move along
                        return None
                    # seek back 2KB to collect preceding lines
                    lmm.seek(max(idx - len(token) - 2048, 0))
                    data = lmm.read(cls.READ_LIMIT)
        except (OSError, ValueError):  # pragma: no cover
            # OSError: in case the file goes away
            # ValueError: cannot mmap an empty file on Windows
            return None

        data_lines = data.decode("ascii", errors="ignore").splitlines()
        token_str = token.decode()
        is_kbi = False
        tb_start = None
        tb_end = None
        line_count = len(data_lines)
        for line_num, log_line in enumerate(data_lines):
            if tb_start is None and token_str in log_line:
                tb_start = line_num
                continue
            if tb_start is not None:
                log_line = log_line.strip()
                if not log_line:
                    # stop at first empty line
                    tb_end = min(line_num, line_count)
                    break
                if match(r"^\w+(\.\w+)*\:\s|^\w+(Interrupt|Error)$", log_line):
                    is_kbi = log_line.startswith("KeyboardInterrupt")
                    if is_kbi and ignore_kbi:
                        # ignore this exception since it is a KeyboardInterrupt
                        return None
                    # stop after error message
                    tb_end = min(line_num + 1, line_count)
                    break
        assert tb_start is not None
        if max_preceding > 0:
            prev_start = max(tb_start - max_preceding, 0)
            prev_lines = data_lines[prev_start:tb_start]
        else:
            prev_lines = None
        if tb_end is None:
            # limit if the end is not identified (failsafe)
            tb_end = max(line_count, cls.MAX_LINES)
        if tb_end - tb_start > cls.MAX_LINES:
            # add first entry
            lines = data_lines[tb_start : tb_start + 3]
            lines += ["<--- TRACEBACK TRIMMED--->"]
            # add end entries
            lines += data_lines[tb_end - (cls.MAX_LINES - 3) : tb_end]
        else:
            lines = data_lines[tb_start:tb_end]
        return cls(log_file, lines, is_kbi=is_kbi, prev_lines=prev_lines)

    def __len__(self) -> int:
        return len(str(self))

    def __str__(self) -> str:
        return "\n".join(
            [f"Log: '{self.log_file.name}'", *self.prev_lines, *self.lines]
        )


class BaseReporter(ABC):
    # summary output must be no more than 4KB
    SUMMARY_LIMIT = 4096

    @staticmethod
    def _format_entries(entries: list[tuple[str, str | None]]) -> str:
        """Generate formatted output from (label, body) pairs.
        Each entry must have a label and an optional body.

        Example:
        entries = (
            ("Test data output", None),
            ("first", "1"),
            ("second", "2"),
            ("third", "3.0"),
        )
        Will generate...
        Test data output
         first : 1
        second : 2
         third : 3.0

        Args:
            entries: Data to merge.

        Returns:
            Formatted output.
        """
        label_lengths = tuple(len(x[0]) for x in entries if x[1])
        max_len = max(label_lengths) if label_lengths else 0
        out = []
        for label, body in entries:
            if body is None:
                out.append(label)
            else:
                out.append(f"{label}".rjust(max_len) + f" : {body}")
        return "\n".join(out)

    @staticmethod
    def _merge_tracebacks(tracebacks: list[TracebackReport], size_limit: int) -> str:
        """Merge traceback without exceeding size_limit.

        Args:
            tracebacks: TracebackReports to merge.
            size_limit: Maximum size in bytes of output.

        Returns:
            Merged tracebacks.
        """
        txt = []
        txt.append(f"\n\nWARNING Tracebacks ({len(tracebacks)}) detected!")
        tb_size = len(txt[-1])
        for tbr in tracebacks:
            tb_size += len(tbr) + 1
            if tb_size > size_limit:
                break
            txt.append(str(tbr))
        return "\n".join(txt)

    @staticmethod
    def _sys_info() -> list[tuple[str, str]]:
        """Collect system information.

        Args:
            None

        Returns:
            System information.
        """
        entries: list[tuple[str, str]] = []

        # CPU and load
        disp: list[str] = []
        disp.append(
            f"{cpu_count(logical=True)} ({cpu_count(logical=False)}) @ "
            # use minimum interval=0.1 for accuracy
            f"{cpu_percent(interval=0.25):0.0f}%"
        )
        # getloadavg() on Windows does not return anything useful in this case
        # https://psutil.readthedocs.io/en/latest/#psutil.getloadavg
        if system() != "Windows":
            disp.append(" (")
            # round the results of getloadavg(), precision varies across platforms
            disp.append(", ".join(f"{x:0.1f}" for x in getloadavg()))
            disp.append(")")
        entries.append(("CPU & Load", "".join(disp)))

        # memory usage
        disp = []
        mem_usage = virtual_memory()
        if mem_usage.available < 1_073_741_824:  # < 1GB
            disp.append(f"{mem_usage.available // 1_048_576}MB")
        else:
            disp.append(f"{mem_usage.available / 1_073_741_824:0.1f}GB")
        disp.append(f" of {mem_usage.total / 1_073_741_824:0.1f}GB free")
        entries.append(("Memory", "".join(disp)))

        # disk usage
        disp = []
        usage = disk_usage("/")
        if usage.free < 1_073_741_824:  # < 1GB
            disp.append(f"{usage.free // 1_048_576}MB")
        else:
            disp.append(f"{usage.free / 1_073_741_824:0.1f}GB")
        disp.append(f" of {usage.total / 1_073_741_824:0.1f}GB free")
        entries.append(("Disk", "".join(disp)))

        return entries

    @staticmethod
    def _tracebacks(
        path: Path, ignore_kbi: bool = True, max_preceding: int = 5
    ) -> list[TracebackReport]:
        """Search screen logs for tracebacks.

        Args:
            path: Directory containing log files.
            ignore_kbi: Do not include KeyboardInterrupts in results
            max_preceding: Maximum number of lines preceding traceback to include.

        Returns:
            TracebackReports.
        """
        tracebacks = []
        for screen_log in (x for x in path.glob("screenlog.*") if x.is_file()):
            tbr = TracebackReport.from_file(
                screen_log, max_preceding=max_preceding, ignore_kbi=ignore_kbi
            )
            if tbr:
                tracebacks.append(tbr)
        return tracebacks

    @property
    @abstractmethod
    def has_results(self) -> bool:
        pass

    @classmethod
    @abstractmethod
    def load(
        cls, db_file: Path, tb_path: Path | None = None, time_limit: float = 120
    ) -> BaseReporter:
        pass

    @abstractmethod
    def results(self, max_len: int = 85) -> str:
        """Merged and generate formatted output from results.

        Args:
            max_len: Maximum length of result description.

        Returns:
            A formatted report.
        """

    @abstractmethod
    def specific(
        self,
        sysinfo: bool = False,
        timestamp: bool = False,
        iters_per_result: int = 100,
    ) -> str:
        """Merged and generate formatted output from status reports.

        Args:
            iters_per_result: Threshold for warning of potential blockers.

        Returns:
            A formatted report.
        """

    @abstractmethod
    def summary(
        self,
        rate: bool = True,
        runtime: bool = True,
        sysinfo: bool = False,
        timestamp: bool = False,
        iters_per_result: int = 100,
    ) -> str:
        """Merge and generate a summary from status reports.

        Args:
            rate: Include iteration rate.
            runtime: Include total runtime in output.
            sysinfo: Include system info (CPU, disk, RAM... etc) in output.
            timestamp: Include time stamp in output.
            iters_per_result: Threshold for warning of potential blockers.

        Returns:
            A summary of merged reports.
        """


class StatusReporter(BaseReporter):
    """Read and merge Grizzly status reports, including tracebacks if found.
    Output is a single textual report, e.g. for submission to EC2SpotManager.
    """

    DISPLAY_LIMIT_LOG = 10  # don't include log results unless size exceeds 10MBs
    TIME_LIMIT = 120  # ignore older reports

    def __init__(
        self,
        reports: list[ReadOnlyStatus],
        tracebacks: list[TracebackReport] | None = None,
    ) -> None:
        self.reports = reports
        self.tracebacks = tracebacks

    @property
    def has_results(self) -> bool:
        return any(x.results.total for x in self.reports if x.results)

    @classmethod
    def load(
        cls,
        db_file: Path,
        tb_path: Path | None = None,
        time_limit: float = TIME_LIMIT,
    ) -> StatusReporter:
        """Read Grizzly status reports and create a StatusReporter object.

        Args:
            db_file: Status data file to load.
            tb_path: Directory to scan for files containing Python tracebacks.
            time_limit: Only include entries with a timestamp that is within the
                        given number of seconds. Use zero for no limit.

        Returns:
            Available status reports and traceback reports.
        """
        return cls(
            list(ReadOnlyStatus.load_all(db_file, time_limit=time_limit)),
            tracebacks=None if tb_path is None else cls._tracebacks(tb_path),
        )

    def results(self, max_len: int = 85) -> str:
        """Merged and generate formatted output from results.

        Args:
            max_len: Maximum length of result description.

        Returns:
            A formatted report.
        """
        blockers: set[str] = set()
        counts: dict[str, int] = defaultdict(int)
        descs: dict[str, str | None] = {}
        # calculate totals
        for report in self.reports:
            for result in report.results:
                descs[result.rid] = result.desc
                counts[result.rid] += result.count
            blockers.update(x.rid for x in report.results.blockers(report.iteration))
        # generate output
        entries: list[tuple[str, str | None]] = []
        for rid, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            desc = descs[rid]
            assert desc is not None
            # trim long descriptions
            if len(desc) > max_len:
                desc = f"{desc[: max_len - 3]}..."
            label = f"*{count}" if rid in blockers else str(count)
            entries.append((label, desc))
        if not entries:
            entries.append(("No results available", None))
        elif blockers:
            entries.append(("(* = Blocker)", None))
        entries.append(("", None))
        return self._format_entries(entries)

    def specific(
        self,
        sysinfo: bool = False,
        timestamp: bool = False,
        iters_per_result: int = 100,
    ) -> str:
        """Merged and generate formatted output from status reports.

        Args:
            iters_per_result: Threshold for warning of potential blockers.

        Returns:
            A formatted report.
        """
        if not self.reports:
            return "No status reports available"
        self.reports.sort(key=lambda x: x.start_time)
        entries: list[tuple[str, str | None]] = []
        for report in self.reports:
            label = (
                f"PID {report.pid} started at "
                f"{strftime('%Y/%m/%d %X', localtime(report.start_time))}"
            )
            entries.append((label, None))
            # iterations
            entries.append(("Iterations", f"{report.iteration} @ {report.rate:0.2f}"))
            # ignored
            if report.ignored:
                ignore_pct = report.ignored / report.iteration * 100
                entries.append(("Ignored", f"{report.ignored} @ {ignore_pct:0.1f}%"))
            # results
            if report.results.total:
                # avoid divide by zero if results are found before first update
                iters = report.iteration if report.iteration else report.results.total
                result_pct = report.results.total / iters * 100
                if any(
                    report.results.blockers(iters, iters_per_result=iters_per_result)
                ):
                    blkd = " (Blockers detected)"
                else:
                    blkd = ""
                entries.append(
                    (
                        "Results",
                        f"{report.results.total} @ {result_pct:0.1f}%{blkd}",
                    )
                )
            else:
                entries.append(("Results", "0"))
            # runtime
            entries.append(("Runtime", str(timedelta(seconds=int(report.runtime)))))
            # add profiling data if it exists
            if any(report.profile_entries()):
                entries.append(("Profiling entries", None))
                for entry in sorted(
                    report.profile_entries(), key=lambda x: x.total, reverse=True
                ):
                    avg = entry.total / entry.count
                    body = []
                    body.append(f"{entry.count}x ")
                    if entry.total > 300:
                        body.append(str(timedelta(seconds=int(entry.total))))
                    else:
                        body.append(f"{entry.total:0.3f}s")
                    if report.runtime > 0:
                        body.append(f" {entry.total / report.runtime * 100:0.2f}%")
                    body.append(f" ({avg:0.3f} avg,")
                    body.append(f" {entry.max:0.3f} max,")
                    body.append(f" {entry.min:0.3f} min)")
                    entries.append((entry.name, "".join(body)))
            entries.append(("", None))
        return self._format_entries(entries)

    def summary(
        self,
        rate: bool = True,
        runtime: bool = True,
        sysinfo: bool = False,
        timestamp: bool = False,
        iters_per_result: int = 100,
    ) -> str:
        """Merge and generate a summary from status reports.

        Args:
            rate: Include iteration rate.
            runtime: Include total runtime in output.
            sysinfo: Include system info (CPU, disk, RAM... etc) in output.
            timestamp: Include time stamp in output.
            iters_per_result: Threshold for warning of potential blockers.

        Returns:
            A summary of merged reports.
        """
        entries: list[tuple[str, str | None]] = []
        # Job specific status
        if self.reports:
            # calculate totals
            iterations = tuple(x.iteration for x in self.reports)
            log_sizes = tuple(x.log_size for x in self.reports)
            results = tuple(x.results.total for x in self.reports)
            count = len(self.reports)
            total_ignored = sum(x.ignored for x in self.reports)
            total_iters = sum(iterations)

            # Iterations
            disp = [str(total_iters)]
            if count > 1:
                disp.append(f" ({max(iterations)}, {min(iterations)})")
            entries.append(("Iterations", "".join(disp)))

            # Rate
            if rate:
                rates = tuple(x.rate for x in self.reports)
                disp = [f"{count} @ {sum(rates):0.2f}"]
                if count > 1:
                    disp.append(f" ({max(rates):0.2f}, {min(rates):0.2f})")
                entries.append(("Rate", "".join(disp)))
            else:
                entries.append(("Instances", str(count)))

            # Results
            if total_iters:
                total_results = sum(results)
                result_pct = total_results / total_iters * 100
                buckets: set[str] = set()
                for report in self.reports:
                    buckets.update(x.rid for x in report.results)
                disp = [f"{total_results} ({len(buckets)})"]
                if total_results:
                    disp.append(f" @ {result_pct:0.1f}%")
                if any(
                    any(
                        report.results.blockers(
                            report.iteration, iters_per_result=iters_per_result
                        )
                    )
                    for report in self.reports
                    if report.iteration > 0
                ):
                    disp.append(" (Blockers)")
                entries.append(("Results", "".join(disp)))

            # Ignored
            if total_ignored:
                ignore_pct = total_ignored / total_iters * 100
                entries.append(("Ignored", f"{total_ignored} @ {ignore_pct:0.1f}%"))

            # Runtime
            if runtime:
                total_runtime = sum(x.runtime for x in self.reports)
                entries.append(("Runtime", str(timedelta(seconds=int(total_runtime)))))

            # Log size
            log_usage = sum(log_sizes) / 1_048_576
            if log_usage > self.DISPLAY_LIMIT_LOG:
                disp = [f"{log_usage:0.1f}MB"]
                if count > 1:
                    disp.append(
                        f" ({max(log_sizes) / 1_048_576:0.2f}MB, "
                        f"{min(log_sizes) / 1_048_576:0.2f}MB)"
                    )
                entries.append(("Logs", "".join(disp)))
        else:
            entries.append(("No status reports available", None))

        # System information
        if sysinfo:
            entries.extend(self._sys_info())

        # Timestamp
        if timestamp:
            entries.append(("Timestamp", strftime("%Y/%m/%d %X %z", gmtime())))

        # Format output
        msg = self._format_entries(entries)

        if self.tracebacks:
            txt = self._merge_tracebacks(self.tracebacks, self.SUMMARY_LIMIT - len(msg))
            msg = f"{msg}{txt}"
        return msg


class _TableFormatter:
    """Format data in a table."""

    def __init__(
        self,
        column_names: tuple[str, ...],
        formatters: tuple[Callable[..., str] | None, ...],
        vsep: str = " | ",
        hsep: str = "-",
    ) -> None:
        """Initialize a TableFormatter instance.

        Arguments:
            column_names: List of column names for the table header.
            formatters: List of format functions for each column.
                        None will result in hiding that column.
            vsep: Vertical separation between columns.
            hsep: Horizontal separation between header and data.
        """
        assert len(column_names) == len(formatters)
        self._columns = tuple(
            column for (column, fmt) in zip(column_names, formatters) if fmt is not None
        )
        self._formatters = formatters
        self._vsep = vsep
        self._hsep = hsep

    def format_rows(self, rows: Iterable[ReductionStep]) -> Generator[str, None, None]:
        """Format rows as a table and return a line generator.

        Arguments:
            rows: Tabular data. Each row must be the same length as
                  `column_names` passed to `__init__`.

        Yields:
            Each line of formatted tabular data.
        """
        max_width = [len(col) for col in self._columns]
        formatted: list[list[str]] = []
        for row in rows:
            data = astuple(row)
            assert len(data) == len(self._formatters)
            formatted.append([])
            offset = 0
            for idx, (datum, formatter) in enumerate(zip(data, self._formatters)):
                if formatter is None:
                    offset += 1
                    continue
                datum_str = formatter(datum)
                max_width[idx - offset] = max(max_width[idx - offset], len(datum_str))
                formatted[-1].append(datum_str)

        # build a format_str to space out the columns with separators using `max_width`
        # the first column is left-aligned, and other fields are right-aligned.
        format_str = self._vsep.join(
            field % (width,)
            for field, width in zip_longest(["%%-%ds"], max_width, fillvalue="%%%ds")
        )
        yield format_str % self._columns
        yield self._hsep * (len(self._vsep) * (len(self._columns) - 1) + sum(max_width))
        for fmt_row in formatted:
            yield format_str % tuple(fmt_row)


def _format_seconds(duration: float) -> str:
    # format H:M:S, without leading zeros
    minutes, seconds = divmod(int(duration), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    if minutes:
        return f"{minutes}:{seconds:02d}"
    # a bare number is ambiguous. output 's' for seconds
    return f"{seconds}s"


def _format_duration(duration: int | None, total: float = 0) -> str:
    result = ""
    if duration is not None:
        percent = 0 if total == 0 else int(100 * duration / total)
        result = _format_seconds(duration)
        result += f" ({percent:3d}%)"
    return result


def _format_number(number: int | None, total: float = 0) -> str:
    result = ""
    if number is not None:
        percent = 0 if total == 0 else int(100 * number / total)
        result = f"{number:n} ({percent:3d}%)"
    return result


class ReductionStatusReporter(BaseReporter):
    """Create a status report for a reducer instance.
    Merging multiple reports is not possible. This is intended for automated use only.
    """

    TIME_LIMIT = 120  # ignore older reports

    def __init__(
        self,
        reports: list[ReductionStatus],
        tracebacks: list[TracebackReport] | None = None,
    ) -> None:
        self.reports: list[ReductionStatus] = reports
        self.tracebacks = tracebacks

    @property
    def has_results(self) -> bool:
        return False  # TODO

    @classmethod
    def load(
        cls,
        db_file: Path,
        tb_path: Path | None = None,
        time_limit: float = TIME_LIMIT,
    ) -> ReductionStatusReporter:
        """Read Grizzly reduction status reports and create a ReductionStatusReporter
        object.

        Args:
            path: Path to scan for status data files.
            tb_path: Directory to scan for files containing Python tracebacks.
            time_limit: Only include entries with a timestamp that is within the
                        given number of seconds. Use zero for no limit.

        Returns:
            ReductionStatusReporter containing available status reports and traceback
            reports.
        """
        tracebacks = None if tb_path is None else cls._tracebacks(tb_path)
        return cls(
            list(ReductionStatus.load_all(db_file, time_limit=time_limit)),
            tracebacks=tracebacks,
        )

    @staticmethod
    def _analysis_entry(report: ReductionStatus) -> tuple[str, str]:
        return (
            "Analysis",
            ", ".join(
                f"{desc}: {100 * reliability:0.2f}%"
                for desc, reliability in report.analysis.items()
            ),
        )

    @staticmethod
    def _crash_id_entry(report: ReductionStatus) -> tuple[str, str]:
        crash_str = str(report.crash_id)
        if report.tool:
            crash_str += f" ({report.tool})"
        return ("Crash ID", crash_str)

    @staticmethod
    def _last_reports_entry(report: ReductionStatus) -> tuple[str, str]:
        return ("Latest Reports", ", ".join(str(r) for r in report.last_reports))

    @staticmethod
    def _run_params_entry(report: ReductionStatus) -> tuple[str, str]:
        return (
            "Run Parameters",
            ", ".join(
                (f"{desc}: {value!r}") for desc, value in report.run_params.items()
            ),
        )

    @staticmethod
    def _signature_info_entry(report: ReductionStatus) -> tuple[str, str]:
        return (
            "Signature",
            ", ".join(
                (f"{desc}: {value!r}") for desc, value in report.signature_info.items()
            ),
        )

    def results(self, max_len: int = 85) -> str:  # pragma: no cover
        raise NotImplementedError()

    def specific(
        self,
        sysinfo: bool = False,
        timestamp: bool = False,
        iters_per_result: int = 0,
    ) -> str:
        """Generate formatted output from status report.

        Args:
            None

        Returns:
            A formatted report.
        """
        if not self.reports:
            return "No status reports available"

        reports: list[str] = []
        for report in self.reports:
            entries: list[tuple[str, str | None]] = []
            if report.crash_id:
                entries.append(self._crash_id_entry(report))
            if report.analysis:
                entries.append(self._analysis_entry(report))
            if report.run_params:
                entries.append(self._run_params_entry(report))
            if report.last_reports:
                entries.append(self._last_reports_entry(report))
            if report.current_strategy:
                entries.append(
                    (
                        "Current Strategy",
                        f"{report.current_strategy.name} "
                        f"({report.current_strategy_idx!r} of "
                        f"{len(report.strategies) if report.strategies else 0})",
                    )
                )
            if report.current_strategy and report.original:
                # TODO: lines/tokens?
                entries.append(
                    (
                        "Current/Original",
                        f"{report.current_strategy.size}B / {report.original.size}B",
                    )
                )
            if report.total:
                # TODO: other results
                entries.append(
                    (
                        "Results",
                        (
                            f"{report.total.successes} successes,"
                            f" {report.total.attempts} attempts"
                        ),
                    )
                )
            if report.total and report.current_strategy:
                strategy_duration = report.current_strategy.duration or 0
                total_duration = report.total.duration or 0
                entries.append(
                    (
                        "Time Elapsed",
                        f"{_format_seconds(strategy_duration)} in "
                        f"strategy, {_format_seconds(total_duration)} total",
                    )
                )

            # System information
            if sysinfo:
                entries.extend(self._sys_info())

            # Timestamp
            if timestamp:
                entries.append(("Timestamp", strftime("%Y/%m/%d %X %z", gmtime())))

            reports.append(self._format_entries(entries))
        return "\n\n".join(reports)

    def summary(
        self,
        rate: bool = False,
        runtime: bool = False,
        sysinfo: bool = False,
        timestamp: bool = False,
        iters_per_result: int = 0,
    ) -> str:
        """Merge and generate a summary from status reports.

        Args:
            rate: Ignored (compatibility).
            runtime: Ignored (compatibility).
            sysinfo: Include system info (CPU, disk, RAM... etc) in output.
            timestamp: Include time stamp in output.
            iters_per_result: Ignored (compatibility).

        Returns:
            A summary of merged reports.
        """
        if not self.reports:
            return "No status reports available"

        reports: list[str] = []
        for report in self.reports:
            entries: list[tuple[str, str | None]] = []
            lines: list[str] = []
            if report.crash_id:
                entries.append(self._crash_id_entry(report))
            if report.analysis:
                entries.append(self._analysis_entry(report))
            if report.signature_info:
                entries.append(self._signature_info_entry(report))
            if report.run_params:
                entries.append(self._run_params_entry(report))
            if report.last_reports:
                entries.append(self._last_reports_entry(report))
            if report.total and report.original:
                tabulator = _TableFormatter(
                    tuple(f.name for f in fields(ReductionStep)),
                    # this tuple must match the order of fields
                    # defined on ReductionStep!
                    (
                        str,  # name
                        # duration/successes/attempts are % of total/last
                        partial(_format_duration, total=report.total.duration or 0),
                        partial(_format_number, total=report.total.successes or 0),
                        partial(_format_number, total=report.total.attempts or 0),
                        # size is % of init/1st
                        partial(_format_number, total=report.original.size or 0),
                        None,  # iterations (hidden)
                    ),
                )
                lines.extend(tabulator.format_rows(report.finished_steps))
            # Format output
            if entries:
                lines.append(self._format_entries(entries))
            if lines:
                reports.append("\n".join(lines))

        entries = []

        # System information
        if sysinfo:
            entries.extend(self._sys_info())

        # Timestamp
        if timestamp:
            entries.append(("Timestamp", strftime("%Y/%m/%d %X %z", gmtime())))

        if entries:
            reports.append(self._format_entries(entries))

        msg = "\n\n".join(reports)

        if self.tracebacks:
            msg += self._merge_tracebacks(
                self.tracebacks, self.SUMMARY_LIMIT - len(msg)
            )

        return msg


def main(argv: list[str] | None = None) -> int:
    """Merge Grizzly status files into a single report (main entrypoint).

    Args:
        argv: Argument list to parse instead of sys.argv (for testing).

    Returns:
        int
    """
    if bool(getenv("DEBUG")):  # pragma: no cover
        log_level = DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_level = INFO
        log_fmt = "%(message)s"
    basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    # report types: define name and time range of scan
    report_types = {
        # include status reports from the last 2 minutes
        "active": 120,
        # include status reports from the last 8 hours
        "complete": 28800,
    }

    parser = ArgumentParser(description="Grizzly status report generator")
    parser.add_argument(
        "--dump",
        type=Path,
        help="File to write report to, existing files will be overwritten.",
    )
    parser.add_argument(
        "--type",
        choices=report_types.keys(),
        default="active",
        help="Report type. active: Current snapshot of activity, complete: "
        "Aggregate summary of all jobs over a longer duration. (default: %(default)s)",
    )
    parser.add_argument(
        "--scan-mode",
        choices=("fuzzing", "reducing"),
        default="fuzzing",
        help="Scan mode. (default: %(default)s)",
    )
    parser.add_argument(
        "--system-report",
        action="store_true",
        help="Output summary and system information",
    )
    parser.add_argument(
        "--time-limit",
        type=int,
        help="Maximum age of reports in seconds. Use zero for no limit."
        f" (default: {', '.join(f'{k}: {v}' for k, v in report_types.items())})",
    )
    parser.add_argument(
        "--tracebacks",
        type=Path,
        help="Scan path for Python tracebacks found in screenlog.# files",
    )
    args = parser.parse_args(argv)
    if args.tracebacks and not args.tracebacks.is_dir():
        parser.error("--tracebacks must be a directory")

    time_limit = report_types[args.type] if args.time_limit is None else args.time_limit
    if args.scan_mode == "fuzzing":
        reporter: StatusReporter | ReductionStatusReporter = StatusReporter.load(
            STATUS_DB_FUZZ,
            tb_path=args.tracebacks,
            time_limit=time_limit,
        )
    else:
        reporter = ReductionStatusReporter.load(
            STATUS_DB_REDUCE,
            tb_path=args.tracebacks,
            time_limit=time_limit,
        )

    if args.dump:
        with args.dump.open("w") as ofp:
            if args.type == "active" and args.scan_mode == "fuzzing":
                ofp.write(reporter.summary(runtime=False, sysinfo=True, timestamp=True))
            # mode == "fuzzing"
            elif args.type == "active":
                # reducer only has one instance, so show specific report while running
                ofp.write(reporter.specific(sysinfo=True, timestamp=True))
            # type == "complete"
            else:
                ofp.write(reporter.summary(rate=False))
        return 0

    if not reporter.reports:
        LOG.info(
            "Grizzly Status - No status reports to display (time-limit: %s)",
            _format_seconds(time_limit),
        )
        return 0

    LOG.info("Grizzly Status - %s", strftime("%Y/%m/%d %X"))
    LOG.info("Instance report frequency: %s", _format_seconds(REPORT_RATE))
    LOG.info("Time limit filter: %s", _format_seconds(time_limit))
    LOG.info("")
    LOG.info("[Reports]")
    LOG.info(reporter.specific())
    if reporter.has_results:
        LOG.info("[Result Signatures]")
        LOG.info(reporter.results())
    LOG.info("[Summary]")
    LOG.info(reporter.summary(rate=args.type == "active", sysinfo=args.system_report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
