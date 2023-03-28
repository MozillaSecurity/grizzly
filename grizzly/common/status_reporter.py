#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from argparse import ArgumentParser
from collections import defaultdict
from datetime import timedelta
from functools import partial
from itertools import zip_longest
from logging import DEBUG, INFO, basicConfig, getLogger

try:
    from os import getloadavg
except ImportError:  # pragma: no cover
    # os.getloadavg() is not available on all platforms
    getloadavg = None
from os import SEEK_CUR, getenv
from pathlib import Path
from re import match
from re import sub as re_sub
from time import gmtime, localtime, strftime

from psutil import cpu_count, cpu_percent, disk_usage, virtual_memory

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


class StatusReporter:
    """Read and merge Grizzly status reports, including tracebacks if found.
    Output is a single textual report, e.g. for submission to EC2SpotManager.
    """

    CPU_POLL_INTERVAL = 1
    DISPLAY_LIMIT_LOG = 10  # don't include log results unless size exceeds 10MBs
    READ_BUF_SIZE = 0x10000  # 64KB
    SUMMARY_LIMIT = 4095  # summary output must be no more than 4KB
    TIME_LIMIT = 120  # ignore older reports

    def __init__(self, reports, tracebacks=None):
        self.reports = reports
        self.tracebacks = tracebacks

    @property
    def has_results(self):
        return any(x.results.total for x in self.reports)

    @classmethod
    def load(cls, db_file, tb_path=None, time_limit=TIME_LIMIT):
        """Read Grizzly status reports and create a StatusReporter object.

        Args:
            db_file (str): Status data file to load.
            tb_path (Path): Directory to scan for files containing Python tracebacks.
            time_limit (int): Only include entries with a timestamp that is within the
                              given number of seconds.

        Returns:
            StatusReporter: Contains available status reports and traceback reports.
        """
        return cls(
            list(ReadOnlyStatus.load_all(db_file, time_limit=time_limit)),
            tracebacks=None if tb_path is None else cls._tracebacks(tb_path),
        )

    @staticmethod
    def format_entries(entries):
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
            entries list(2-tuple(str, str)): Data to merge.

        Returns:
            str: Formatted output.
        """
        label_lengths = tuple(len(x[0]) for x in entries if x[1])
        max_len = max(label_lengths) if label_lengths else 0
        out = []
        for label, body in entries:
            if body:
                out.append(f"{label}".rjust(max_len) + f" : {body}")
            else:
                out.append(label)
        return "\n".join(out)

    def results(self, max_len=85):
        """Merged and generate formatted output from results.

        Args:
            max_len (int): Maximum length of result description.

        Returns:
            str: A formatted report.
        """
        blockers = set()
        counts = defaultdict(int)
        descs = {}
        # calculate totals
        for report in self.reports:
            for result in report.results:
                descs[result.rid] = result.desc
                counts[result.rid] += result.count
            blockers.update(x.rid for x in report.results.blockers(report.iteration))
        # generate output
        entries = []
        for rid, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            desc = descs[rid]
            # trim long descriptions
            if len(descs[rid]) > max_len:
                desc = f"{desc[: max_len - 3]}..."
            label = f"*{count}" if rid in blockers else str(count)
            entries.append((label, desc))
        if not entries:
            entries.append(("No results available", None))
        elif blockers:
            entries.append(("(* = Blocker)", None))
        entries.append(("", None))
        return self.format_entries(entries)

    def specific(self, iters_per_result=100):
        """Merged and generate formatted output from status reports.

        Args:
            iters_per_result (int): Threshold for warning of potential blockers.

        Returns:
            str: A formatted report.
        """
        if not self.reports:
            return "No status reports available"
        self.reports.sort(key=lambda x: x.start_time)
        entries = []
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
                    body.append(f" {entry.total / report.runtime * 100:0.2f}%")
                    body.append(f" ({avg:0.3f} avg,")
                    body.append(f" {entry.max:0.3f} max,")
                    body.append(f" {entry.min:0.3f} min)")
                    entries.append((entry.name, "".join(body)))
            entries.append(("", None))
        return self.format_entries(entries)

    def summary(
        self,
        rate=True,
        runtime=True,
        sysinfo=False,
        timestamp=False,
        iters_per_result=100,
    ):
        """Merge and generate a summary from status reports.

        Args:
            runtime (bool): Include total runtime in output.
            sysinfo (bool): Include system info (CPU, disk, RAM... etc) in output.
            timestamp (bool): Include time stamp in output.
            iters_per_result (int): Threshold for warning of potential blockers.

        Returns:
            str: A summary of merged reports.
        """
        entries = []
        # Job specific status
        if self.reports:
            # calculate totals
            iterations = tuple(x.iteration for x in self.reports)
            log_sizes = tuple(x.log_size for x in self.reports)
            rates = tuple(x.rate for x in self.reports)
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
                disp = [f"{count} @ {sum(rates):0.2f}"]
                if count > 1:
                    disp.append(f" ({max(rates):0.2f}, {min(rates):0.2f})")
                entries.append(("Rate", "".join(disp)))

            # Results
            if total_iters:
                total_results = sum(results)
                result_pct = total_results / total_iters * 100
                buckets = set()
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
        msg = self.format_entries(entries)

        if self.tracebacks:
            txt = self._merge_tracebacks(self.tracebacks, self.SUMMARY_LIMIT - len(msg))
            msg = "".join((msg, txt))
        return msg

    @staticmethod
    def _merge_tracebacks(tracebacks, size_limit):
        """Merge traceback without exceeding size_limit.

        Args:
            tracebacks (iterable): TracebackReport to merge.
            size_limit (int): Maximum size in bytes of output.

        Returns:
            str: merged tracebacks.
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
    def _sys_info():
        """Collect system information.

        Args:
            None

        Returns:
            list(tuple): System information in tuples (label, display data).
        """
        entries = []

        # CPU and load
        disp = []
        disp.append(
            f"{cpu_count(logical=True)} ({cpu_count(logical=False)}) @ "
            f"{cpu_percent(interval=StatusReporter.CPU_POLL_INTERVAL):0.0f}%"
        )
        if getloadavg is not None:
            disp.append(" (")
            # round the results of getloadavg(), precision varies across platforms
            disp.append(", ".join(f"{x:0.1f}" for x in getloadavg()))
            disp.append(")")
        entries.append(("CPU & Load", "".join(disp)))

        # memory usage
        disp = []
        mem_usage = virtual_memory()
        if mem_usage.available < 1_073_741_824:  # < 1GB
            disp.append(f"{int(mem_usage.available / 1_048_576)}MB")
        else:
            disp.append(f"{mem_usage.available / 1_073_741_824:0.1f}GB")
        disp.append(f" of {mem_usage.total / 1_073_741_824:0.1f}GB free")
        entries.append(("Memory", "".join(disp)))

        # disk usage
        disp = []
        usage = disk_usage("/")
        if usage.free < 1_073_741_824:  # < 1GB
            disp.append(f"{int(usage.free / 1_048_576)}MB")
        else:
            disp.append(f"{usage.free / 1_073_741_824:0.1f}GB")
        disp.append(f" of {usage.total / 1_073_741_824:0.1f}GB free")
        entries.append(("Disk", "".join(disp)))

        return entries

    @staticmethod
    def _tracebacks(path, ignore_kbi=True, max_preceding=5):
        """Search screen logs for tracebacks.

        Args:
            path (Path): Directory containing log files.
            ignore_kbi (bool): Do not include KeyboardInterrupts in results
            max_preceding (int): Maximum number of lines preceding traceback to
                                  include.

        Returns:
            list: A list of TracebackReports.
        """
        tracebacks = []
        for screen_log in (x for x in path.glob("screenlog.*") if x.is_file()):
            tbr = TracebackReport.from_file(
                screen_log, max_preceding=max_preceding, ignore_kbi=ignore_kbi
            )
            if tbr:
                tracebacks.append(tbr)
        return tracebacks


class TracebackReport:
    """Read Python tracebacks from log files and store it in a manner that is helpful
    when generating reports.
    """

    MAX_LINES = 16  # should be no less than 6
    READ_LIMIT = 0x20000  # 128KB

    def __init__(self, log_file, lines, is_kbi=False, prev_lines=None):
        assert isinstance(lines, list)
        assert isinstance(log_file, Path)
        assert isinstance(prev_lines, list) or prev_lines is None
        self.is_kbi = is_kbi
        self.lines = lines
        self.log_file = log_file
        self.prev_lines = prev_lines or []

    @classmethod
    def from_file(cls, log_file, max_preceding=5, ignore_kbi=False):
        """Create TracebackReport from a text file containing a Python traceback.
        Only the first traceback in the file will be parsed.

        Args:
            log_file (Path): File to parse.
            max_preceding (int): Number of lines to collect leading up to the traceback.
            ignore_kbi (bool): Skip/ignore KeyboardInterrupt.

        Returns:
            TracebackReport: Contains data from log_file.
        """
        token = b"Traceback (most recent call last):"
        assert len(token) < cls.READ_LIMIT
        try:
            with log_file.open("rb") as in_fp:
                for chunk in iter(partial(in_fp.read, cls.READ_LIMIT), b""):
                    idx = chunk.find(token)
                    if idx > -1:
                        # calculate offset of data in the file
                        pos = in_fp.tell() - len(chunk) + idx
                        break
                    if len(chunk) == cls.READ_LIMIT:
                        # seek back to avoid missing beginning of token
                        in_fp.seek(len(token) * -1, SEEK_CUR)
                else:
                    # no traceback here, move along
                    return None
                # seek back 2KB to collect preceding lines
                in_fp.seek(max(pos - 2048, 0))
                data = in_fp.read(cls.READ_LIMIT)
        except OSError:  # pragma: no cover
            # in case the file goes away
            return None

        data = data.decode("ascii", errors="ignore").splitlines()
        token = token.decode()
        is_kbi = False
        tb_start = None
        tb_end = None
        line_count = len(data)
        for line_num, log_line in enumerate(data):
            if tb_start is None and token in log_line:
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
            prev_lines = data[prev_start:tb_start]
        else:
            prev_lines = None
        if tb_end is None:
            # limit if the end is not identified (failsafe)
            tb_end = max(line_count, cls.MAX_LINES)
        if tb_end - tb_start > cls.MAX_LINES:
            # add first entry
            lines = data[tb_start : tb_start + 3]
            lines += ["<--- TRACEBACK TRIMMED--->"]
            # add end entries
            lines += data[tb_end - (cls.MAX_LINES - 3) : tb_end]
        else:
            lines = data[tb_start:tb_end]
        return cls(log_file, lines, is_kbi=is_kbi, prev_lines=prev_lines)

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return "\n".join(
            [f"Log: '{self.log_file.name}'"] + self.prev_lines + self.lines
        )


class _TableFormatter:
    """Format data in a table."""

    def __init__(self, columns, formatters, vsep=" | ", hsep="-"):
        """Initialize a TableFormatter instance.

        Arguments:
            columns (iterable(str)): List of column names for the table header.
            formatters (iterable(callable)): List of format functions for each column.
                                             None will result in hiding that column.
            vsep (str): Vertical separation between columns.
            hsep (str): Horizontal separation between header and data.
        """
        assert len(columns) == len(formatters)
        self._columns = tuple(
            column for (column, fmt) in zip(columns, formatters) if fmt is not None
        )
        self._formatters = formatters
        self._vsep = vsep
        self._hsep = hsep

    def format_rows(self, rows):
        """Format rows as a table and return a line generator.

        Arguments:
            rows (list(list(str))): Tabular data. Each row must be the same length as
                                    `columns` passed to `__init__`.

        Yields:
            str: Each line of formatted tabular data.
        """
        max_width = [len(col) for col in self._columns]
        formatted = []
        for row in rows:
            assert len(row) == len(self._formatters)
            formatted.append([])
            offset = 0
            for idx, (data, formatter) in enumerate(zip(row, self._formatters)):
                if formatter is None:
                    offset += 1
                    continue
                data = formatter(data)
                max_width[idx - offset] = max(max_width[idx - offset], len(data))
                formatted[-1].append(data)

        # build a format_str to space out the columns with separators using `max_width`
        # the first column is left-aligned, and other fields are right-aligned.
        format_str = self._vsep.join(
            field % (width,)
            for field, width in zip_longest(["%%-%ds"], max_width, fillvalue="%%%ds")
        )
        yield format_str % self._columns
        yield self._hsep * (len(self._vsep) * (len(self._columns) - 1) + sum(max_width))
        for row in formatted:
            yield format_str % tuple(row)


def _format_seconds(duration):
    # format H:M:S, and then remove all leading zeros with regex
    minutes, seconds = divmod(int(duration), 60)
    hours, minutes = divmod(minutes, 60)
    result = re_sub("^[0:]*", "", f"{hours}:{minutes:0>2d}:{seconds:0>2d}")
    # if the result is all zeroes, ensure one zero is output
    if not result:
        result = "0"
    # a bare number is ambiguous. output 's' for seconds
    if ":" not in result:
        result += "s"
    return result


def _format_duration(duration, total=0):
    result = ""
    if duration is not None:
        if total == 0:
            percent = 0  # pragma: no cover
        else:
            percent = int(100 * duration / total)
        result = _format_seconds(duration)
        result += f" ({percent:>3d}%)"
    return result


def _format_number(number, total=0):
    result = ""
    if number is not None:
        if total == 0:
            percent = 0
        else:
            percent = int(100 * number / total)
        result = f"{number:n} ({percent:3d}%)"
    return result


class ReductionStatusReporter(StatusReporter):
    """Create a status report for a reducer instance.
    Merging multiple reports is not possible. This is intended for automated use only.
    """

    TIME_LIMIT = 120  # ignore older reports

    # pylint: disable=super-init-not-called
    def __init__(self, reports, tracebacks=None):
        self.reports = reports
        self.tracebacks = tracebacks

    @property
    def has_results(self):
        return False  # TODO

    @classmethod
    def load(cls, db_file, tb_path=None, time_limit=TIME_LIMIT):
        """Read Grizzly reduction status reports and create a ReductionStatusReporter
        object.

        Args:
            path (str): Path to scan for status data files.
            tb_path (str): Directory to scan for files containing Python tracebacks.
            time_limit (int): Only include entries with a timestamp that is within the
                              given number of seconds.

        Returns:
            ReductionStatusReporter: Contains available status reports and traceback
                                     reports.
        """
        tracebacks = None if tb_path is None else cls._tracebacks(tb_path)
        return cls(
            list(ReductionStatus.load_all(db_file, time_limit=time_limit)),
            tracebacks=tracebacks,
        )

    @staticmethod
    def _analysis_entry(report):
        return (
            "Analysis",
            ", ".join(
                f"{desc}: {100 * reliability:0.2f}%"
                for desc, reliability in report.analysis.items()
            ),
        )

    @staticmethod
    def _crash_id_entry(report):
        crash_str = str(report.crash_id)
        if report.tool:
            crash_str += f" ({report.tool})"
        return ("Crash ID", crash_str)

    @staticmethod
    def _last_reports_entry(report):
        return ("Latest Reports", ", ".join(str(r) for r in report.last_reports))

    @staticmethod
    def _run_params_entry(report):
        return (
            "Run Parameters",
            ", ".join(
                (f"{desc}: {value!r}") for desc, value in report.run_params.items()
            ),
        )

    @staticmethod
    def _signature_info_entry(report):
        return (
            "Signature",
            ", ".join(
                (f"{desc}: {value!r}") for desc, value in report.signature_info.items()
            ),
        )

    def specific(
        self,
        sysinfo=False,
        timestamp=False,
    ):  # pylint: disable=arguments-renamed
        """Generate formatted output from status report.

        Args:
            None

        Returns:
            str: A formatted report.
        """
        if not self.reports:
            return "No status reports available"

        reports = []
        for report in self.reports:
            entries = []
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
                        f"{len(report.strategies)})",
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
                entries.append(
                    (
                        "Time Elapsed",
                        f"{_format_seconds(report.current_strategy.duration)} in "
                        f"strategy, {_format_seconds(report.total.duration)} total",
                    )
                )

            # System information
            if sysinfo:
                entries.extend(self._sys_info())

            # Timestamp
            if timestamp:
                entries.append(("Timestamp", strftime("%Y/%m/%d %X %z", gmtime())))

            reports.append(self.format_entries(entries))
        return "\n\n".join(reports)

    def summary(
        self,
        rate=False,
        runtime=False,
        sysinfo=False,
        timestamp=False,
    ):  # pylint: disable=arguments-differ
        """Merge and generate a summary from status reports.

        Args:
            rate (bool): Ignored (compatibility).
            runtime (bool): Ignored (compatibility).
            sysinfo (bool): Include system info (CPU, disk, RAM... etc) in output.
            timestamp (bool): Include time stamp in output.

        Returns:
            str: A summary of merged reports.
        """
        if not self.reports:
            return "No status reports available"

        reports = []
        for report in self.reports:
            entries = []
            lines = []
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
                    ReductionStep._fields,
                    ReductionStep(
                        name=str,
                        # duration and attempts are % of total/last, size % of init/1st
                        duration=partial(_format_duration, total=report.total.duration),
                        attempts=partial(_format_number, total=report.total.attempts),
                        successes=partial(_format_number, total=report.total.successes),
                        iterations=None,  # hide
                        size=partial(_format_number, total=report.original.size),
                    ),
                )
                lines.extend(tabulator.format_rows(report.finished_steps))
            # Format output
            if entries:
                lines.append(self.format_entries(entries))
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
            reports.append(self.format_entries(entries))

        msg = "\n\n".join(reports)

        if self.tracebacks:
            msg += self._merge_tracebacks(
                self.tracebacks, self.SUMMARY_LIMIT - len(msg)
            )

        return msg


def main(args=None):
    """Merge Grizzly status files into a single report (main entrypoint).

    Args:
        args (list/None): Argument list to parse instead of sys.argv (for testing).

    Returns:
        None
    """
    if bool(getenv("DEBUG")):  # pragma: no cover
        log_level = DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_level = INFO
        log_fmt = "%(message)s"
    basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    modes = {
        "fuzzing": (StatusReporter, STATUS_DB_FUZZ),
        "reducing": (ReductionStatusReporter, STATUS_DB_REDUCE),
    }

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
        "Aggregate summary of all jobs over a longer duration (8h). "
        "(default: %(default)s)",
    )
    parser.add_argument(
        "--scan-mode",
        choices=modes.keys(),
        default="fuzzing",
        help="Report mode. (default: %(default)s)",
    )
    parser.add_argument(
        "--system-report",
        action="store_true",
        help="Output summary and system information",
    )
    parser.add_argument(
        "--tracebacks",
        type=Path,
        help="Scan path for Python tracebacks found in screenlog.# files",
    )
    args = parser.parse_args(args)
    if args.tracebacks and not args.tracebacks.is_dir():
        parser.error("--tracebacks must be a directory")

    reporter_cls, status_db = modes.get(args.scan_mode)
    reporter = reporter_cls.load(
        status_db,
        tb_path=args.tracebacks,
        time_limit=report_types[args.type],
    )

    if args.dump:
        with args.dump.open("w") as ofp:
            if args.type == "active" and args.scan_mode == "fuzzing":
                ofp.write(reporter.summary(runtime=False, sysinfo=True, timestamp=True))
            elif args.type == "active":
                # reducer only has one instance, so show specific report while running
                ofp.write(reporter.specific(sysinfo=True, timestamp=True))
            else:
                ofp.write(
                    reporter.summary(
                        rate=False, runtime=True, sysinfo=False, timestamp=False
                    )
                )
        return 0

    if not reporter.reports:
        LOG.info("Grizzly Status - No status reports to display")
        return 0

    LOG.info(
        "Grizzly Status - %s - Instance report frequency: %ds\n",
        strftime("%Y/%m/%d %X"),
        REPORT_RATE,
    )
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
