#!/usr/bin/env python
# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from argparse import ArgumentParser
from collections import defaultdict
from datetime import timedelta
from functools import partial
from itertools import zip_longest
from logging import DEBUG, INFO, basicConfig

try:
    from os import getloadavg
except ImportError:  # pragma: no cover
    # os.getloadavg() is not available on all platforms
    getloadavg = None
from os import SEEK_CUR, getenv, scandir
from os.path import isdir
from re import match
from re import sub as re_sub
from time import gmtime, localtime, strftime

from psutil import cpu_count, cpu_percent, disk_usage, virtual_memory

from .status import ReductionStatus, ReductionStep, Status

__all__ = ("StatusReporter",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


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
            path (str): Path to scan for status data files.
            tb_path (str): Directory to scan for files containing Python tracebacks.
            time_limit (int): Only include entries with a timestamp that is within the
                              given number of seconds.

        Returns:
            StatusReporter: Contains available status reports and traceback reports.
        """
        tracebacks = None if tb_path is None else cls._tracebacks(tb_path)
        return cls(
            list(Status.loadall(db_file=db_file, time_limit=time_limit)),
            tracebacks=tracebacks,
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
        out = list()
        for label, body in entries:
            if body:
                out.append(
                    "%s%s : %s" % ((" " * max(max_len - len(label), 0), label, body))
                )
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
        descs = dict()
        # calculate totals
        for report in self.reports:
            for result in report.results.all():
                descs[result.rid] = result.desc
                counts[result.rid] += result.count
            blockers.update(x.rid for x in report.blockers())
        # generate output
        entries = list()
        for rid, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            desc = descs[rid]
            # trim long descriptions
            if len(descs[rid]) > max_len:
                desc = "%s..." % (desc[: max_len - 3],)
            label = "%s%d" % ("*" if rid in blockers else "", count)
            entries.append((label, desc))
        if not entries:
            entries.append(("No results available", None))
        elif blockers:
            entries.append(("(* = Blocker)", None))
        entries.append(("", None))
        return self.format_entries(entries)

    @staticmethod
    def _scan(path, fname_pattern):
        for entry in scandir(path):
            if match(fname_pattern, entry.name) is None:
                continue
            if not entry.is_file():
                continue
            if entry.stat().st_size:
                yield entry.path

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
        entries = list()
        for report in self.reports:
            label = "PID %d started at %s" % (
                report.pid,
                strftime("%Y/%m/%d %X", localtime(report.start_time)),
            )
            entries.append((label, None))
            # iterations
            entries.append(
                ("Iterations", "%d @ %0.2f" % (report.iteration, round(report.rate, 2)))
            )
            # ignored
            if report.ignored:
                ignore_pct = report.ignored / float(report.iteration) * 100
                entries.append(
                    (
                        "Ignored",
                        "%d @ %0.1f%%" % (report.ignored, round(ignore_pct, 1)),
                    )
                )
            # results
            if report.results.total:
                # avoid divide by zero if results are found before first update
                iters = report.iteration if report.iteration else report.results.total
                result_pct = report.results.total / float(iters) * 100
                if any(report.blockers(iters_per_result=iters_per_result)):
                    blk_str = " (Blockers detected)"
                else:
                    blk_str = ""
                entries.append(
                    (
                        "Results",
                        "%d @ %0.1f%% %s"
                        % (report.results.total, round(result_pct, 1), blk_str),
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
                    avg = entry.total / float(entry.count)
                    body = list()
                    body.append("%dx " % (entry.count,))
                    if entry.total > 300:
                        body.append(str(timedelta(seconds=int(entry.total))))
                    else:
                        body.append("%0.3fs" % (round(entry.total, 3),))
                    body.append(
                        " %0.2f%%" % (round(entry.total / report.runtime * 100, 2),)
                    )
                    body.append(" (%0.3f avg," % (round(avg, 3),))
                    body.append(" %0.3f max," % (round(entry.max, 3),))
                    body.append(" %0.3f min)" % (round(entry.min, 3),))
                    entries.append((entry.name, "".join(body)))
            entries.append(("", None))
        return self.format_entries(entries)

    def summary(
        self, runtime=True, sysinfo=False, timestamp=False, iters_per_result=100
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
        entries = list()
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
            disp = list()
            disp.append(str(total_iters))
            if count > 1:
                disp.append(" (%d, %d)" % (max(iterations), min(iterations)))
            entries.append(("Iterations", "".join(disp)))

            # Rate
            disp = list()
            disp.append("%d @ %0.2f" % (count, round(sum(rates), 2)))
            if count > 1:
                disp.append(
                    " (%0.2f, %0.2f)" % (round(max(rates), 2), round(min(rates), 2))
                )
            entries.append(("Rate", "".join(disp)))

            # Results
            if total_iters:
                total_results = sum(results)
                result_pct = total_results / float(total_iters) * 100
                disp = list()
                disp.append("%d" % (total_results,))
                if total_results:
                    disp.append(" @ %0.1f%%" % (round(result_pct, 1),))
                if any(
                    any(x.blockers(iters_per_result=iters_per_result))
                    for x in self.reports
                ):
                    disp.append(" (Blockers)")
                entries.append(("Results", "".join(disp)))

            # Ignored
            if total_ignored:
                ignore_pct = total_ignored / float(total_iters) * 100
                entries.append(
                    ("Ignored", "%d @ %0.1f%%" % (total_ignored, round(ignore_pct, 1)))
                )

            # Runtime
            if runtime:
                total_runtime = sum(x.runtime for x in self.reports)
                entries.append(("Runtime", str(timedelta(seconds=int(total_runtime)))))

            # Log size
            log_usage = sum(log_sizes) / 1_048_576.0
            if log_usage > self.DISPLAY_LIMIT_LOG:
                disp = list()
                disp.append("%0.1fMB" % (log_usage,))
                if count > 1:
                    disp.append(
                        " (%0.2fMB, %0.2fMB)"
                        % (max(log_sizes) / 1_048_576.0, min(log_sizes) / 1_048_576.0)
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
        txt = list()
        txt.append("\n\nWARNING Tracebacks (%d) detected!" % (len(tracebacks),))
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
        entries = list()

        # CPU and load
        disp = list()
        disp.append(
            "%d (%d) @ %d%%"
            % (
                cpu_count(logical=True),
                cpu_count(logical=False),
                round(cpu_percent(interval=StatusReporter.CPU_POLL_INTERVAL)),
            )
        )
        if getloadavg is not None:
            disp.append(" (")
            # round the results of getloadavg(), precision varies across platforms
            disp.append(", ".join("%0.1f" % (round(x, 1),) for x in getloadavg()))
            disp.append(")")
        entries.append(("CPU & Load", "".join(disp)))

        # memory usage
        disp = list()
        mem_usage = virtual_memory()
        if mem_usage.available < 1_073_741_824:  # < 1GB
            disp.append("%dMB" % (mem_usage.available / 1_048_576,))
        else:
            disp.append("%0.1fGB" % (mem_usage.available / 1_073_741_824.0,))
        disp.append(" of %0.1fGB free" % (mem_usage.total / 1_073_741_824.0,))
        entries.append(("Memory", "".join(disp)))

        # disk usage
        disp = list()
        usage = disk_usage("/")
        if usage.free < 1_073_741_824:  # < 1GB
            disp.append("%dMB" % (usage.free / 1_048_576,))
        else:
            disp.append("%0.1fGB" % (usage.free / 1_073_741_824.0,))
        disp.append(" of %0.1fGB free" % (usage.total / 1_073_741_824.0,))
        entries.append(("Disk", "".join(disp)))

        return entries

    @staticmethod
    def _tracebacks(path, ignore_kbi=True, max_preceding=5):
        """Search screen logs for tracebacks.

        Args:
            path (str): Directory containing log files.
            ignore_kbi (bool): Do not include KeyboardInterupts in results
            max_preceding (int): Maximum number of lines preceding traceback to
                                  include.

        Returns:
            list: A list of TracebackReports.
        """
        tracebacks = list()
        for screen_log in StatusReporter._scan(path, r"screenlog\.\d+"):
            tbr = TracebackReport.from_file(screen_log, max_preceding=max_preceding)
            if tbr is None:
                continue
            if ignore_kbi and tbr.is_kbi:
                continue
            tracebacks.append(tbr)
        return tracebacks


class TracebackReport:
    """Read Python tracebacks from log files and store it in a manner that is helpful
    when generating reports.
    """

    MAX_LINES = 16  # should be no less than 6
    READ_LIMIT = 0x10000  # 64KB

    def __init__(self, file_name, lines, is_kbi=False, prev_lines=None):
        assert isinstance(lines, list)
        self.file_name = file_name
        self.lines = lines
        self.prev_lines = list() if prev_lines is None else prev_lines
        self.is_kbi = is_kbi

    @classmethod
    def from_file(cls, input_log, max_preceding=5):
        """Create TracebackReport from a text file containing a Python traceback.
        Only the first traceback in the file will be parsed.

        Args:
            input_log (str): File to parse.
            max_preceding (int): Number of lines to collect leading up to the traceback.

        Returns:
            TracebackReport: Contains data from input_log.
        """
        token = b"Traceback (most recent call last):"
        assert len(token) < cls.READ_LIMIT
        try:
            with open(input_log, "rb") as in_fp:
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
        return cls(input_log, lines, is_kbi=is_kbi, prev_lines=prev_lines)

    def __len__(self):
        return len(str(self))

    def __str__(self):
        return "\n".join(["Log: %r" % self.file_name] + self.prev_lines + self.lines)


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
    result = re_sub("^[0:]*", "", "%d:%02d:%02d" % (hours, minutes, seconds))
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
        result += " (%3d%%)" % (percent,)
    return result


def _format_number(number, total=0):
    result = ""
    if number is not None:
        if total == 0:
            percent = 0
        else:
            percent = int(100 * number / total)
        result = "{:n} ({:3d}%)".format(number, percent)
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
            list(ReductionStatus.loadall(db_file=db_file, time_limit=time_limit)),
            tracebacks=tracebacks,
        )

    @staticmethod
    def _analysis_entry(report):
        return (
            "Analysis",
            ", ".join(
                ("%s: %d%%" % (desc, 100 * reliability))
                for desc, reliability in report.analysis.items()
            ),
        )

    @staticmethod
    def _crash_id_entry(report):
        crash_str = str(report.crash_id)
        if report.tool:
            crash_str += " (%s)" % (report.tool,)
        return ("Crash ID", crash_str)

    @staticmethod
    def _last_reports_entry(report):
        return ("Latest Reports", ", ".join(str(r) for r in report.last_reports))

    @staticmethod
    def _run_params_entry(report):
        return (
            "Run Parameters",
            ", ".join(
                ("%s: %r" % (desc, value)) for desc, value in report.run_params.items()
            ),
        )

    @staticmethod
    def _signature_info_entry(report):
        return (
            "Signature",
            ", ".join(
                ("%s: %r" % (desc, value))
                for desc, value in report.signature_info.items()
            ),
        )

    def specific(  # pylint: disable=arguments-differ
        self,
        sysinfo=False,
        timestamp=False,
    ):
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
                        "%s (%r of %d)"
                        % (
                            report.current_strategy.name,
                            report.current_strategy_idx,
                            len(report.strategies),
                        ),
                    )
                )
            if report.current_strategy and report.original:
                # TODO: lines/tokens?
                entries.append(
                    (
                        "Current/Original",
                        "%dB / %dB"
                        % (report.current_strategy.size, report.original.size),
                    )
                )
            if report.total:
                # TODO: other results
                entries.append(
                    (
                        "Results",
                        "%d successes, %d attempts"
                        % (report.total.successes, report.total.attempts),
                    )
                )
            if report.total and report.current_strategy:
                entries.append(
                    (
                        "Time Elapsed",
                        "%s in strategy, %s total"
                        % (
                            _format_seconds(report.current_strategy.duration),
                            _format_seconds(report.total.duration),
                        ),
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
        runtime=False,
        sysinfo=False,
        timestamp=False,
    ):  # pylint: disable=arguments-differ
        """Merge and generate a summary from status reports.

        Args:
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
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    modes = {
        "fuzzing": (StatusReporter, Status.STATUS_DB),
        "reducing": (ReductionStatusReporter, ReductionStatus.STATUS_DB),
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
        "--dump", help="File to write report to, existing files will be overwritten."
    )
    parser.add_argument(
        "--type",
        choices=report_types.keys(),
        default="active",
        help="Report type. active: Current snapshot of activity, complete: "
        "Aggregate summary of all jobs over a longer duration (8h). "
        "(default: active)",
    )
    parser.add_argument(
        "--scan-mode",
        choices=modes.keys(),
        default="fuzzing",
        help="Report mode. (default: fuzzing)",
    )
    parser.add_argument(
        "--system-report",
        action="store_true",
        help="Output summary and system information",
    )
    parser.add_argument(
        "--tracebacks",
        help="Scan path for Python tracebacks found in screenlog.# files",
    )
    args = parser.parse_args(args)
    if args.tracebacks and not isdir(args.tracebacks):
        parser.error("--tracebacks must be a directory")

    reporter_cls, status_db = modes.get(args.scan_mode)
    reporter = reporter_cls.load(
        db_file=status_db,
        tb_path=args.tracebacks,
        time_limit=report_types[args.type],
    )

    if args.dump:
        with open(args.dump, "w") as ofp:
            if args.type == "active" and args.scan_mode == "fuzzing":
                ofp.write(reporter.summary(runtime=False, sysinfo=True, timestamp=True))
            elif args.type == "active":
                # reducer only has one instance, so show specific report while running
                ofp.write(reporter.specific(sysinfo=True, timestamp=True))
            else:
                ofp.write(
                    reporter.summary(runtime=True, sysinfo=False, timestamp=False)
                )
        return 0

    if not reporter.reports:
        print("Grizzly Status - No status reports to display")
        return 0

    print(
        "Grizzly Status - %s - Instance report frequency: %ds\n"
        % (strftime("%Y/%m/%d %X"), Status.REPORT_FREQ)
    )
    print("[Reports]")
    print(reporter.specific())
    if reporter.has_results:
        print("[Result Signatures]")
        print(reporter.results())
    print("[Summary]")
    print(reporter.summary(sysinfo=args.system_report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
