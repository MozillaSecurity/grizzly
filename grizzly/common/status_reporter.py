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
from logging import DEBUG, INFO, basicConfig

try:
    from os import getloadavg
except ImportError:  # pragma: no cover
    # os.getloadavg() is not available on all platforms
    getloadavg = None
from os import SEEK_CUR, getenv, scandir
from os.path import isdir
from re import match
from time import gmtime, strftime

from psutil import cpu_count, cpu_percent, disk_usage, virtual_memory

from ..session import Session
from .status import Status

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

    def dump_specific(self, filename):
        """Write out merged reports.

        Args:
            filename (str): Path where output should be written.

        Returns:
            None
        """
        with open(filename, "w") as ofp:
            ofp.write(self._specific())

    def dump_summary(self, filename, runtime=False, sysinfo=True, timestamp=True):
        """Write out summary merged reports.

        Args:
            filename (str): Path where output should be written.
            runtime (bool): Include total runtime in output
            sysinfo (bool): Include system info (CPU, disk, RAM... etc) in output
            timestamp (bool): Include time stamp in output

        Returns:
            None
        """
        with open(filename, "w") as ofp:
            ofp.write(
                self._summary(runtime=runtime, sysinfo=sysinfo, timestamp=timestamp)
            )

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

    def print_results(self):
        print(self._results())

    def print_specific(self):
        print(self._specific())

    def print_summary(self, runtime=True, sysinfo=False, timestamp=False):
        print(self._summary(runtime=runtime, sysinfo=sysinfo, timestamp=timestamp))

    def _results(self, max_len=85):
        descs = dict()
        counts = defaultdict(int)
        # calculate totals
        for entry in self.reports:
            for rid, count, desc in entry.results.all():
                descs[rid] = desc
                counts[rid] += count
        # generate output
        txt = list()
        for rid, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            if len(descs[rid]) > max_len:
                txt.append("%d: '%s...'\n" % (count, descs[rid][:max_len]))
            else:
                txt.append("%d: %r\n" % (count, descs[rid]))
        if not txt:
            txt.append("No results available\n")
        return "".join(txt)

    @staticmethod
    def _scan(path, fname_pattern):
        for entry in scandir(path):
            if match(fname_pattern, entry.name) is None:
                continue
            if not entry.is_file():
                continue
            if entry.stat().st_size:
                yield entry.path

    def _specific(self):
        """Merged and generate formatted output of status reports.

        Args:
            None

        Returns:
            str: A formatted report
        """
        if not self.reports:
            return "No status reports available"
        self.reports.sort(key=lambda x: x.runtime, reverse=True)
        txt = list()
        for num, report in enumerate(self.reports, start=1):
            txt.append("#%02d - %d -" % (num, report.pid))
            txt.append(" Runtime %s\n" % (timedelta(seconds=int(report.runtime)),))
            txt.append(" * Iterations: %d" % (report.iteration,))
            txt.append(" @ %0.2f," % (round(report.rate, 2),))
            txt.append(" Ignored: %d," % (report.ignored,))
            txt.append(" Results: %d" % (report.results.total,))
            txt.append("\n")
            # add profiling data if it exists
            if any(report.profile_entries()):
                txt.append(" * Profiling entries *\n")
            for entry in sorted(
                report.profile_entries(), key=lambda x: x.total, reverse=True
            ):
                avg = entry.total / float(entry.count)
                txt.append(" > %s: %dx " % (entry.name, entry.count))
                if entry.total > 300:
                    txt.append(str(timedelta(seconds=int(entry.total))))
                else:
                    txt.append("%0.3fs" % (round(entry.total, 3),))
                txt.append(" %0.2f%%" % (round(entry.total / report.runtime * 100, 2),))
                txt.append(" (%0.3f avg," % (round(avg, 3),))
                txt.append(" %0.3f max," % (round(entry.max, 3),))
                txt.append(" %0.3f min)" % (round(entry.min, 3),))
                txt.append("\n")
        return "".join(txt)

    def _summary(
        self, runtime=True, sysinfo=False, timestamp=False, iters_per_result=100
    ):
        """Merge and generate a summary of status reports.

        Args:
            runtime (bool): Include total runtime in output
            sysinfo (bool): Include system info (CPU, disk, RAM... etc) in output
            timestamp (bool): Include time stamp in output
            iters_per_result (int): Threshold for warning of potential blockers

        Returns:
            str: A summary of merged reports
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
        label_lengths = tuple(len(x[0]) for x in entries if x[1])
        max_len = max(label_lengths) if label_lengths else 0
        msg = list()
        for label, body in entries:
            if body:
                msg.append(
                    "%s%s : %s" % ((" " * max(max_len - len(label), 0), label, body))
                )
            else:
                msg.append(label)
        msg = "\n".join(msg)

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
            disp.append(" %s" % (str(getloadavg()),))
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
    def _tracebacks(path, ignore_kbi=True, max_preceeding=5):
        """Search screen logs for tracebacks.

        Args:
            path (str): Directory containing log files.
            ignore_kbi (bool): Do not include KeyboardInterupts in results
            max_preceeding (int): Maximum number of lines preceding traceback to
                                  include.

        Returns:
            list: A list of TracebackReports.
        """
        tracebacks = list()
        for screen_log in StatusReporter._scan(path, r"screenlog\.\d+"):
            tbr = TracebackReport.from_file(screen_log, max_preceeding=max_preceeding)
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
    def from_file(cls, input_log, max_preceeding=5):
        """Create TracebackReport from a text file containing a Python traceback.
        Only the first traceback in the file will be parsed.

        Args:
            input_log (str): File to parse.
            max_preceeding (int): Number of lines to collect leading up to the
                                  traceback.

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
        if max_preceeding > 0:
            prev_start = max(tb_start - max_preceeding, 0)
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

    # TODO: add support for reducer
    modes = {"fuzzing": Session.STATUS_DB}

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

    status_db = modes.get(args.scan_mode)
    reporter = StatusReporter.load(
        db_file=status_db,
        tb_path=args.tracebacks,
        time_limit=report_types[args.type],
    )
    if args.dump:
        if args.type == "active":
            reporter.dump_summary(
                args.dump, runtime=False, sysinfo=True, timestamp=True
            )
        else:
            reporter.dump_summary(
                args.dump, runtime=True, sysinfo=False, timestamp=False
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
    reporter.print_specific()
    if reporter.has_results:
        print("[Result Signatures]")
        reporter.print_results()
    print("[Summary]")
    reporter.print_summary(sysinfo=args.system_report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
