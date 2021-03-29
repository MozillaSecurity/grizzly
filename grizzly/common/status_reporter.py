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
from time import gmtime, strftime, time

from psutil import cpu_count, cpu_percent, disk_usage, virtual_memory

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
    EXP_LIMIT = 600  # expiration limit, ignore older reports
    READ_BUF_SIZE = 0x10000  # 64KB
    SUMMARY_LIMIT = 4095  # summary output must be no more than 4KB

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
        return any(x.results for x in self.reports)

    @classmethod
    def load(cls, tb_path=None):
        """Read Grizzly status reports and create a StatusReporter object.

        Args:
            tb_path (str): Directory to scan for files containing Python tracebacks.

        Returns:
            StatusReporter: Contains available status reports and traceback reports.
        """
        tracebacks = None if tb_path is None else cls._tracebacks(tb_path)
        return cls(list(Status.loadall()), tracebacks=tracebacks)

    def print_results(self):
        print(self._results())

    def print_specific(self):
        print(self._specific())

    def print_summary(self, runtime=True, sysinfo=False, timestamp=False):
        print(self._summary(runtime=runtime, sysinfo=sysinfo, timestamp=timestamp))

    def _results(self, max_len=85):
        signatures = defaultdict(int)
        # calculate totals
        for result in self.reports:
            for sig, count in result.signatures():
                signatures[sig] += count
        # generate output
        txt = list()
        for sig, count in sorted(signatures.items(), key=lambda x: x[1], reverse=True):
            if len(sig) > max_len:
                txt.append("%d: '%s...'\n" % (count, sig[:max_len]))
            else:
                txt.append("%d: %r\n" % (count, sig))
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
        exp = int(time()) - self.EXP_LIMIT
        self.reports.sort(key=lambda x: x.duration, reverse=True)
        self.reports.sort(key=lambda x: x.timestamp < exp)
        txt = list()
        for num, report in enumerate(self.reports, start=1):
            txt.append("#%02d - %d -" % (num, report.pid))
            if report.timestamp < exp:
                txt.append(" (EXPIRED)\n")
                continue
            txt.append(" Runtime %s\n" % (timedelta(seconds=int(report.duration)),))
            txt.append(" * Iterations: %d" % (report.iteration,))
            txt.append(" @ %0.2f," % (round(report.rate, 2),))
            txt.append(" Ignored: %d," % (report.ignored,))
            txt.append(" Results: %d" % (report.results,))
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
                txt.append(
                    " %0.2f%%" % (round(entry.total / report.duration * 100, 2),)
                )
                txt.append(" (%0.3f avg," % (round(avg, 3),))
                txt.append(" %0.3f max," % (round(entry.max, 3),))
                txt.append(" %0.3f min)" % (round(entry.min, 3),))
                txt.append("\n")
        return "".join(txt)

    def _summary(self, runtime=True, sysinfo=False, timestamp=False):
        """Merge and generate a summary of status reports.

        Args:
            filename (str): Path where output should be written.
            runtime (bool): Include total runtime in output
            sysinfo (bool): Include system info (CPU, disk, RAM... etc) in output
            timestamp (bool): Include time stamp in output

        Returns:
            str: A summary of merged reports
        """
        txt = list()
        # Job specific status
        exp = int(time()) - self.EXP_LIMIT
        reports = tuple(x for x in self.reports if x.timestamp > exp)
        if reports:
            # calculate totals
            iterations = tuple(x.iteration for x in reports)
            log_sizes = tuple(x.log_size for x in reports)
            rates = tuple(x.rate for x in reports)
            results = tuple(x.results for x in reports)
            count = len(reports)
            total_ignored = sum(x.ignored for x in reports)
            total_iters = sum(iterations)
            # Iterations
            txt.append("Iterations : %d" % (total_iters,))
            if count > 1:
                txt.append(" (%d, %d)" % (max(iterations), min(iterations)))
            txt.append("\n")
            # Rate
            txt.append("      Rate : %d @ %0.2f" % (count, round(sum(rates), 2)))
            if count > 1:
                txt.append(
                    " (%0.2f, %0.2f)" % (round(max(rates), 2), round(min(rates), 2))
                )
            txt.append("\n")
            # Results / Signature mismatch
            txt.append("   Results : %d" % (sum(results),))
            if total_ignored:
                ignore_pct = total_ignored / float(total_iters) * 100
                txt.append(
                    " (%d ignored @ %0.2f%%)" % (total_ignored, round(ignore_pct, 2))
                )
            # Runtime
            if runtime:
                txt.append("\n")
                total_runtime = sum(x.duration for x in reports)
                txt.append("   Runtime : %s" % (timedelta(seconds=int(total_runtime)),))
            # Log size
            log_usage = sum(log_sizes) / 1048576.0
            if log_usage > self.DISPLAY_LIMIT_LOG:
                txt.append("\n")
                txt.append("      Logs : %0.1fMB" % (log_usage,))
                if count > 1:
                    txt.append(
                        " (%0.2fMB, %0.2fMB)"
                        % (max(log_sizes) / 1048576.0, min(log_sizes) / 1048576.0)
                    )
        else:
            txt.append("No status reports available")
        if sysinfo:
            txt.append("\n")
            txt.append(self._sys_info())
        if timestamp:
            txt.append("\n")
            txt.append(strftime(" Timestamp : %Y/%m/%d %X %z", gmtime()))
        msg = "".join(txt)
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
        """Collect and format system information.

        Args:
            None

        Returns:
            str: System information formatted to match output from _summary()
        """
        txt = list()
        txt.append(
            "CPU & Load : %d @ %0.1f%%"
            % (
                cpu_count(),
                cpu_percent(interval=StatusReporter.CPU_POLL_INTERVAL),
            )
        )
        if getloadavg is not None:
            txt.append(" %s\n" % (str(getloadavg()),))
        else:
            txt.append("\n")
        mem_usage = virtual_memory()
        txt.append("    Memory : ")
        if mem_usage.available < 1073741824:  # < 1GB
            txt.append("%dMB" % (mem_usage.available / 1048576,))
        else:
            txt.append("%0.1fGB" % (mem_usage.available / 1073741824.0,))
        txt.append(" of %0.1fGB free\n" % (mem_usage.total / 1073741824.0,))
        usage = disk_usage("/")
        txt.append("      Disk : ")
        if usage.free < 1073741824:  # < 1GB
            txt.append("%dMB" % (usage.free / 1048576,))
        else:
            txt.append("%0.1fGB" % (usage.free / 1073741824.0,))
        txt.append(" of %0.1fGB free" % (usage.total / 1073741824.0,))
        return "".join(txt)

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

    modes = ("status",)
    parser = ArgumentParser(description="Grizzly status report generator")
    parser.add_argument("--dump", help="File to write report to")
    parser.add_argument(
        "--mode",
        default="status",
        help="Status loading mode. Available modes: %s (default: 'status')"
        % (", ".join(modes),),
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
    if args.mode not in modes:
        parser.error("Invalid mode %r" % args.mode)
    if args.tracebacks and not isdir(args.tracebacks):
        parser.error("--tracebacks must be a directory")

    reporter = StatusReporter.load(tb_path=args.tracebacks)
    if args.dump:
        reporter.dump_summary(args.dump)
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
