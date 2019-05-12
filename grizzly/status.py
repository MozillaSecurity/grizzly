#!/usr/bin/env python
# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Merge multiple Grizzly status reports into one report."""

import argparse
import datetime
import json
import os
import re
import sys
import time
import traceback

import psutil

__all__ = ("Status", "StatusReporter")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class Status(object):
    """Status holds status information for the Grizzly session.
    """
    FILE_PREFIX = "grz_status_"
    FILE_EXT = ".json"
    REPORT_FREQ = 60

    def __init__(self, report_name=None, start_time=True):
        self.duration = None
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.rate = None
        self.report_path = report_name
        self.results = 0
        self.test_name = None
        self.timestamp = 0
        self._start_time = time.time() if start_time else None
        if self.report_path is None:
            self.report_path = "%s%d%s" % (self.FILE_PREFIX, os.getpid(), self.FILE_EXT)

    def cleanup(self):
        """Remove files that are no longer needed.

        Args:
            None

        Returns:
            None
        """
        if os.path.isfile(self.report_path):
            os.remove(self.report_path)

    @classmethod
    def load(cls, fname):
        """Read Grizzly status report.

        Args:
            fname (str): JSON file to load Grizzly status from.

        Returns:
            None
        """
        if not os.path.isfile(fname):
            return None
        try:
            with open(fname, "r") as in_fp:
                data = json.load(in_fp)
        except (IOError, ValueError):
            return None
        report = cls(report_name=fname, start_time=False)
        report.duration = data["Duration"]
        report.ignored = data["Ignored"]
        report.iteration = data["Iteration"]
        report.log_size = data["Logsize"]
        report.rate = data["Rate"]
        report.results = data["Results"]
        report.timestamp = data["Timestamp"]
        return report

    def report(self, report_freq=REPORT_FREQ):
        """Write Grizzly status report. Reports are only written when the duration
        of time since the previous report was created exceeds `report_freq` seconds

        Args:
            report_freq (int): Minimum number of seconds between writes.

        Returns:
            None
        """
        if self._start_time is None:
            # don't report data loaded from disk
            return
        now = time.time()
        if now < (self.timestamp + report_freq):
            return
        self.timestamp = now
        duration = now - self._start_time
        with open(self.report_path, "w") as log_fp:
            json.dump({
                "Duration": duration,
                "Ignored": self.ignored,
                "Iteration": self.iteration,
                "Logsize": self.log_size,
                "Rate": (self.iteration/duration) if duration > 0 else 0,
                "Results": self.results,
                "Timestamp": self.timestamp}, log_fp)


class StatusReporter(object):
    """Read and merge Grizzly status reports, including tracebacks if found.
    Output is a single textual report, e.g. for submission to EC2SpotManager.
    """
    AGE_LIMIT = 600  # 10 minutes
    CPU_POLL_INTERVAL = 1
    DISPLAY_LIMIT_LOG = 10  # don't include log results unless size exceeds 10MBs
    READ_BUF_SIZE = 0x10000  # 64KB
    REPORT_PATTERN = re.compile(r"%s\d+%s" % (Status.FILE_PREFIX, Status.FILE_EXT))

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
            ofp.write(self._summary(runtime=runtime, sysinfo=sysinfo, timestamp=timestamp))

    @classmethod
    def load(cls, path, tracebacks=False):
        """Read Grizzly status reports and create a StatusReporter object

        Args:
            path (str): Directory containing Grizzly status JSON files.
            tracebacks (bool): Scan for and include Python tracebacks

        Returns:
            StatusReporter: Contains status reports and traceback reports that were found
        """
        reports = list()
        for fname in cls._scan(path, cls.REPORT_PATTERN):
            reports.append(Status.load(fname))
        tb_reports = cls._tracebacks(path) if tracebacks else None
        return cls(reports, tb_reports)

    def print_specific(self):
        print(self._specific())

    def print_summary(self, runtime=True, sysinfo=False, timestamp=False):
        print(self._summary(runtime=runtime, sysinfo=sysinfo, timestamp=timestamp))

    @staticmethod
    def _scan(path, fname_pattern):
        if not os.path.isdir(path):
            return
        abs_path = os.path.abspath(path)
        for fname in os.listdir(abs_path):
            if fname_pattern.match(fname) is None:
                continue
            full_path = os.path.join(abs_path, fname)
            if not os.path.isfile(full_path):
                continue
            if os.path.getsize(full_path) > 0:
                yield full_path

    def _specific(self):
        """Merged and generate formatted output of status reports.

        Args:
            None

        Returns:
            str: A formatted report
        """
        if not self.reports:
            return "No status reports loaded"
        exp = time.time() - self.AGE_LIMIT
        self.reports.sort(key=lambda x: x.duration, reverse=True)
        self.reports.sort(key=lambda x: x.timestamp < exp)
        txt = list()
        for num, report in enumerate(self.reports, start=1):
            txt.append("#%02d Report %r" % (num, os.path.basename(report.report_path)))
            if report.timestamp < exp:
                txt.append(" (EXPIRED)\n")
                continue
            txt.append(" (%s)\n" % str(datetime.timedelta(seconds=int(report.duration))))
            txt.append(" * Iterations: %03d" % report.iteration)
            txt.append(" - Rate: %0.2f" % report.rate)
            txt.append(" - Ignored: %02d" % report.ignored)
            txt.append(" - Results: %d\n" % report.results)
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
        if not self.reports:
            return "No status reports loaded"
        exp = time.time() - self.AGE_LIMIT
        reports = tuple(x for x in self.reports if x.timestamp > exp)
        # calculate totals
        iterations = tuple(x.iteration for x in reports)
        log_sizes = tuple(x.log_size for x in reports)
        rates = tuple(x.rate for x in reports)
        results = tuple(x.results for x in reports)
        count = len(reports)
        total_ignored = sum(x.ignored for x in reports)
        total_iters = sum(iterations)

        txt = list()
        # Iterations
        txt.append("Iterations : %d" % total_iters)
        if count > 1:
            txt.append(" (%s, %s)" % (max(iterations), min(iterations)))
        txt.append("\n")
        # Rate
        txt.append("      Rate : %d @ %0.2f" % (count, sum(rates)))
        if count > 1:
            txt.append(" (%0.2f, %0.2f)" % (max(rates), min(rates)))
        txt.append("\n")
        # Results and ignored
        txt.append("   Results : %d" % sum(results))
        if total_ignored:
            ignore_pct = (total_ignored/float(total_iters)) * 100
            txt.append(" (%d ignored @ %0.2f%%)" % (total_ignored, ignore_pct))
        # Runtime
        if runtime:
            txt.append("\n")
            total_runtime = sum((x.duration for x in reports))
            txt.append("   Runtime : %s" % (str(datetime.timedelta(seconds=int(total_runtime)))))
        # Log size
        log_usage = sum(log_sizes)/1048576.0
        if log_usage > self.DISPLAY_LIMIT_LOG:
            txt.append("\n")
            txt.append("      Logs : %0.1fMB" % log_usage)
            if count > 1:
                txt.append(" (%0.2fMB, %0.2fMB)" % (
                    max(log_sizes)/1048576.0,
                    min(log_sizes)/1048576.0))
        if sysinfo:
            txt.append("\n")
            txt.append(self._sys_info())
        if timestamp:
            txt.append("\n")
            txt.append(" Timestamp : %s" % (time.strftime("%Y/%m/%d %X %z", time.gmtime())))
        if self.tracebacks:
            txt.append("\n\nWARNING Tracebacks detected!")
            for tbr in self.tracebacks:
                txt.append("\n")
                txt.append(str(tbr))
        return "".join(txt)

    @staticmethod
    def _sys_info():
        """Collect and format system information.

        Args:
            None

        Returns:
            str: System information formatted to match output from _summary()
        """
        txt = list()
        txt.append("CPU & Load : %d @ %0.1f%%" % (
            psutil.cpu_count(),
            psutil.cpu_percent(interval=StatusReporter.CPU_POLL_INTERVAL)))
        try:
            txt.append(" %s\n" % str(os.getloadavg()))
        except AttributeError:
            txt.append("\n")
        mem_usage = psutil.virtual_memory()
        txt.append("    Memory : ")
        if mem_usage.available < 1073741824:  # < 1GB
            txt.append("%dMB" % (mem_usage.available/1048576))
        else:
            txt.append("%0.1fGB" % (mem_usage.available/1073741824.0))
        txt.append(" of %0.1fGB free\n" % (mem_usage.total/1073741824.0))
        disk_usage = psutil.disk_usage("/")
        txt.append("      Disk : ")
        if disk_usage.free < 1073741824:  # < 1GB
            txt.append("%dMB" % (disk_usage.free/1048576))
        else:
            txt.append("%0.1fGB" % (disk_usage.free/1073741824.0))
        txt.append(" of %0.1fGB free" % (disk_usage.total/1073741824.0))
        return "".join(txt)

    @staticmethod
    def _tracebacks(path, ignore_kbi=True, max_preceeding=5):
        """Search screen logs for tracebacks.

        Args:
            path (str): Directory containing log files.
            ignore_kbi (bool): Do not include KeyboardInterupts in results
            max_preceeding (int): Maximum number of lines preceding traceback to include.

        Returns:
            list: A list of TracebackReports
        """
        tracebacks = list()
        for screen_log in StatusReporter._scan(path, re.compile(r"screenlog\.\d+")):
            tbr = TracebackReport.from_file(screen_log, max_preceeding=max_preceeding)
            if tbr is None:
                continue
            if ignore_kbi and tbr.is_kbi:
                continue
            tracebacks.append(tbr)
        return tracebacks


class TracebackReport(object):
    """Read Python tracebacks from log files and store it in a manner that is helpful
    when generating reports.
    """
    MAX_LINES = 15
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
            max_preceeding (int): Number of lines to collect leading up to the traceback.

        Returns:
            TracebackReport: Contains data from input_log.
        """
        token_traceback = "Traceback (most recent call last):"
        try:
            with open(input_log, "r") as in_fp:
                for line in iter(in_fp.readline, ""):
                    if token_traceback in line:
                        # seek 2KB before tb
                        in_fp.seek(max(in_fp.tell() - 2048, 0))
                        data = in_fp.read(cls.READ_LIMIT).splitlines()
                        break
                else:
                    # no traceback here, move along
                    return None
        except IOError:
            # in case the file goes away
            return None

        is_kbi = False
        tb_start = None
        tb_end = None
        line_count = len(data)
        for line_num, log_line in enumerate(data):
            if tb_start is None and token_traceback in log_line:
                tb_start = line_num
                continue
            elif tb_start is not None:
                log_line = log_line.strip()
                if not log_line:
                    # stop at first empty line
                    tb_end = min(line_num, line_count)
                    break
                is_kbi = log_line.startswith("KeyboardInterrupt")
                if is_kbi or re.match(r"^\w+(\.\w+)*\:\s", log_line) is not None:
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
            lines = ["..."] + data[tb_end - cls.MAX_LINES:tb_end]
        else:
            lines = data[tb_start:tb_end]
        return cls(input_log, lines, is_kbi=is_kbi, prev_lines=prev_lines)

    def __str__(self):
        return "\n".join(["Log: %r" % self.file_name] + self.prev_lines + self.lines)


def main(args=None):
    """Merge Grizzly status files into a single report (main entrypoint).

    Args:
        args (list/None): Argument list to parse instead of sys.argv (for testing).

    Returns:
        None
    """
    parser = argparse.ArgumentParser(description="Grizzly status report generator")
    parser.add_argument(
        "--dump",
        help="File to write report to")
    parser.add_argument(
        "--path", default=".",
        help="Directory to search for status report %r files" % Status.FILE_EXT)
    parser.add_argument(
        "--system-report", action="store_true",
        help="Output summary and system information")
    parser.add_argument(
        "--tracebacks", action="store_true",
        help="Include Python tracebacks found in screenlog.# files")
    args = parser.parse_args(args)
    if not os.path.isdir(args.path):
        parser.error("Directory %r does not exist" % args.path)

    reporter = StatusReporter.load(args.path, tracebacks=args.tracebacks)
    if args.dump:
        try:
            reporter.dump_summary(args.dump)
        except Exception:  # pylint: disable=broad-except
            with open(args.dump, "w") as out_fp:
                out_fp.write("Something went wrong!\n\n")
                out_fp.write(traceback.format_exc())
                out_fp.write("\n")
            raise
        return 0
    if not reporter.reports:
        print("No reports to display found in %r" % args.path)
        return 0
    if not args.system_report:
        print("Grizzly Status %r\n" % os.path.abspath(args.path))
        print("Instances")
        print("---------")
        reporter.print_specific()
        print("Summary")
        print("-------")
    reporter.print_summary(
        sysinfo=args.system_report,
        timestamp=args.system_report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
