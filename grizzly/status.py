#!/usr/bin/env python
# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import datetime
import json
import os
import re
import sys
import time

try:
    import psutil
except ImportError:
    psutil = None

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class Status(object):
    """
    Status holds status information for the grizzly session.
    """
    FILE_PREFIX = "grz_status_"
    FILE_EXT = ".json"
    REPORT_FREQ = 60

    def __init__(self, report_name=None, start_time=True):
        self.date = None
        self.duration = None
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.rate = None
        self.report_path = report_name
        self.results = 0
        self.test_name = None
        self._last_report = 0
        self._start_time = time.time() if start_time else None
        if self.report_path is None:
            self.report_path = "%s%d%s" % (self.FILE_PREFIX, os.getpid(), self.FILE_EXT)

    def cleanup(self):
        if os.path.isfile(self.report_path):
            os.remove(self.report_path)

    @classmethod
    def load(cls, fname):
        if not os.path.isfile(fname):
            return None
        try:
            with open(fname, "r") as in_fp:
                data = json.load(in_fp)
        except (IOError, ValueError):
            return None
        report = cls(report_name=fname, start_time=False)
        report.date = os.stat(fname).st_mtime
        report.duration = data["Duration"]
        report.ignored = data["Ignored"]
        report.iteration = data["Iteration"]
        report.log_size = data["Logsize"]
        report.rate = data["Rate"]
        report.results = data["Results"]
        return report

    def report(self, report_freq=None):
        if self._start_time is None:
            # don't report data loaded from disk
            return
        if report_freq is None:
            report_freq = Status.REPORT_FREQ
        now = time.time()
        if now < (self._last_report + report_freq):
            return
        self._last_report = now
        duration = now - self._start_time
        with open(self.report_path, "w") as log_fp:
            json.dump({
                "Duration": duration,
                "Ignored": self.ignored,
                "Iteration": self.iteration,
                "Logsize": self.log_size,
                "Rate": (self.iteration/duration) if duration > 0 else 0,
                "Results": self.results}, log_fp)


class StatusReporter(object):
    REPORT_PATTERN = re.compile(r"%s\d+%s" % (Status.FILE_PREFIX, Status.FILE_EXT))
    AGE_LIMIT = 600  # 10 minutes

    CPU_INTERVAL = 1
    DISPLAY_LIMIT_LOG = 10  # don't include log results unless size exceeds 10MBs
    READ_BUF_SIZE = 0x10000  # 64KB
    REPORT_LIMIT = 4095  # maximum output size of the report in bytes

    def __init__(self):
        self.path = None
        self.reports = None

    def dump_specific(self, filename):
        with open(filename, "w") as ofp:
            ofp.write(self._specific())

    def dump_summary(self, filename, runtime=False, sysinfo=True, timestamp=True):
        with open(filename, "w") as ofp:
            ofp.write(self._summary(runtime=runtime, sysinfo=sysinfo, timestamp=timestamp))

    def load_reports(self, path):
        if not os.path.isdir(path):
            return
        self.path = path
        self.reports = list()
        for fname in self._scan(path, self.REPORT_PATTERN):
            self.reports.append(Status.load(fname))
        self.reports.sort(key=lambda x: x.duration, reverse=True)

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
        txt = list()
        for num, report in enumerate(self.reports, start=1):
            txt.append("#%02d Report %r" % (num, os.path.basename(report.report_path)))
            if report.date < (time.time() - (Status.REPORT_FREQ + self.AGE_LIMIT)):
                txt.append(" (EXPIRED)\n")
                continue
            txt.append(" (%s)\n" % str(datetime.timedelta(seconds=int(report.duration))))
            txt.append(" * Iterations: %03d" % report.iteration)
            txt.append(" - Rate: %0.2f" % report.rate)
            txt.append(" - Ignored: %02d" % report.ignored)
            txt.append(" - Results: %d\n" % report.results)
        return "".join(txt)

    def _summary(self, runtime=True, sysinfo=False, timestamp=False):
        exp = time.time() - self.AGE_LIMIT
        reports = [x for x in self.reports if x.date > exp]

        # calculate totals
        ignored = [x.ignored for x in reports]
        iterations = [x.iteration for x in reports]
        log_sizes = [x.log_size for x in reports]
        rates = [x.rate for x in reports]
        results = [x.results for x in reports]

        count = len(reports)
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
        if ignored:
            total_ignored = sum(ignored)
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
        # dump system info if psutil is available
        if sysinfo and psutil is not None:
            txt.append("\n")
            txt.append("CPU & Load : %d @ %0.1f%%" % (
                psutil.cpu_count(),
                psutil.cpu_percent(interval=self.CPU_INTERVAL)))
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
        if timestamp:
            txt.append("\n")
            txt.append(" Timestamp : %s" % (time.strftime("%Y/%m/%d %X %z", time.gmtime())))
        return "".join(txt)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dump",
        help="File to write report to")
    parser.add_argument(
        "--path", default=".",
        help="Directory to search for status report %r files" % Status.FILE_EXT)
    parser.add_argument(
        "--system-report", action="store_true",
        help="Output summary and system information")
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        parser.error("Directory %r does not exist" % args.path)

    reporter = StatusReporter()
    reporter.load_reports(args.path)
    if args.dump:
        reporter.dump_summary(args.dump)
        return 0
    if not reporter.reports:
        print("No reports to display found in %r" % reporter.path)
        return 0
    if not args.system_report:
        print("Grizzly Status %r\n" % os.path.abspath(reporter.path))
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
