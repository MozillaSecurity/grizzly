# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import json
import os
import time

__all__ = ("Status")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class Status(object):
    """
    Status holds status information for the grizzly session.
    """
    FILE_PREFIX = "grz_status_"
    FILE_EXT = ".json"
    REPORT_FREQ = 60

    def __init__(self, report_name=None):
        self.duration = None
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.rate = None
        self.results = 0
        self.test_name = None
        self._last_report = 0
        if report_name is None:
            self._report_file = "%s%d%s" % (self.FILE_PREFIX, os.getpid(), self.FILE_EXT)
        else:
            self._report_file = report_name
        self._start_time = time.time()

    @classmethod
    def load(cls, fname):
        if not os.path.isfile(fname):
            return None
        try:
            with open(fname, "r") as in_fp:
                data = json.load(in_fp)
        except ValueError:
            return None
        report = cls(report_name=fname)
        report.duration = data["Duration"]
        report.ignored = data["Ignored"]
        report.iteration = data["Iteration"]
        report.log_size = data["Logsize"]
        report.rate = data["Rate"]
        report.results = data["Results"]
        report._start_time = None # reports loaded from disk will not have a start time
        return report

    def cleanup(self):
        if os.path.isfile(self._report_file):
            os.remove(self._report_file)

    def report(self, report_freq=None):
        if self._start_time is None: # don't report data loaded from disk
            return
        now = time.time()
        if report_freq is None:
            report_freq = Status.REPORT_FREQ
        if now < (self._last_report + report_freq):
            return

        self._last_report = now
        duration = now - self._start_time
        with open(self._report_file, "w") as log_fp:
            json.dump({
                "Duration": duration,
                "Ignored": self.ignored,
                "Iteration": self.iteration,
                "Logsize": self.log_size,
                "Rate": (self.iteration/duration) if duration > 0 else 0,
                "Results": self.results}, log_fp)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--path", default=".",
        help="Directory to search for status report %r files" % Status.FILE_EXT)
    args = parser.parse_args()
    if not os.path.isdir(args.path):
        parser.error("Directory %r does not exist" % args.path)

    total = {
        "iteration": 0,
        "ignored": 0,
        "old": [],
        "rate": 0,
        "results": 0}

    full_path = os.path.abspath(args.path)
    # scan directory for reports
    reports = []
    for fname in os.listdir(full_path):
        if not fname.lower().endswith(Status.FILE_EXT):
            continue
        fname = os.path.join(full_path, fname)
        if os.stat(fname).st_mtime < (time.time() - (Status.REPORT_FREQ  + 300)): # + 5 min
            total["old"].append(fname)
            continue
        report = Status.load(fname)
        if report is None:
            continue
        reports.append(report)

    # display results
    if not reports:
        print("No reports to display found in %r" % full_path)
    else:
        print("Status reports found in %r" % full_path)
        for report in reports:
            print(" iters: %03d - rate: %0.2f - ignored: %02d - results %d" % (
                report.iteration, report.rate, report.ignored, report.results))
            total["ignored"] += report.ignored
            total["iteration"] += report.iteration
            total["rate"] += report.rate
            total["results"] += report.results
        if len(reports) > 1: # only display summary if we have more than one report
            print("Totals - %d reports" % len(reports))
            print(" iters: %03d - rate: %0.2f - ignored: %02d - results %d" % (
                total["iteration"], total["rate"], total["ignored"], total["results"]))
    if total["old"]:
        print("Out of date reports have been skipped")
        for fname in total["old"]:
            print(" %s" % fname)


if __name__ == "__main__":
    main()
