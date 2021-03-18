# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from collections import defaultdict, namedtuple
from contextlib import contextmanager
from json import dump, load
from logging import getLogger
from os import close, getpid, listdir, unlink
from os.path import isdir, isfile
from os.path import join as pathjoin
from tempfile import mkstemp
from time import time

from fasteners.process_lock import InterProcessLock

from .utils import grz_tmp

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)

ProfileEntry = namedtuple("ProfileEntry", "count max min name total")


class Status:
    """Status holds status information for the Grizzly session.
    There can be multiple readers of the data but only a single writer.
    """

    PATH = grz_tmp("status")
    REPORT_FREQ = 60

    __slots__ = (
        "_enable_profiling",
        "_lock",
        "_profiles",
        "_results",
        "data_file",
        "ignored",
        "iteration",
        "log_size",
        "pid",
        "start_time",
        "test_name",
        "timestamp",
    )

    def __init__(self, data_file, enable_profiling=False, start_time=None):
        assert data_file.endswith(".json")
        assert start_time is None or isinstance(start_time, float)
        self._lock = InterProcessLock("%s.lock" % (data_file,))
        self._enable_profiling = enable_profiling
        self._profiles = dict()
        self._results = defaultdict(int)
        # if data_file is None the status report is read only (no reporting)
        self.data_file = data_file
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.pid = None
        self.start_time = start_time
        self.test_name = None
        self.timestamp = start_time

    def cleanup(self):
        """Remove data and lock files from disk.

        Args:
            None

        Returns:
            None
        """
        if self.data_file is None:
            return
        try:
            with self._lock:
                unlink(self.data_file)
        except OSError:  # pragma: no cover
            LOG.warning("Failed to delete %r", self.data_file)
        try:
            unlink("%s.lock" % (self.data_file,))
        except OSError:  # pragma: no cover
            pass
        self.data_file = None

    def count_result(self, signature):
        """Increment counter that matches `signature`.

        Args:
            signature (str):

        Returns:
            None
        """
        self._results[signature] += 1

    @property
    def _data(self):
        return {
            "_profiles": self._profiles,
            "_results": self._results,
            "ignored": self.ignored,
            "iteration": self.iteration,
            "log_size": self.log_size,
            "pid": self.pid,
            "start_time": self.start_time,
            "test_name": self.test_name,
            "timestamp": self.timestamp,
        }

    @property
    def duration(self):
        """Calculate the number of seconds since start() was called.

        Args:
            None

        Returns:
            int: Total runtime in seconds since start() was called
        """
        return max(self.timestamp - self.start_time, 0)

    @classmethod
    def load(cls, data_file):
        """Load status report. Loading a status report from disk will create a
        read only status report.

        Args:
            data_file (str): JSON file that contains status data.

        Returns:
            Status: Loaded status object or None
        """
        status = cls(data_file)
        data = None
        try:
            with status._lock:  # pylint: disable=protected-access
                with open(data_file, "r") as out_fp:
                    data = load(out_fp)
        except OSError:
            LOG.debug("failed to open %r", data_file)
            # if data_file exists the lock will be removed by the active session
            if not isfile(data_file):
                # attempt to remove potentially leaked lock file
                try:
                    unlink("%s.lock" % (data_file,))
                except OSError:  # pragma: no cover
                    pass
        except ValueError:
            LOG.debug("failed to load json data from %r", data_file)
        else:
            LOG.debug("no such file %r", data_file)
        if data is None:
            return None
        if "start_time" not in data:
            LOG.debug("invalid status json file")
            return None
        for attr, value in data.items():
            setattr(status, attr, value)
        # set read only
        status.data_file = None
        return status

    @classmethod
    def loadall(cls):
        """Load all status reports found in cls.PATH.

        Args:
            None

        Returns:
            Generator: Status objects stored in cls.PATH.
        """
        if isdir(cls.PATH):
            for data_file in listdir(cls.PATH):
                if not data_file.endswith(".json"):
                    continue
                status = cls.load(pathjoin(cls.PATH, data_file))
                if status is None:
                    continue
                yield status

    @contextmanager
    def measure(self, name):
        """Used to simplify collecting profiling data.

        Args:
            name (str): Used to group the entries.

        Returns:
            None
        """
        if self._enable_profiling:
            mark = time()
            yield
            self.record(name, time() - mark)
        else:
            yield

    def profile_entries(self):
        """Used to retrieve profiling data.

        Args:
            None

        Yields:
            ProfileEntry: Containing recorded profiling data.
        """
        for name, entry in self._profiles.items():
            yield ProfileEntry(
                entry["count"],
                entry["max"],
                entry["min"],
                name,
                entry["total"],
            )

    @property
    def rate(self):
        """Calculate the number of iterations performed per second since start()
        was called.

        Args:
            None

        Returns:
            float: Number of iterations performed per second.
        """
        return self.iteration / float(self.duration) if self.duration > 0 else 0

    def record(self, name, duration):
        """Used to add profiling data. This is intended to be used to make rough
        calculations to identify major configuration issues.

        Args:
            name (str): Used to group the entries.
            duration (int, float): Stored to be later used for measurements.

        Returns:
            None
        """
        assert isinstance(duration, (float, int))
        try:
            self._profiles[name]["count"] += 1
            if self._profiles[name]["max"] < duration:
                self._profiles[name]["max"] = duration
            elif self._profiles[name]["min"] > duration:
                self._profiles[name]["min"] = duration
            self._profiles[name]["total"] += duration
        except KeyError:
            if self._enable_profiling:
                # add profile entry
                self._profiles[name] = {
                    "count": 1,
                    "max": duration,
                    "min": duration,
                    "total": duration,
                }

    def report(self, force=False, report_freq=REPORT_FREQ):
        """Write status report to disk. Reports are only written periodically.
        It is limited by `report_freq`. The specified number of seconds must
        elapse before another write will be performed unless `force` is True.

        Args:
            force (bool): Ignore report frequently limiting.
            report_freq (int): Minimum number of seconds between writes.

        Returns:
            bool: Returns true if the report was successful otherwise false.
        """
        assert self.data_file is not None
        now = time()
        if not force and now < (self.timestamp + report_freq):
            return False
        self.timestamp = now
        with self._lock:
            with open(self.data_file, "w") as out_fp:
                dump(self._data, out_fp)
        return True

    @property
    def results(self):
        """Calculate the total number of results.

        Args:
            None

        Returns:
            int: Total number of results.
        """
        return sum(self._results.values())

    def signatures(self):
        """Provide the signature and the number of times it has been found for
        each result.

        Args:
            None

        Yields:
            tuples: Containing signature and count.
        """
        for sig, count in self._results.items():
            yield (sig, count)

    @classmethod
    def start(cls, enable_profiling=False):
        """Create a unique Status object.

        Args:
            enable_profiling (bool): Record profiling data.

        Returns:
            Status: Active status report.
        """
        tfd, filepath = mkstemp(dir=cls.PATH, prefix="grzstatus_", suffix=".json")
        close(tfd)
        status = cls(filepath, enable_profiling=enable_profiling, start_time=time())
        status.pid = getpid()
        status.report(force=True)
        return status
