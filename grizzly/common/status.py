# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from collections import defaultdict, namedtuple
from contextlib import contextmanager
from json import dump, load
from logging import getLogger
from os import close, getpid, scandir, unlink
from os.path import isdir, isfile
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
    There can be multiple readers (read-only) but only a single writer of data.
    Read-only mode is implied if `data_file` is None.

    Attributes:
        _enable_profiling (bool): Profiling support status.
        _lock (InterProcessLock): Lock used with data_file.
        _profiles (dict): Profiling data.
        _results (dict): Results data. Used to count occurrences of a signature.
        data_file (str): File to save data to. None in read-only mode.
        ignored (int): Ignored result count.
        iteration (int): Iteration count.
        log_size (int): Log size in bytes.
        pid (int): Python process ID.
        start_time (float): Start time of session.
        test_name (str): Current test name.
        timestamp (float): Last time data was saved to data_file. Set by report().
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
        if data_file is None:
            # read-only mode
            assert start_time is None
            self._lock = None
            self._enable_profiling = False
        else:
            assert data_file.endswith(".json")
            assert isinstance(start_time, float)
            self._lock = InterProcessLock(self.lock_file(data_file))
            self._enable_profiling = enable_profiling
        self._profiles = dict()
        self._results = defaultdict(int)
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
        if self.data_file is not None:
            try:
                with self._lock:
                    unlink(self.data_file)
            except OSError:  # pragma: no cover
                LOG.warning("Failed to delete %r", self.data_file)
            try:
                unlink(self.lock_file(self.data_file))
            except OSError:  # pragma: no cover
                pass
            self.data_file = None

    def count_result(self, signature):
        """Increment counter that matches `signature`.

        Args:
            signature (str): Signature to increment.

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

    @classmethod
    def load(cls, data_file):
        """Load status report from a file. This will create a read-only status report.

        Args:
            data_file (str): JSON file that contains status data.

        Returns:
            Status: Loaded status object (read-only) or None
        """
        assert data_file
        status = cls(None)
        data = None
        try:
            with InterProcessLock(cls.lock_file(data_file)):
                with open(data_file, "r") as out_fp:
                    data = load(out_fp)
        except OSError:
            LOG.debug("failed to open %r", data_file)
            # if data_file exists the lock will be removed by the active session
            if not isfile(data_file):
                # attempt to remove potentially leaked lock file
                try:
                    unlink(cls.lock_file(data_file))
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
        assert status.start_time <= status.timestamp
        assert status.data_file is None
        return status

    @classmethod
    def loadall(cls, path):
        """Load all status reports found in `path`.

        Args:
            path (str): Path to scan for files containing status data.

        Yields:
            Status: Successfully loaded read-only status objects.
        """
        if isdir(path):
            for entry in scandir(path):
                if entry.is_file() and entry.name.endswith(".json"):
                    status = cls.load(entry.path)
                    if status is not None:
                        yield status

    @staticmethod
    def lock_file(data_file):
        """Name of lock file to use with data_file.

        Args:
            data_file (str): Name of data file.

        Returns:
            str: Lock file name.
        """
        return "%s.lock" % (data_file,)

    @contextmanager
    def measure(self, name):
        """Used to simplify collecting profiling data.

        Args:
            name (str): Used to group the entries.

        Yields:
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
        runtime = self.runtime
        return self.iteration / float(runtime) if runtime else 0

    def record(self, name, duration):
        """Used to add profiling data. This is intended to be used to make rough
        calculations to identify major configuration issues.

        Args:
            name (str): Used to group the entries.
            duration (int, float): Stored to be later used for measurements.

        Returns:
            None
        """
        if self._enable_profiling:
            assert isinstance(duration, (float, int))
            try:
                self._profiles[name]["count"] += 1
                if self._profiles[name]["max"] < duration:
                    self._profiles[name]["max"] = duration
                elif self._profiles[name]["min"] > duration:
                    self._profiles[name]["min"] = duration
                self._profiles[name]["total"] += duration
            except KeyError:
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
        assert self.start_time <= now
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

    @property
    def runtime(self):
        """Calculate the number of seconds since start() was called. Value is
        calculated relative to 'timestamp' if status object is read-only.

        Args:
            None

        Returns:
            int: Total runtime in seconds.
        """
        if self.data_file is None:
            return self.timestamp - self.start_time
        return max(time() - self.start_time, 0)

    def signatures(self):
        """Provide the signature and the number of times it has been found for
        each result.

        Args:
            None

        Yields:
            tuple: Signature and count.
        """
        for sig, count in self._results.items():
            yield (sig, count)

    @classmethod
    def start(cls, path=PATH, enable_profiling=False):
        """Create a unique Status object.

        Args:
            path (str): Location to save files containing status data.
            enable_profiling (bool): Record profiling data.

        Returns:
            Status: Active status report.
        """
        tfd, filepath = mkstemp(dir=path, prefix="grzstatus_", suffix=".json")
        close(tfd)
        status = cls(filepath, enable_profiling=enable_profiling, start_time=time())
        status.pid = getpid()
        status.report(force=True)
        return status
