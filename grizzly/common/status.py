# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
import json
import logging
import os
import tempfile
import time

import fasteners

__all__ = ("ReducerStats", "Status")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = logging.getLogger("status")


class Status(object):
    """Status holds status information for the Grizzly session.
    There can be multiple readers of the data but only a single writer.
    """
    AGE_LIMIT = 3600  # 1 hour
    PATH = os.path.join(tempfile.gettempdir(), "grzstatus")
    REPORT_FREQ = 60

    __slots__ = (
        "_lock", "data_file", "ignored", "iteration", "log_size", "results",
        "start_time", "test_name", "timestamp")

    def __init__(self, data_file, start_time):
        assert isinstance(data_file, str) and os.path.isfile(data_file)
        assert isinstance(start_time, float)
        self._lock = fasteners.process_lock.InterProcessLock("%s.lock" % (data_file,))
        self.data_file = data_file
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.results = 0
        self.start_time = start_time
        self.test_name = None
        self.timestamp = start_time

    def cleanup(self):
        """Remove data file.

        Args:
            None

        Returns:
            None
        """
        if self.data_file is None:
            return
        with self._lock:
            try:
                if os.path.isfile(self.data_file):
                    os.unlink(self.data_file)
            except OSError:
                LOG.warning("Failed to delete %r", self.data_file)
            lock_file = "%s.lock" % (self.data_file,)
            self.data_file = None
        if os.path.isfile(lock_file):
            try:
                os.unlink(lock_file)
            except OSError:
                pass

    @property
    def duration(self):
        """Calculate the number of second since start() was called

        Args:
            None

        Returns:
            int: Total runtime in seconds since start() was called
        """
        return max(self.timestamp - self.start_time, 0)

    @classmethod
    def load(cls, data_file):
        """Read Grizzly status report.

        Args:
            data_file (str): JSON file that contains status data.

        Returns:
            Status: Loaded status object or None
        """
        if not os.path.isfile(data_file):
            return None
        with fasteners.process_lock.InterProcessLock("%s.lock" % (data_file,)):
            with open(data_file, "r") as out_fp:
                try:
                    data = json.load(out_fp)
                except ValueError:
                    LOG.debug("failed to json")
                    return None
        status = cls(data_file, data["start_time"])
        for attr, value in data.items():
            setattr(status, attr, value)
        return status

    @classmethod
    def loadall(cls):
        """Read all Grizzly status reports found in cls.PATH.

        Args:
            None

        Returns:
            Generator: Status objects stored in cls.PATH.
        """
        if not os.path.isdir(cls.PATH):
            return
        for data_file in os.listdir(cls.PATH):
            if not data_file.endswith(".json"):
                continue
            status = cls.load(os.path.join(cls.PATH, data_file))
            if status is None:
                continue
            yield status

    @property
    def rate(self):
        """Calculate the number of iterations performed per second since start() was called

        Args:
            None

        Returns:
            float: Number of iterations performed per second
        """
        return self.iteration / float(self.duration) if self.duration > 0 else 0

    @property
    def _data(self):
        return {
            "ignored": self.ignored,
            "iteration": self.iteration,
            "log_size": self.log_size,
            "results": self.results,
            "start_time": self.start_time,
            "test_name": self.test_name,
            "timestamp": self.timestamp}

    def report(self, force=False, report_freq=REPORT_FREQ):
        """Write Grizzly status report. Reports are only written when the duration
        of time since the previous report was created exceeds `report_freq` seconds

        Args:
            force (bool): Ignore report frequently limiting.
            report_freq (int): Minimum number of seconds between writes.

        Returns:
            bool: Returns true if the report was successful otherwise false
        """
        now = time.time()
        if not force and now < (self.timestamp + report_freq):
            return False
        self.timestamp = now
        with self._lock:
            with open(self.data_file, "w") as out_fp:
                json.dump(self._data, out_fp)
        return True

    @classmethod
    def start(cls):
        """Create a unique Status object.

        Args:
            None

        Returns:
            Status: Ready to be used to report Grizzly status
        """
        if not os.path.isdir(cls.PATH):
            try:
                os.mkdir(cls.PATH)
            except OSError:
                if not os.path.isdir(cls.PATH):
                    raise
        tfd, filepath = tempfile.mkstemp(dir=cls.PATH, prefix="grzstatus_", suffix=".json")
        os.close(tfd)
        status = cls(filepath, time.time())
        status.report(force=True)
        return status


class ReducerStats(object):
    """ReducerStats holds stats for the Grizzly reducer.
    """

    FILE = "reducer-stats.json"
    PATH = tempfile.gettempdir()

    def __init__(self):
        if not os.path.isdir(self.PATH):
            raise OSError("Missing directory %r" % self.PATH)
        self._file = os.path.join(self.PATH, self.FILE)
        self._lock = None
        self.error = 0
        self.failed = 0
        self.passed = 0

    def __enter__(self):
        self._lock = fasteners.process_lock.InterProcessLock("%s.lock" % (self._file,))
        self._lock.acquire()
        try:
            with open(self._file, "r") as in_fp:
                data = json.load(in_fp)
            self.error = data["error"]
            self.failed = data["failed"]
            self.passed = data["passed"]
        except IOError:
            LOG.debug("%r does not exist", self._file)
        except ValueError:
            LOG.debug("failed to load stats from %r", self._file)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            with open(self._file, "w") as out_fp:
                json.dump({
                    "error": self.error,
                    "failed": self.failed,
                    "passed": self.passed}, out_fp)
        finally:
            if self._lock:
                self._lock.release()
            self._lock = None
