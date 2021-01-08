# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from collections import defaultdict
from json import dump, load
from logging import getLogger
from os import close, listdir, unlink
from os.path import isdir, isfile, join as pathjoin
from tempfile import mkstemp
from time import time

from fasteners.process_lock import InterProcessLock

from .utils import grz_tmp

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class Status:
    """Status holds status information for the Grizzly session.
    There can be multiple readers of the data but only a single writer.
    """
    PATH = grz_tmp("status")
    REPORT_FREQ = 60

    __slots__ = (
        "_lock", "_results", "data_file", "ignored", "iteration",
        "log_size", "start_time", "test_name", "timestamp")

    def __init__(self, data_file, start_time=None):
        assert ".json" in data_file
        assert start_time is None or isinstance(start_time, float)
        self._lock = InterProcessLock("%s.lock" % (data_file,))
        self._results = defaultdict(int)
        # if data_file is None the status report is read only (no reporting)
        self.data_file = data_file
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
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
        with self._lock:
            try:
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
            "_results": self._results,
            "ignored": self.ignored,
            "iteration": self.iteration,
            "log_size": self.log_size,
            "start_time": self.start_time,
            "test_name": self.test_name,
            "timestamp": self.timestamp}

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

    def report(self, force=False, report_freq=REPORT_FREQ):
        """Write status report. Reports are only written when the time since the
        previous report was created exceeds `report_freq` seconds.

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

    @classmethod
    def start(cls):
        """Create a unique Status object.

        Args:
            None

        Returns:
            Status: Active status report.
        """
        tfd, filepath = mkstemp(dir=cls.PATH, prefix="grzstatus_", suffix=".json")
        close(tfd)
        status = cls(filepath, start_time=time())
        status.report(force=True)
        return status
