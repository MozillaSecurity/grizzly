# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from collections import namedtuple
from contextlib import contextmanager
from json import dumps, loads
from logging import getLogger
from os import getpid
from sqlite3 import connect
from time import time

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)

ProfileEntry = namedtuple("ProfileEntry", "count max min name total")


class Status:
    """Status holds status information for the Grizzly session.
    Read-only mode is implied if `_db_file` is None.

    Attributes:
        _db_file (str): Database file containing data. None in read-only mode.
        _enable_profiling (bool): Profiling support status.
        _profiles (dict): Profiling data.
        _results (dict): Results data. Used to count occurrences of results.
        ignored (int): Ignored result count.
        iteration (int): Iteration count.
        log_size (int): Log size in bytes.
        pid (int): Python process ID.
        start_time (float): Start time of session.
        test_name (str): Current test name.
        timestamp (float): Last time data was saved to database.
    """

    DB_VERSION = 1
    # entries older than 'EXP_LIMIT' seconds will be removed.
    EXP_LIMIT = 86400
    # database will be updated no more than every 'REPORT_FREQ' seconds.
    REPORT_FREQ = 60

    __slots__ = (
        "_db_file",
        "_enable_profiling",
        "_profiles",
        "_results",
        "ignored",
        "iteration",
        "log_size",
        "pid",
        "start_time",
        "test_name",
        "timestamp",
    )

    def __init__(
        self, db_file=None, enable_profiling=False, start_time=None, exp_limit=EXP_LIMIT
    ):
        if db_file is None:
            # read-only mode
            assert start_time is None
            self._enable_profiling = False
        else:
            assert isinstance(start_time, float)
            self._enable_profiling = enable_profiling
        self._profiles = dict()
        self._results = dict()
        self._db_file = db_file
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.pid = None
        self.start_time = start_time
        self.test_name = None
        self.timestamp = start_time

        # prepare database
        if self._db_file:
            LOG.debug("using status db %r", self._db_file)
            con = connect(self._db_file)
            try:
                cur = con.cursor()
                # check db version
                cur.execute("PRAGMA user_version;")
                version = cur.fetchone()[0]
                if version < self.DB_VERSION:
                    LOG.debug("db version %d < %d", version, self.DB_VERSION)
                    cur.execute("DROP TABLE IF EXISTS status;")
                    cur.execute("PRAGMA user_version = %d;" % (self.DB_VERSION,))
                    con.commit()
                else:
                    assert version == self.DB_VERSION
                # create tables if needed
                con.execute(
                    """CREATE TABLE IF NOT EXISTS status (
                       _profiles TEXT NOT NULL,
                       _results TEXT NOT NULL,
                       ignored INTEGER NOT NULL,
                       iteration INTEGER NOT NULL,
                       log_size INTEGER NOT NULL,
                       pid INTEGER UNIQUE NOT NULL,
                       start_time REAL NOT NULL,
                       timestamp REAL NOT NULL);"""
                )
                con.commit()
                # remove inactive status data
                if exp_limit > 0:
                    con.execute(
                        """DELETE FROM status WHERE timestamp <= ?;""",
                        (time() - exp_limit,),
                    )
                con.commit()
            finally:
                con.close()

    def count_result(self, uid, description):
        """Increment counter that matches `uid`.

        Args:
            uid (str): Unique identifier.
            description (str): User friendly name (short signature).

        Returns:
            int: Current count.
        """
        if uid not in self._results:
            assert isinstance(uid, str)
            assert isinstance(description, str)
            # create result entry
            self._results[uid] = {
                "count": 0,
                "desc": description,
            }
        self._results[uid]["count"] += 1
        return self._results[uid]["count"]

    @classmethod
    def loadall(cls, db_file, time_limit=300):
        """Load all status reports found in `db_file`.

        Args:
            db_file (str): Path to database containing status data.
            time_limit (int): Only include entries with a timestamp that is within the
                              given number of seconds.

        Yields:
            Status: Successfully loaded read-only status objects.
        """
        assert time_limit >= 0
        con = connect(db_file)
        try:
            cur = con.cursor()
            # check db version
            cur.execute("PRAGMA user_version;")
            assert cur.fetchone()[0] <= cls.DB_VERSION
            # check table exists
            cur.execute(
                """SELECT name
                           FROM sqlite_master
                           WHERE type='table'
                           AND name='status';"""
            )
            if cur.fetchone():
                # collect entries
                cur.execute(
                    """SELECT pid,
                             _profiles,
                             _results,
                             ignored,
                             iteration,
                             log_size,
                             start_time,
                             timestamp
                       FROM status
                       WHERE timestamp > ?;""",
                    (time() - time_limit,),
                )
                entries = cur.fetchall()
            else:
                entries = ()
        finally:
            con.close()

        for entry in entries:
            status = cls()
            status.pid = entry[0]
            status._profiles = loads(entry[1])
            status._results = loads(entry[2])
            status.ignored = entry[3]
            status.iteration = entry[4]
            status.log_size = entry[5]
            status.start_time = entry[6]
            status.timestamp = entry[7]
            yield status

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
        """Write status report to database. Reports are only written periodically.
        It is limited by `report_freq`. The specified number of seconds must
        elapse before another write will be performed unless `force` is True.

        Args:
            force (bool): Ignore report frequently limiting.
            report_freq (int): Minimum number of seconds between writes.

        Returns:
            bool: Returns true if the report was successful otherwise false.
        """
        now = time()
        if not force and now < (self.timestamp + report_freq):
            return False
        assert self._db_file
        assert self.start_time <= now
        self.timestamp = now

        profiles = dumps(self._profiles)
        results = dumps(self._results)
        con = connect(self._db_file)
        try:
            cur = con.cursor()
            cur.execute(
                """UPDATE status
                   SET _profiles = ?,
                       _results = ?,
                       ignored = ?,
                       iteration = ?,
                       log_size = ?,
                       start_time = ?,
                       timestamp = ?
                   WHERE pid = ?;""",
                (
                    profiles,
                    results,
                    self.ignored,
                    self.iteration,
                    self.log_size,
                    self.start_time,
                    self.timestamp,
                    self.pid,
                ),
            )
            if cur.rowcount < 1:
                cur.execute(
                    """INSERT INTO status(
                       pid,
                       _profiles,
                       _results,
                       ignored,
                       iteration,
                       log_size,
                       start_time,
                       timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
                    (
                        self.pid,
                        profiles,
                        results,
                        self.ignored,
                        self.iteration,
                        self.log_size,
                        self.start_time,
                        self.timestamp,
                    ),
                )
            con.commit()
        finally:
            con.close()

        return True

    @property
    def results(self):
        """Calculate the total number of results.

        Args:
            None

        Returns:
            int: Total number of results.
        """
        return sum(x["count"] for x in self._results.values())

    def result_entries(self):
        """Provide unique result entries.

        Args:
            None

        Yields:
            dict: Result entry.
        """
        for uid, result in self._results.items():
            yield uid, result

    @property
    def runtime(self):
        """Calculate the number of seconds since start() was called. Value is
        calculated relative to 'timestamp' if status object is read-only.

        Args:
            None

        Returns:
            int: Total runtime in seconds.
        """
        if self._db_file is None:
            return self.timestamp - self.start_time
        return max(time() - self.start_time, 0)

    @classmethod
    def start(cls, db_file, enable_profiling=False):
        """Create a unique Status object.

        Args:
            db_file (str): Path to database containing status data.
            enable_profiling (bool): Record profiling data.

        Returns:
            Status: Active status report.
        """
        assert db_file
        pid = getpid()
        status = cls(
            db_file=db_file, enable_profiling=enable_profiling, start_time=time()
        )
        status.pid = pid
        status.report(force=True)
        return status
