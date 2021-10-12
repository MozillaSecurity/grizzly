# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from collections import defaultdict, namedtuple
from contextlib import contextmanager
from json import dumps, loads
from logging import getLogger
from os import getpid
from sqlite3 import connect
from time import time

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

# used to track changes to the database layout
DB_VERSION = 1
# default expiration limit for entries in the database
EXP_LIMIT = 86400
LOG = getLogger(__name__)

ProfileEntry = namedtuple("ProfileEntry", "count max min name total")


def _db_version_check(db_file, expected=DB_VERSION):
    """Perform version check and remove obsolete tables if required.

    Args:
        db_file (str): Database file containing data.
        expected (int): The latest database version.

    Returns:
        bool: True if database was reset otherwise False.
    """
    assert expected > 0
    with connect(db_file, isolation_level=None) as con:
        cur = con.cursor()
        # collect db version
        cur.execute("PRAGMA user_version;")
        version = cur.fetchone()[0]
        # check if an update is required
        if version < expected:
            cur.execute("BEGIN EXCLUSIVE;")
            # check db version while locked to avoid race
            cur.execute("PRAGMA user_version;")
            version = cur.fetchone()[0]
            if version < expected:
                LOG.debug("db version %d < %d", version, expected)
                # remove ALL tables from the database
                cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
                for entry in cur.fetchall():
                    LOG.debug("dropping table %r", entry[0])
                    cur.execute("DROP TABLE IF EXISTS %s;" % (entry[0],))
                # update db version number
                cur.execute("PRAGMA user_version = %d;" % (expected,))
                con.commit()
                return True
    assert version == expected, "code out of date?"
    return False


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

    # database will be updated no more than every 'REPORT_FREQ' seconds.
    REPORT_FREQ = 60

    __slots__ = (
        "_db_file",
        "_enable_profiling",
        "_profiles",
        "results",
        "ignored",
        "iteration",
        "log_size",
        "pid",
        "start_time",
        "test_name",
        "timestamp",
    )

    def __init__(
        self,
        db_file=None,
        enable_profiling=False,
        start_time=None,
        exp_limit=EXP_LIMIT,
        pid=None,
        report_limit=0,
    ):
        if db_file is None:
            # read-only mode
            assert start_time is None
            self._enable_profiling = False
        else:
            assert isinstance(start_time, float)
            assert exp_limit >= 0
            assert report_limit >= 0
            assert pid >= 0
            self._enable_profiling = enable_profiling
        self._profiles = dict()
        self._db_file = db_file
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.pid = pid
        self.results = None
        self.start_time = start_time
        self.test_name = None
        self.timestamp = start_time

        # prepare database
        if self._db_file:
            LOG.debug("status using db %r", self._db_file)
            _db_version_check(self._db_file)
            with connect(self._db_file) as con:
                # create table if needed
                con.execute(
                    """CREATE TABLE IF NOT EXISTS status (
                       _profiles TEXT NOT NULL,
                       ignored INTEGER NOT NULL,
                       iteration INTEGER NOT NULL,
                       log_size INTEGER NOT NULL,
                       pid INTEGER UNIQUE NOT NULL,
                       start_time REAL NOT NULL,
                       timestamp REAL NOT NULL);"""
                )
                # remove expired status data
                if exp_limit > 0:
                    con.execute(
                        """DELETE FROM status WHERE timestamp <= ?;""",
                        (time() - exp_limit,),
                    )
                # avoid (unlikely) pid reuse collision
                con.execute("""DELETE FROM status WHERE pid = ?;""", (pid,))
                con.commit()

            self.results = ResultCounter(
                pid,
                db_file=db_file,
                exp_limit=EXP_LIMIT,
                freq_limit=report_limit,
            )

    def blockers(self, iters_per_result=100):
        """Any result with an iterations-per-result ratio of less than or equal the
        given limit are considered 'blockers'.

        Args:
            iters_per_result (int): Iterations-per-result threshold.

        Yields:
            tuple(int, str): Count and description of result.
        """
        assert iters_per_result > 0
        if self.results:
            for _, count, desc in self.results.all():
                if self.iteration / count <= iters_per_result:
                    yield count, desc

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
        assert db_file
        assert time_limit >= 0
        with connect(db_file) as con:
            cur = con.cursor()
            # check table exists
            cur.execute(
                """SELECT name
                   FROM sqlite_master
                   WHERE type='table'
                   AND name='status';"""
            )
            if cur.fetchone():
                # check db version
                cur.execute("PRAGMA user_version;")
                assert cur.fetchone()[0] == DB_VERSION, "code out of date?"
                # collect entries
                cur.execute(
                    """SELECT pid,
                             _profiles,
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

        results = ResultCounter.load(db_file, time_limit)

        for entry in entries:
            status = cls(pid=entry[0])
            status._profiles = loads(entry[1])
            status.ignored = entry[2]
            status.iteration = entry[3]
            status.log_size = entry[4]
            status.start_time = entry[5]
            status.timestamp = entry[6]
            for counter in results:
                if counter.pid == status.pid:
                    status.results = counter
                    break
            else:
                # no existing ResultCounter with matching pid found
                status.results = ResultCounter(status.pid)
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
        with connect(self._db_file) as con:
            cur = con.cursor()
            cur.execute(
                """UPDATE status
                   SET _profiles = ?,
                       ignored = ?,
                       iteration = ?,
                       log_size = ?,
                       start_time = ?,
                       timestamp = ?
                   WHERE pid = ?;""",
                (
                    profiles,
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
                       ignored,
                       iteration,
                       log_size,
                       start_time,
                       timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?);""",
                    (
                        self.pid,
                        profiles,
                        self.ignored,
                        self.iteration,
                        self.log_size,
                        self.start_time,
                        self.timestamp,
                    ),
                )
            con.commit()

        return True

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
    def start(cls, db_file, enable_profiling=False, report_limit=0):
        """Create a unique Status object.

        Args:
            db_file (str): Path to database containing status data.
            enable_profiling (bool): Record profiling data.

        Returns:
            Status: Active status report.
        """
        assert db_file
        status = cls(
            db_file=db_file,
            enable_profiling=enable_profiling,
            start_time=time(),
            pid=getpid(),
            report_limit=report_limit,
        )
        status.report(force=True)
        return status


class ResultCounter:
    __slots__ = (
        "_count",
        "_db_file",
        "_desc",
        "_frequent",
        "_limit",
        "pid",
    )

    def __init__(self, pid, db_file=None, exp_limit=EXP_LIMIT, freq_limit=0):
        assert exp_limit >= 0
        assert freq_limit >= 0
        assert pid >= 0
        self._count = defaultdict(int)
        self._desc = dict()
        self._db_file = db_file
        self._frequent = set()
        self._limit = freq_limit
        self.pid = pid

        # prepare database
        if self._db_file:
            LOG.debug("resultcounter using db %r", self._db_file)
            _db_version_check(self._db_file)
            with connect(self._db_file) as con:
                # create table if needed
                con.execute(
                    """CREATE TABLE IF NOT EXISTS results (
                       count INTEGER NOT NULL,
                       description TEXT NOT NULL,
                       pid INTEGER NOT NULL,
                       result_id TEXT NOT NULL,
                       timestamp INTEGER NOT NULL);"""
                )
                # remove expired entries
                if exp_limit > 0:
                    con.execute(
                        """DELETE FROM results WHERE timestamp <= ?;""",
                        (int(time() - exp_limit),),
                    )
                # avoid (unlikely) pid reuse collision
                con.execute("""DELETE FROM results WHERE pid = ?;""", (pid,))
                con.commit()

    def all(self):
        """Yield all result data.

        Args:
            None

        Yields:
            tuple: Contains result_id, count and description for each entry.
        """
        for result_id, count in self._count.items():
            if count > 0:
                yield (result_id, count, self._desc.get(result_id, None))

    def count(self, result_id, desc):
        """

        Args:
            result_id (str): Result ID.
            desc (str): User friendly description.

        Returns:
            int: Current count for given result_id.
        """
        assert isinstance(result_id, str)
        self._count[result_id] += 1
        if result_id not in self._desc:
            self._desc[result_id] = desc
        if self._db_file:
            with connect(self._db_file) as con:
                timestamp = int(time())
                cur = con.cursor()
                cur.execute(
                    """UPDATE results
                       SET timestamp = ?,
                           count = ?
                       WHERE pid = ?
                       AND result_id = ?;""",
                    (timestamp, self._count[result_id], self.pid, result_id),
                )
                if cur.rowcount < 1:
                    cur.execute(
                        """INSERT INTO results(
                           pid,
                           result_id,
                           description,
                           timestamp,
                           count)
                           VALUES (?, ?, ?, ?, ?);""",
                        (
                            self.pid,
                            result_id,
                            desc,
                            timestamp,
                            self._count[result_id],
                        ),
                    )
                con.commit()
        return self._count[result_id]

    @classmethod
    def load(cls, db_file, time_limit):
        """Load existing entries for database and populate a ResultCounter.

        Args:
            db_file (str): Database file.
            time_limit (int): Used to filter older entries.

        Returns:
            list: Loaded ResultCounters.
        """
        assert db_file
        assert time_limit >= 0
        with connect(db_file) as con:
            cur = con.cursor()
            # check table exists
            cur.execute(
                """SELECT name
                   FROM sqlite_master
                   WHERE type='table'
                   AND name='results';"""
            )
            if cur.fetchone():
                # check db version
                cur.execute("PRAGMA user_version;")
                assert cur.fetchone()[0] == DB_VERSION, "code out of date?"
                # collect entries
                cur.execute(
                    """SELECT pid,
                              result_id,
                              description,
                              count
                       FROM results
                       WHERE timestamp > ?;""",
                    (int(time()) - time_limit,),
                )
                entries = cur.fetchall()
            else:
                entries = ()

        loaded = dict()
        for pid, result_id, desc, count in entries:
            if pid not in loaded:
                loaded[pid] = cls(pid)
            loaded[pid]._desc[result_id] = desc
            loaded[pid]._count[result_id] = count

        return list(loaded.values())

    def get(self, result_id):
        """Get count and description for given result id.

        Args:
            result_id (str): Result ID.

        Returns:
            tuple: Count and description.
        """
        assert isinstance(result_id, str)
        return (self._count.get(result_id, 0), self._desc.get(result_id, None))

    def is_frequent(self, result_id):
        """Scan all results including results from other running instances
        to determine if the limit has been exceeded. Local count must be >1 before
        limit is checked.

        Args:
            result_id (str): Result ID.

        Returns:
            bool: True if limit has been exceeded otherwise False.
        """
        assert isinstance(result_id, str)
        if self._limit < 1:
            return False
        if result_id in self._frequent:
            return True
        total = self._count.get(result_id, 0)
        # only count for parallel results if more than 1 local result has been found
        if total > 1 and self._db_file:
            # look up count from all sources
            with connect(self._db_file) as con:
                cur = con.cursor()
                cur.execute(
                    """SELECT SUM(count) FROM results WHERE result_id = ?;""",
                    (result_id,),
                )
                total = cur.fetchone()[0] or 0
        if total > self._limit:
            self._frequent.add(result_id)
            return True
        return False

    def mark_frequent(self, result_id):
        """Mark given results ID as frequent locally.

        Args:
            result_id (str): Result ID.

        Returns:
            None
        """
        assert isinstance(result_id, str)
        if result_id not in self._frequent:
            self._frequent.add(result_id)

    @property
    def total(self):
        """Get total count of all results.

        Args:
            None

        Returns:
            int: Total result count.
        """
        return sum(x for x in self._count.values())
