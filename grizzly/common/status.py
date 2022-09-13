# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from collections import defaultdict, namedtuple
from contextlib import closing, contextmanager
from copy import deepcopy
from json import dumps, loads
from logging import getLogger
from os import getpid
from pathlib import Path
from sqlite3 import OperationalError, connect
from time import time

from ..common.utils import grz_tmp

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

# time in seconds for db connection to wait before raising an exception
DB_TIMEOUT = 30
# used to track changes to the database layout
DB_VERSION = 2
# default expiration limit for report entries in the database (24 hours)
REPORT_EXP_LIMIT = 86400
# default expiration limit for result entries in the database (30 days)
RESULT_EXP_LIMIT = 2592000
LOG = getLogger(__name__)

ProfileEntry = namedtuple("ProfileEntry", "count max min name total")

ResultEntry = namedtuple("ResultEntry", "rid count desc")


def _db_version_check(con, expected=DB_VERSION):
    """Perform version check and remove obsolete tables if required.

    Args:
        con (sqlite3.Connection): An open database connection.
        expected (int): The latest database version.

    Returns:
        bool: True if database was reset otherwise False.
    """
    assert expected > 0
    cur = con.cursor()
    # collect db version and check if an update is required
    cur.execute("PRAGMA user_version;")
    version = cur.fetchone()[0]
    if version < expected:
        cur.execute("BEGIN EXCLUSIVE;")
        # check db version again while locked to avoid race
        cur.execute("PRAGMA user_version;")
        version = cur.fetchone()[0]
        if version < expected:
            LOG.debug("db version %d < %d", version, expected)
            # remove ALL tables from the database
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            with con:
                for entry in cur.fetchall():
                    LOG.debug("dropping table %r", entry[0])
                    cur.execute("DROP TABLE IF EXISTS %s;" % (entry[0],))
                # update db version number
                cur.execute("PRAGMA user_version = %d;" % (expected,))
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

    STATUS_DB = str(Path(grz_tmp()) / "fuzz-status.db")

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
        exp_limit=REPORT_EXP_LIMIT,
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
            with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
                _db_version_check(con)
                cur = con.cursor()
                with con:
                    # create table if needed
                    cur.execute(
                        """CREATE TABLE IF NOT EXISTS status (
                           _profiles TEXT NOT NULL,
                           ignored INTEGER NOT NULL,
                           iteration INTEGER NOT NULL,
                           log_size INTEGER NOT NULL,
                           pid INTEGER NOT NULL PRIMARY KEY,
                           start_time REAL NOT NULL,
                           timestamp REAL NOT NULL);"""
                    )
                    # remove expired status data
                    if exp_limit > 0:
                        cur.execute(
                            """DELETE FROM status WHERE timestamp <= ?;""",
                            (time() - exp_limit,),
                        )
                    # avoid (unlikely) pid reuse collision
                    cur.execute("""DELETE FROM status WHERE pid = ?;""", (pid,))

            self.results = ResultCounter(
                pid,
                db_file=db_file,
                freq_limit=report_limit,
            )

    def blockers(self, iters_per_result=100):
        """Any result with an iterations-per-result ratio of less than or equal the
        given limit are considered 'blockers'. Results with a count <= 1 are not
        included.

        Args:
            iters_per_result (int): Iterations-per-result threshold.

        Yields:
            ResultEntry: ID, count and description of blocking result.
        """
        assert iters_per_result > 0
        if self.results:
            for entry in self.results.all():
                if entry.count > 1 and self.iteration / entry.count <= iters_per_result:
                    yield entry

    @classmethod
    def loadall(cls, db_file=STATUS_DB, time_limit=300):
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
        with closing(connect(db_file, timeout=DB_TIMEOUT)) as con:
            cur = con.cursor()
            # collect entries
            try:
                if time_limit:
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
                else:
                    cur.execute(
                        """SELECT pid,
                                  _profiles,
                                  ignored,
                                  iteration,
                                  log_size,
                                  start_time,
                                  timestamp
                           FROM status;"""
                    )
                entries = cur.fetchall()
            except OperationalError as exc:
                if not str(exc).startswith("no such table:"):
                    raise  # pragma: no cover
                entries = ()

        # Load all results
        results = ResultCounter.load(db_file, 0)
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
        with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
            cur = con.cursor()
            with con:
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
    def start(cls, db_file=None, enable_profiling=False, report_limit=0):
        """Create a unique Status object.

        Args:
            db_file (str): Path to database containing status data.
            enable_profiling (bool): Record profiling data.

        Returns:
            Status: Active status report.
        """
        if db_file is None:
            db_file = cls.STATUS_DB
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

    def __init__(self, pid, db_file=None, exp_limit=RESULT_EXP_LIMIT, freq_limit=0):
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
            with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
                _db_version_check(con)
                cur = con.cursor()
                with con:
                    # create table if needed
                    cur.execute(
                        """CREATE TABLE IF NOT EXISTS results (
                           count INTEGER NOT NULL,
                           description TEXT NOT NULL,
                           pid INTEGER NOT NULL,
                           result_id TEXT NOT NULL,
                           timestamp INTEGER NOT NULL,
                           PRIMARY KEY(pid, result_id));"""
                    )
                    # remove expired entries
                    if exp_limit > 0:
                        cur.execute(
                            """DELETE FROM results WHERE timestamp <= ?;""",
                            (int(time() - exp_limit),),
                        )
                    # avoid (unlikely) pid reuse collision
                    cur.execute("""DELETE FROM results WHERE pid = ?;""", (pid,))
                    # remove results for jobs that have been removed
                    try:
                        cur.execute(
                            """DELETE FROM results
                               WHERE pid NOT IN (SELECT pid FROM status);"""
                        )
                    except OperationalError as exc:
                        if not str(exc).startswith("no such table:"):
                            raise  # pragma: no cover

    def all(self):
        """Yield all result data.

        Args:
            None

        Yields:
            ResultEntry: Contains ID, count and description for each result entry.
        """
        for result_id, count in self._count.items():
            if count > 0:
                yield ResultEntry(result_id, count, self._desc.get(result_id, None))

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
            with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
                cur = con.cursor()
                timestamp = int(time())
                with con:
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
        with closing(connect(db_file, timeout=DB_TIMEOUT)) as con:
            cur = con.cursor()
            try:
                # collect entries
                if time_limit:
                    cur.execute(
                        """SELECT pid,
                                result_id,
                                description,
                                count
                           FROM results
                           WHERE timestamp > ?;""",
                        (int(time()) - time_limit,),
                    )
                else:
                    cur.execute(
                        """SELECT pid, result_id, description, count FROM results"""
                    )
                entries = cur.fetchall()
            except OperationalError as exc:
                if not str(exc).startswith("no such table:"):
                    raise  # pragma: no cover
                entries = ()

        loaded = dict()
        for pid, result_id, desc, count in entries:
            if pid not in loaded:
                loaded[pid] = cls(pid)
            loaded[pid]._desc[result_id] = desc  # pylint: disable=protected-access
            loaded[pid]._count[result_id] = count  # pylint: disable=protected-access

        return list(loaded.values())

    def get(self, result_id):
        """Get count and description for given result id.

        Args:
            result_id (str): Result ID.

        Returns:
            ResultEntry: Count and description.
        """
        assert isinstance(result_id, str)
        return ResultEntry(
            result_id, self._count.get(result_id, 0), self._desc.get(result_id, None)
        )

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
        # get local total
        total = self._count.get(result_id, 0)
        # only check the db for parallel results if
        # - result has been found locally more than once
        # - limit has not been exceeded locally
        # - a db file is given
        if self._limit >= total > 1 and self._db_file:
            with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
                cur = con.cursor()
                # look up total count from all processes
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


ReductionStep = namedtuple(
    "ReductionStep", "name, duration, successes, attempts, size, iterations"
)


class ReductionStatus:
    """Status for a single grizzly reduction"""

    # database will be updated no more than every 'REPORT_FREQ' seconds.
    REPORT_FREQ = 60

    STATUS_DB = str(Path(grz_tmp()) / "reduce-status.db")

    def __init__(
        self,
        strategies=None,
        testcase_size_cb=None,
        crash_id=None,
        db_file=None,
        pid=None,
        tool=None,
        exp_limit=REPORT_EXP_LIMIT,
    ):
        """Initialize a ReductionStatus instance.

        Arguments:
            strategies (list(str)): List of strategies to be run.
            testcase_size_cb (callable): Callback to get testcase size
            crash_id (int): CrashManager ID of original testcase
            db_file (str): Database file containing data. None in read-only mode.
            tool (str): The tool name used for reporting to FuzzManager.
        """
        self.analysis = {}
        self.attempts = 0
        self.iterations = 0
        self.run_params = {}
        self.signature_info = {}
        self.successes = 0
        self.current_strategy_idx = None
        self._testcase_size_cb = testcase_size_cb
        self.crash_id = crash_id
        self.finished_steps = []
        self._in_progress_steps = []
        self.strategies = strategies
        self._db_file = db_file
        self.pid = pid
        self.timestamp = time()
        self.tool = tool
        self._current_size = None
        self.last_reports = []

        # prepare database
        if self._db_file:
            LOG.debug("status using db %r", self._db_file)
            with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
                _db_version_check(con)
                cur = con.cursor()
                with con:
                    # create table if needed
                    cur.execute(
                        """CREATE TABLE IF NOT EXISTS reduce_status (
                           pid INTEGER NOT NULL PRIMARY KEY,
                           analysis TEXT NOT NULL,
                           attempts INTEGER NOT NULL,
                           iterations INTEGER NOT NULL,
                           run_params TEXT NOT NULL,
                           signature_info TEXT NOT NULL,
                           successes INTEGER NOT NULL,
                           crash_id INTEGER,
                           finished_steps TEXT NOT NULL,
                           _in_progress_steps TEXT NOT NULL,
                           strategies TEXT NOT NULL,
                           _current_size INTEGER NOT NULL,
                           current_strategy_idx INTEGER,
                           timestamp REAL NOT NULL,
                           tool TEXT,
                           last_reports TEXT NOT NULL);"""
                    )
                    # remove expired status data
                    if exp_limit > 0:
                        cur.execute(
                            """DELETE FROM reduce_status WHERE timestamp <= ?;""",
                            (time() - exp_limit,),
                        )
                    # avoid (unlikely) pid reuse collision
                    cur.execute("""DELETE FROM reduce_status WHERE pid = ?;""", (pid,))

    @classmethod
    def start(
        cls,
        db_file=None,
        strategies=None,
        testcase_size_cb=None,
        crash_id=None,
        tool=None,
    ):
        """Create a unique ReductionStatus object.

        Args:
            db_file (str): Path to database containing status data.
            strategies (list(str)): List of strategies to be run.
            testcase_size_cb (callable): Callback to get testcase size
            crash_id (int): CrashManager ID of original testcase
            tool (str): The tool name used for reporting to FuzzManager.

        Returns:
            ReductionStatus: Active status report.
        """
        if db_file is None:
            db_file = cls.STATUS_DB
        status = cls(
            crash_id=crash_id,
            db_file=db_file,
            pid=getpid(),
            strategies=strategies,
            testcase_size_cb=testcase_size_cb,
            tool=tool,
        )
        status.report(force=True)
        return status

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
        self.timestamp = now

        with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
            cur = con.cursor()
            with con:
                analysis = dumps(self.analysis)
                run_params = dumps(self.run_params)
                sig_info = dumps(self.signature_info)
                finished = dumps(self.finished_steps)
                in_prog = dumps([step.serialize() for step in self._in_progress_steps])
                strategies = dumps(self.strategies)
                last_reports = dumps(self.last_reports)

                cur.execute(
                    """UPDATE reduce_status
                       SET analysis = ?,
                           attempts = ?,
                           iterations = ?,
                           run_params = ?,
                           signature_info = ?,
                           successes = ?,
                           crash_id = ?,
                           finished_steps = ?,
                           _in_progress_steps = ?,
                           strategies = ?,
                           _current_size = ?,
                           current_strategy_idx = ?,
                           timestamp = ?,
                           tool = ?,
                           last_reports = ?
                       WHERE pid = ?;""",
                    (
                        analysis,
                        self.attempts,
                        self.iterations,
                        run_params,
                        sig_info,
                        self.successes,
                        self.crash_id,
                        finished,
                        in_prog,
                        strategies,
                        self._testcase_size(),
                        self.current_strategy_idx,
                        self.timestamp,
                        self.tool,
                        last_reports,
                        self.pid,
                    ),
                )
                if cur.rowcount < 1:
                    cur.execute(
                        """INSERT INTO reduce_status(
                               pid,
                               analysis,
                               attempts,
                               iterations,
                               run_params,
                               signature_info,
                               successes,
                               crash_id,
                               finished_steps,
                               _in_progress_steps,
                               strategies,
                               _current_size,
                               current_strategy_idx,
                               timestamp,
                               tool,
                               last_reports)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                        (
                            self.pid,
                            analysis,
                            self.attempts,
                            self.iterations,
                            run_params,
                            sig_info,
                            self.successes,
                            self.crash_id,
                            finished,
                            in_prog,
                            strategies,
                            self._testcase_size(),
                            self.current_strategy_idx,
                            self.timestamp,
                            self.tool,
                            last_reports,
                        ),
                    )

        return True

    @classmethod
    def loadall(cls, db_file=STATUS_DB, time_limit=300):
        """Load all reduction status reports found in `db_file`.

        Args:
            db_file (str): Path to database containing status data.
            time_limit (int): Only include entries with a timestamp that is within the
                              given number of seconds.

        Yields:
            Status: Successfully loaded read-only status objects.
        """
        assert db_file
        assert time_limit >= 0
        with closing(connect(db_file, timeout=DB_TIMEOUT)) as con:
            cur = con.cursor()
            # collect entries
            try:
                cur.execute(
                    """SELECT pid,
                              analysis,
                              attempts,
                              iterations,
                              run_params,
                              signature_info,
                              successes,
                              crash_id,
                              finished_steps,
                              _in_progress_steps,
                              strategies,
                              _current_size,
                              current_strategy_idx,
                              timestamp,
                              tool,
                              last_reports
                       FROM reduce_status
                       WHERE timestamp > ?
                       ORDER BY timestamp DESC;""",
                    (time() - time_limit,),
                )
                entries = cur.fetchall()
            except OperationalError as exc:
                if not str(exc).startswith("no such table:"):
                    raise  # pragma: no cover
                entries = ()

        for entry in entries:
            pid = entry[0]

            status = cls(
                strategies=loads(entry[10]),
                crash_id=entry[7],
                pid=pid,
                tool=entry[14],
            )
            status.analysis = loads(entry[1])
            status.attempts = entry[2]
            status.iterations = entry[3]
            status.run_params = loads(entry[4])
            status.signature_info = loads(entry[5])
            status.successes = entry[6]
            status.finished_steps = [
                ReductionStep._make(step) for step in loads(entry[8])
            ]
            status._in_progress_steps = [
                status._construct_milestone(*step) for step in loads(entry[9])
            ]
            status._current_size = entry[11]
            status.current_strategy_idx = entry[12]
            status.timestamp = entry[13]
            status.last_reports = loads(entry[15])
            yield status

    def _testcase_size(self):
        if self._db_file is None:
            return self._current_size
        return self._testcase_size_cb()

    def __deepcopy__(self, memo):
        """Return a deep copy of this instance."""
        # pylint: disable=protected-access
        result = type(self)(
            strategies=deepcopy(self.strategies, memo),
            crash_id=self.crash_id,
            testcase_size_cb=self._testcase_size_cb,
            pid=self.pid,
            tool=self.tool,
        )
        # assign after construction to avoid DB access
        result._db_file = self._db_file
        result.analysis = deepcopy(self.analysis, memo)
        result.attempts = self.attempts
        result.iterations = self.iterations
        result.run_params = deepcopy(self.run_params, memo)
        result.signature_info = deepcopy(self.signature_info, memo)
        result.successes = self.successes
        result.finished_steps = deepcopy(self.finished_steps, memo)
        result.last_reports = deepcopy(self.last_reports, memo)
        # finish open timers
        for step in reversed(self._in_progress_steps):
            result.record(
                step.name,
                attempts=step.attempts,
                duration=step.duration,
                iterations=step.iterations,
                successes=step.successes,
                report=False,
            )
        return result

    @property
    def current_strategy(self):
        if self._in_progress_steps:
            return self._in_progress_steps[-1]
        if self.finished_steps:
            return self.finished_steps[-1]
        return None

    @property
    def total(self):
        if self._in_progress_steps:
            return self._in_progress_steps[0]
        if self.finished_steps:
            return self.finished_steps[-1]
        return None

    @property
    def original(self):
        if self.finished_steps:
            return self.finished_steps[0]
        return None

    def record(
        self,
        name,
        duration=None,
        iterations=None,
        attempts=None,
        successes=None,
        report=True,
    ):
        """Record reduction status for a given point in time:

        - name of the milestone (eg. init, strategy name completed)
        - elapsed time (seconds)
        - # of iterations
        - # of total attempts
        - # of successful attempts

        Arguments:
            name (str): name of milestone
            duration (float or None): seconds elapsed for period recorded
            iterations (int or None): # of iterations performed
            attempts (int or None): # of attempts performed
            successes (int or None): # of attempts successful
            report (bool): Automatically force a report.

        Returns:
            None
        """
        self.finished_steps.append(
            ReductionStep(
                name=name,
                size=self._testcase_size(),
                duration=duration,
                iterations=iterations,
                attempts=attempts,
                successes=successes,
            )
        )
        if report:
            self.report(force=True)

    def _construct_milestone(self, name, start, attempts, iterations, successes):
        # pylint: disable=no-self-argument
        class _MilestoneTimer:
            def __init__(sub):
                sub.name = name
                sub._start_time = start
                sub._start_attempts = attempts
                sub._start_iterations = iterations
                sub._start_successes = successes

            @property
            def size(sub):
                return self._testcase_size()  # pylint: disable=protected-access

            @property
            def attempts(sub):
                return self.attempts - sub._start_attempts

            @property
            def iterations(sub):
                return self.iterations - sub._start_iterations

            @property
            def successes(sub):
                return self.successes - sub._start_successes

            @property
            def duration(sub):
                if self._db_file is None:  # pylint: disable=protected-access
                    return self.timestamp - sub._start_time
                return time() - sub._start_time

            def serialize(sub):
                return (
                    sub.name,
                    sub._start_time,
                    sub._start_attempts,
                    sub._start_iterations,
                    sub._start_successes,
                )

        return _MilestoneTimer()

    @contextmanager
    def measure(self, name, report=True):
        """Time and record the period leading up to a reduction milestone.
        eg. a strategy being run.

        Arguments:
            name (str): name of milestone
            report (bool): Automatically force a report.

        Yields:
            None
        """

        tmr = self._construct_milestone(
            name, time(), self.attempts, self.iterations, self.successes
        )
        self._in_progress_steps.append(tmr)
        yield
        assert self._in_progress_steps.pop() is tmr
        self.record(
            name,
            attempts=tmr.attempts,
            duration=tmr.duration,
            iterations=tmr.iterations,
            successes=tmr.successes,
            report=report,
        )

    def copy(self):
        """Create a deep copy of this instance.

        Arguments:
            None

        Returns:
            ReductionStatus: Clone of self
        """
        return deepcopy(self)

    def add_to_reporter(self, reporter, expected=True):
        """Add the reducer status to reported metadata for the given reporter.

        Arguments:
            reporter (FuzzManagerReporter): Reporter to update.
            expected (bool): Add detailed stats.

        Returns:
            None
        """
        # only add detailed stats for expected results
        if expected:
            reporter.add_extra_metadata("reducer-stats", self.finished_steps)
        # other parameters
        if self.analysis:
            reporter.add_extra_metadata("reducer-analysis", self.analysis)
        if self.run_params:
            reporter.add_extra_metadata("reducer-params", self.run_params)
        if self.signature_info:
            reporter.add_extra_metadata("reducer-sig", self.signature_info)
        # if input was an existing crash-id, record the original
        if self.crash_id:
            reporter.add_extra_metadata("reducer-input", self.crash_id)
