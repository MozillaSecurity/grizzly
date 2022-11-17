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
from sqlite3 import OperationalError, connect
from time import perf_counter, time

from ..common.utils import grz_tmp

__all__ = ("ReadOnlyStatus", "ReductionStatus", "Status", "SimpleStatus")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

# time in seconds for db connection to wait before raising an exception
DB_TIMEOUT = 30
# used to track changes to the database layout
DB_VERSION = 2
# database will be updated no more than once within the defined number of seconds.
REPORT_RATE = 60
# default life time for report entries in the database (24 hours)
REPORTS_EXPIRE = 86400
# default life time for result entries in the database (30 days)
RESULTS_EXPIRE = 2592000
# status database files
STATUS_DB_FUZZ = grz_tmp() / "fuzz-status.db"
STATUS_DB_REDUCE = grz_tmp() / "reduce-status.db"

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
                    cur.execute(f"DROP TABLE IF EXISTS {entry[0]};")
                # update db version number
                cur.execute(f"PRAGMA user_version = {expected};")
            return True
    assert version == expected, "code out of date?"
    return False


class BaseStatus:
    """Record and manage status information.

    Attributes:
        _profiles (dict): Profiling data.
        ignored (int): Ignored result count.
        iteration (int): Iteration count.
        log_size (int): Log size in bytes.
        pid (int): Python process ID.
        results (None): Placeholder for result data.
        start_time (float): Start time of session.
        test_name (str): Current test name.
    """

    __slots__ = (
        "_profiles",
        "ignored",
        "iteration",
        "log_size",
        "pid",
        "results",
        "start_time",
        "test_name",
    )

    def __init__(self, pid, start_time, ignored=0, iteration=0, log_size=0):
        assert pid >= 0
        assert ignored >= 0
        assert iteration >= 0
        assert log_size >= 0
        assert isinstance(start_time, float)
        assert start_time >= 0
        self._profiles = {}
        self.ignored = ignored
        self.iteration = iteration
        self.log_size = log_size
        self.pid = pid
        self.results = None
        self.start_time = start_time
        self.test_name = None

    def profile_entries(self):
        """Used to retrieve profiling data.

        Args:
            None

        Yields:
            ProfileEntry: Containing recorded profiling data.
        """
        for name, entry in self._profiles.items():
            yield ProfileEntry(
                entry["count"], entry["max"], entry["min"], name, entry["total"]
            )

    @property
    def rate(self):
        """Calculate the average iteration rate in seconds.

        Args:
            None

        Returns:
            float: Number of iterations performed per second.
        """
        return self.iteration / self.runtime if self.runtime else 0

    @property
    def runtime(self):
        """Calculate the number of seconds since start() was called.

        Args:
            None

        Returns:
            int: Total runtime in seconds.
        """
        return max(time() - self.start_time, 0)


class ReadOnlyStatus(BaseStatus):
    """Store status information.

    Attributes:
        _profiles (dict): Profiling data.
        ignored (int): Ignored result count.
        iteration (int): Iteration count.
        log_size (int): Log size in bytes.
        pid (int): Python process ID.
        results (None): Placeholder for result data.
        start_time (float): Start time of session.
        test_name (str): Test name.
        timestamp (float): Last time data was saved to database.
    """

    __slots__ = ("timestamp",)

    def __init__(self, pid, start_time, timestamp, ignored=0, iteration=0, log_size=0):
        super().__init__(
            pid, start_time, ignored=ignored, iteration=iteration, log_size=log_size
        )
        assert isinstance(timestamp, float)
        assert timestamp >= start_time
        self.timestamp = timestamp

    @classmethod
    def load_all(cls, db_file, time_limit=300):
        """Load all status reports found in `db_file`.

        Args:
            db_file (Path): Database containing status data.
            time_limit (int): Filter entries by age.

        Yields:
            ReadOnlyStatus: Successfully loaded objects.
        """
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
        results = ReadOnlyResultCounter.load(db_file, time_limit=0)
        for entry in entries:
            status = cls(
                entry[0],
                entry[5],
                entry[6],
                ignored=entry[2],
                iteration=entry[3],
                log_size=entry[4],
            )
            status._profiles = loads(entry[1])
            for counter in results:
                if counter.pid == status.pid:
                    status.results = counter
                    break
            else:
                # no existing ReadOnlyResultCounter with matching pid found
                status.results = ReadOnlyResultCounter(status.pid)
            yield status

    @property
    def runtime(self):
        """Calculate total runtime in seconds relative to 'timestamp'.

        Args:
            None

        Returns:
            int: Total runtime in seconds.
        """
        return self.timestamp - self.start_time


class SimpleStatus(BaseStatus):
    """Record and manage status information.

    Attributes:
        _profiles (dict): Profiling data.
        ignored (int): Ignored result count.
        iteration (int): Iteration count.
        log_size (int): Log size in bytes.
        pid (int): Python process ID.
        results (None): Placeholder for result data.
        start_time (float): Start time of session.
        test_name (str): Current test name.
    """

    def __init__(self, pid, start_time):
        super().__init__(pid, start_time)
        self.results = SimpleResultCounter(pid)

    @classmethod
    def start(cls):
        """Create a unique SimpleStatus object.

        Args:
            None

        Returns:
            SimpleStatus: Active status report.
        """
        return cls(getpid(), time())


class Status(BaseStatus):
    """Status records status information and stores it in a database.

    Attributes:
        _db_file (Path): Database file containing data.
        _enable_profiling (bool): Profiling support status.
        _profiles (dict): Profiling data.
        ignored (int): Ignored result count.
        iteration (int): Iteration count.
        log_size (int): Log size in bytes.
        pid (int): Python process ID.
        results (ResultCounter): Results data. Used to count occurrences of results.
        start_time (float): Start time of session.
        test_name (str): Current test name.
        timestamp (float): Last time data was saved to database.
    """

    __slots__ = ("_db_file", "_enable_profiling", "timestamp")

    def __init__(
        self,
        pid,
        start_time,
        db_file,
        enable_profiling=False,
        life_time=REPORTS_EXPIRE,
        report_limit=0,
    ):

        super().__init__(pid, start_time)
        assert life_time >= 0
        assert report_limit >= 0
        self._db_file = db_file
        self._enable_profiling = enable_profiling
        self._init_db(db_file, pid, life_time)
        self.results = ResultCounter(pid, db_file, report_limit=report_limit)
        self.timestamp = start_time

    @staticmethod
    def _init_db(db_file, pid, life_time):
        # prepare database
        LOG.debug("status using db %r", db_file)
        with closing(connect(db_file, timeout=DB_TIMEOUT)) as con:
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
                if life_time > 0:
                    cur.execute(
                        """DELETE FROM status WHERE timestamp <= ?;""",
                        (time() - life_time,),
                    )
                # avoid (unlikely) pid reuse collision
                cur.execute("""DELETE FROM status WHERE pid = ?;""", (pid,))

    @contextmanager
    def measure(self, name):
        """Used to simplify collecting profiling data.

        Args:
            name (str): Used to group the entries.

        Yields:
            None
        """
        if self._enable_profiling:
            mark = perf_counter()
            yield
            self.record(name, perf_counter() - mark)
        else:
            yield

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

    def report(self, force=False, report_rate=REPORT_RATE):
        """Write status report to database. Reports are only written periodically.
        It is limited by `report_rate`. The specified number of seconds must
        elapse before another write will be performed unless `force` is True.

        Args:
            force (bool): Ignore report frequency limiting.
            report_rate (int): Minimum number of seconds between writes to database.

        Returns:
            bool: True if the report was successful otherwise False.
        """
        now = time()
        if self.results.last_found > self.timestamp:
            LOG.debug("results have been found since last report, force update")
            force = True
        if not force and now < (self.timestamp + report_rate):
            return False
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

    @classmethod
    def start(cls, db_file, enable_profiling=False, report_limit=0):
        """Create a unique Status object.

        Args:
            db_file (Path): Database containing status data.
            enable_profiling (bool): Record profiling data.
            report_limit (int): Number of times a unique result will be reported.

        Returns:
            Status: Active status report.
        """
        status = cls(
            getpid(),
            time(),
            db_file,
            enable_profiling=enable_profiling,
            report_limit=report_limit,
        )
        status.report(force=True)
        return status


class SimpleResultCounter:
    __slots__ = ("_count", "_desc", "pid")

    def __init__(self, pid):
        assert pid >= 0
        self._count = defaultdict(int)
        self._desc = {}
        self.pid = pid

    def __iter__(self):
        """Yield all result data.

        Args:
            None

        Yields:
            ResultEntry: Contains ID, count and description for each result entry.
        """
        for result_id, count in self._count.items():
            if count > 0:
                yield ResultEntry(result_id, count, self._desc.get(result_id, None))

    def blockers(self, iterations, iters_per_result=100):
        """Any result with an iterations-per-result ratio of less than or equal the
        given limit are considered 'blockers'. Results with a count <= 1 are not
        included.

        Args:
            iterations (int): Total iterations.
            iters_per_result (int): Iterations-per-result threshold.

        Yields:
            ResultEntry: ID, count and description of blocking result.
        """
        assert iters_per_result > 0
        if iterations > 0:
            for entry in self:
                if entry.count > 1 and iterations / entry.count <= iters_per_result:
                    yield entry

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
        return self._count[result_id]

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

    @property
    def total(self):
        """Get total count of all results.

        Args:
            None

        Returns:
            int: Total result count.
        """
        return sum(self._count.values())


class ReadOnlyResultCounter(SimpleResultCounter):
    def count(self, result_id, desc):
        raise NotImplementedError("Read only!")  # pragma: no cover

    @classmethod
    def load(cls, db_file, time_limit=0):
        """Load existing entries for database and populate a ReadOnlyResultCounter.

        Args:
            db_file (Path): Database file.
            time_limit (int): Used to filter older entries.

        Returns:
            list: Loaded ReadOnlyResultCounter objects.
        """
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
                        (time() - time_limit,),
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

        loaded = {}
        for pid, result_id, desc, count in entries:
            if pid not in loaded:
                loaded[pid] = cls(pid)
            loaded[pid]._desc[result_id] = desc  # pylint: disable=protected-access
            loaded[pid]._count[result_id] = count  # pylint: disable=protected-access

        return list(loaded.values())


class ResultCounter(SimpleResultCounter):
    __slots__ = ("_db_file", "_frequent", "_limit", "last_found")

    def __init__(self, pid, db_file, life_time=RESULTS_EXPIRE, report_limit=0):
        super().__init__(pid)
        assert report_limit >= 0
        self._db_file = db_file
        self._frequent = set()
        self._limit = report_limit
        self.last_found = 0
        self._init_db(db_file, pid, life_time)

    @staticmethod
    def _init_db(db_file, pid, life_time):
        # prepare database
        LOG.debug("resultcounter using db %r", db_file)
        with closing(connect(db_file, timeout=DB_TIMEOUT)) as con:
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
                if life_time > 0:
                    cur.execute(
                        """DELETE FROM results WHERE timestamp <= ?;""",
                        (time() - life_time,),
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

    def count(self, result_id, desc):
        """Count results and write results to the database.

        Args:
            result_id (str): Result ID.
            desc (str): User friendly description.

        Returns:
            int: Current count for given result_id.
        """
        super().count(result_id, desc)
        timestamp = time()
        with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
            cur = con.cursor()
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
        self.last_found = timestamp
        return self._count[result_id]

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


ReductionStep = namedtuple(
    "ReductionStep", "name, duration, successes, attempts, size, iterations"
)


class ReductionStatus:
    """Status for a single grizzly reduction"""

    def __init__(
        self,
        strategies=None,
        testcase_size_cb=None,
        crash_id=None,
        db_file=None,
        pid=None,
        tool=None,
        life_time=REPORTS_EXPIRE,
    ):
        """Initialize a ReductionStatus instance.

        Arguments:
            strategies (list(str)): List of strategies to be run.
            testcase_size_cb (callable): Callback to get testcase size
            crash_id (int): CrashManager ID of original testcase
            db_file (Path): Database file containing data.
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
                    if life_time > 0:
                        cur.execute(
                            """DELETE FROM reduce_status WHERE timestamp <= ?;""",
                            (time() - life_time,),
                        )
                    # avoid (unlikely) pid reuse collision
                    cur.execute("""DELETE FROM reduce_status WHERE pid = ?;""", (pid,))

    @classmethod
    def start(
        cls,
        db_file,
        strategies=None,
        testcase_size_cb=None,
        crash_id=None,
        tool=None,
    ):
        """Create a unique ReductionStatus object.

        Args:
            db_file (Path): Database containing status data.
            strategies (list(str)): List of strategies to be run.
            testcase_size_cb (callable): Callback to get testcase size
            crash_id (int): CrashManager ID of original testcase
            tool (str): The tool name used for reporting to FuzzManager.

        Returns:
            ReductionStatus: Active status report.
        """
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

    def report(self, force=False, report_rate=REPORT_RATE):
        """Write status report to database. Reports are only written periodically.
        It is limited by `report_rate`. The specified number of seconds must
        elapse before another write will be performed unless `force` is True.

        Args:
            force (bool): Ignore report frequently limiting.
            report_rate (int): Minimum number of seconds between writes.

        Returns:
            bool: Returns true if the report was successful otherwise false.
        """
        now = time()
        if not force and now < (self.timestamp + report_rate):
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
    def load_all(cls, db_file, time_limit=300):
        """Load all reduction status reports found in `db_file`.

        Args:
            db_file (Path): Database containing status data.
            time_limit (int): Only include entries with a timestamp that is within the
                              given number of seconds.

        Yields:
            Status: Successfully loaded read-only status objects.
        """
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
