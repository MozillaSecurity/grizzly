# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
from __future__ import annotations

from abc import ABC
from collections import defaultdict
from contextlib import closing, contextmanager
from copy import deepcopy
from dataclasses import astuple, dataclass
from json import dumps, loads
from logging import getLogger
from os import getpid
from sqlite3 import Connection, OperationalError, connect
from time import perf_counter, time
from typing import TYPE_CHECKING, Any, Callable, Generator, cast

from .utils import grz_tmp

if TYPE_CHECKING:
    from pathlib import Path

    from .reporter import FuzzManagerReporter

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
# default life time for result entries in the database (14 days)
RESULTS_EXPIRE = 1209600
# status database files
STATUS_DB_FUZZ = grz_tmp() / "fuzz-status.db"
STATUS_DB_REDUCE = grz_tmp() / "reduce-status.db"

LOG = getLogger(__name__)


@dataclass(eq=False, frozen=True)
class ProfileEntry:
    count: int
    max: float
    min: float
    name: str
    total: float


@dataclass(frozen=True)
class ResultEntry:
    rid: str
    count: int
    desc: str | None


def _db_version_check(con: Connection, expected: int = DB_VERSION) -> bool:
    """Perform version check and remove obsolete tables if required.

    Args:
        con: An open database connection.
        expected: The latest database version.

    Returns:
        True if database was reset otherwise False.
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
        version = cast(int, cur.fetchone()[0])
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


class SimpleResultCounter:
    __slots__ = ("_count", "_desc", "pid")

    def __init__(self, pid: int) -> None:
        assert pid >= 0
        self._count: dict[str, int] = defaultdict(int)
        self._desc: dict[str, str] = {}
        self.pid = pid

    def __iter__(self) -> Generator[ResultEntry, None, None]:
        """Yield all result data.

        Args:
            None

        Yields:
            Contains ID, count and description for each result entry.
        """
        for result_id, count in self._count.items():
            if count > 0:
                yield ResultEntry(result_id, count, self._desc.get(result_id, None))

    def blockers(
        self, iterations: int, iters_per_result: int = 100
    ) -> Generator[ResultEntry, None, None]:
        """Any result with an iterations-per-result ratio of less than or equal the
        given limit are considered 'blockers'. Results with a count <= 1 are not
        included.

        Args:
            iterations: Total iterations.
            iters_per_result: Iterations-per-result threshold.

        Yields:
            ResultEntry: ID, count and description of blocking result.
        """
        assert iters_per_result > 0
        if iterations > 0:
            for entry in self:
                if entry.count > 1 and iterations / entry.count <= iters_per_result:
                    yield entry

    def count(self, result_id: str, desc: str) -> tuple[int, bool]:
        """

        Args:
            result_id: Result ID.
            desc: User friendly description.

        Returns:
            Current count for given result_id.
        """
        assert isinstance(result_id, str)
        self._count[result_id] += 1
        initial = False
        if result_id not in self._desc:
            self._desc[result_id] = desc
            initial = True
        return self._count[result_id], initial

    def get(self, result_id: str) -> ResultEntry:
        """Get count and description for given result id.

        Args:
            result_id: Result ID.

        Returns:
            ResultEntry: Count and description.
        """
        assert isinstance(result_id, str)
        return ResultEntry(
            result_id, self._count.get(result_id, 0), self._desc.get(result_id, None)
        )

    @property
    def total(self) -> int:
        """Get total count of all results.

        Args:
            None

        Returns:
            Total result count.
        """
        return sum(self._count.values())


class ReadOnlyResultCounter(SimpleResultCounter):
    def count(self, result_id: str, desc: str) -> tuple[int, bool]:
        raise NotImplementedError("Read only!")  # pragma: no cover

    @classmethod
    def load(cls, db_file: Path, time_limit: float = 0) -> list[ReadOnlyResultCounter]:
        """Load existing entries for database and populate a ReadOnlyResultCounter.

        Args:
            db_file: Database file.
            time_limit: Used to filter older entries.

        Returns:
            Loaded ReadOnlyResultCounter objects.
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
                entries = []

        loaded = {}
        for pid, result_id, desc, count in entries:
            if pid not in loaded:
                loaded[pid] = cls(pid)
            loaded[pid]._desc[result_id] = desc  # pylint: disable=protected-access
            loaded[pid]._count[result_id] = count  # pylint: disable=protected-access

        return list(loaded.values())


class ResultCounter(SimpleResultCounter):
    __slots__ = ("_db_file", "_frequent", "_limit", "last_found")

    def __init__(
        self,
        pid: int,
        db_file: Path,
        life_time: int = RESULTS_EXPIRE,
        report_limit: int = 0,
    ) -> None:
        super().__init__(pid)
        assert db_file
        assert report_limit >= 0
        self._db_file = db_file
        self._frequent: set[str] = set()
        # use zero to disable report limit
        self._limit = report_limit
        self.last_found = 0.0
        self._init_db(db_file, pid, life_time)

    @staticmethod
    def _init_db(db_file: Path, pid: int, life_time: float) -> None:
        # prepare database
        LOG.debug("resultcounter using db %s", db_file)
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

    def count(self, result_id: str, desc: str) -> tuple[int, bool]:
        """Count results and write results to the database.

        Args:
            result_id: Result ID.
            desc: User friendly description.

        Returns:
            Local count and initial report flag (includes parallel instances)
            for given result_id.
        """
        super().count(result_id, desc)
        timestamp = time()
        initial = False
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
                        """SELECT pid FROM results WHERE result_id = ?;""",
                        (result_id,),
                    )
                    initial = cur.fetchone() is None
                    cur.execute(
                        """INSERT INTO results(
                                pid,
                                result_id,
                                description,
                                timestamp,
                                count)
                            VALUES (?, ?, ?, ?, ?);""",
                        (self.pid, result_id, desc, timestamp, self._count[result_id]),
                    )
        self.last_found = timestamp
        return self._count[result_id], initial

    def is_frequent(self, result_id: str) -> bool:
        """Scan all results including results from other running instances
        to determine if the limit has been exceeded. Local count must be >1 before
        limit is checked.

        Args:
            result_id: Result ID.

        Returns:
            True if limit has been exceeded otherwise False.
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
        if self._limit >= total > 1:
            with closing(connect(self._db_file, timeout=DB_TIMEOUT)) as con:
                cur = con.cursor()
                # look up total count from all processes
                cur.execute(
                    """SELECT COALESCE(SUM(count), 0)
                        FROM results WHERE result_id = ?;""",
                    (result_id,),
                )
                global_total = cur.fetchone()[0]
            assert global_total >= total
            total = global_total
        if total > self._limit:
            self._frequent.add(result_id)
            return True
        return False

    def mark_frequent(self, result_id: str) -> None:
        """Mark given results ID as frequent locally.

        Args:
            result_id: Result ID.

        Returns:
            None
        """
        assert isinstance(result_id, str)
        if result_id not in self._frequent:
            self._frequent.add(result_id)


class BaseStatus(ABC):
    """Record and manage status information.

    Attributes:
        _profiles: Profiling data.
        ignored: Ignored result count.
        iteration: Iteration count.
        log_size: Log size in bytes.
        pid: Python process ID.
        start_time: Start time of session.
        test_name: Current test name.
    """

    __slots__ = (
        "_profiles",
        "ignored",
        "iteration",
        "log_size",
        "pid",
        "start_time",
        "test_name",
    )

    def __init__(
        self,
        pid: int,
        start_time: float,
        ignored: int = 0,
        iteration: int = 0,
        log_size: int = 0,
    ) -> None:
        assert pid >= 0
        assert ignored >= 0
        assert iteration >= 0
        assert log_size >= 0
        assert start_time >= 0
        self._profiles: dict[str, dict[str, float | int]] = {}
        self.ignored = ignored
        self.iteration = iteration
        self.log_size = log_size
        self.pid = pid
        self.start_time = start_time
        self.test_name: str | None = None

    def profile_entries(self) -> Generator[ProfileEntry, None, None]:
        """Used to retrieve profiling data.

        Args:
            None

        Yields:
            ProfileEntry: Containing recorded profiling data.
        """
        for name, entry in self._profiles.items():
            yield ProfileEntry(
                cast(int, entry["count"]),
                entry["max"],
                entry["min"],
                name,
                entry["total"],
            )

    @property
    def rate(self) -> float:
        """Calculate the average iteration rate in seconds.

        Args:
            None

        Returns:
            Number of iterations performed per second.
        """
        return self.iteration / self.runtime if self.runtime else 0

    @property
    def runtime(self) -> float:
        """Calculate the number of seconds since start() was called.

        Args:
            None

        Returns:
            Total runtime in seconds.
        """
        return max(time() - self.start_time, 0)


class ReadOnlyStatus(BaseStatus):
    """Store status information.

    Attributes:
        _profiles: Profiling data.
        ignored: Ignored result count.
        iteration: Iteration count.
        log_size: Log size in bytes.
        pid: Python process ID.
        results: Result data.
        start_time: Start time of session.
        test_name: Test name.
        timestamp: Last time data was saved to database.
    """

    __slots__ = ("results", "timestamp")

    def __init__(
        self,
        pid: int,
        start_time: float,
        timestamp: float,
        ignored: int = 0,
        iteration: int = 0,
        log_size: int = 0,
        results: ReadOnlyResultCounter | None = None,
    ) -> None:
        super().__init__(
            pid,
            start_time,
            ignored=ignored,
            iteration=iteration,
            log_size=log_size,
        )
        assert timestamp >= start_time
        self.results = results or ReadOnlyResultCounter(pid)
        self.timestamp = timestamp

    @classmethod
    def load_all(
        cls, db_file: Path, time_limit: float = 300
    ) -> Generator[ReadOnlyStatus, None, None]:
        """Load all status reports found in `db_file`.

        Args:
            db_file: Database containing status data.
            time_limit: Filter entries by age. Use zero for no limit.

        Yields:
            ReadOnlyStatus: Successfully loaded objects.
        """
        assert time_limit >= 0
        with closing(connect(db_file, timeout=DB_TIMEOUT)) as con:
            cur = con.cursor()
            # collect entries
            try:
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
                    (time() - time_limit if time_limit else 0,),
                )
                entries = cur.fetchall()
            except OperationalError as exc:
                if not str(exc).startswith("no such table:"):
                    raise  # pragma: no cover
                entries = []

        # Load all results
        results = ReadOnlyResultCounter.load(db_file, time_limit=0)
        for entry in entries:
            # look up counter
            current_counter = None
            for counter in results:
                if counter.pid == cast(int, entry[0]):
                    current_counter = counter
                    break

            status = cls(
                entry[0],
                entry[5],
                entry[6],
                ignored=entry[2],
                iteration=entry[3],
                log_size=entry[4],
                results=current_counter,
            )
            status._profiles = loads(entry[1])
            yield status

    @property
    def runtime(self) -> float:
        """Calculate total runtime in seconds relative to 'timestamp'.

        Args:
            None

        Returns:
            Total runtime in seconds.
        """
        return self.timestamp - self.start_time


class SimpleStatus(BaseStatus):
    """Record and manage status information.

    Attributes:
        _profiles: Profiling data.
        ignored: Ignored result count.
        iteration: Iteration count.
        log_size: Log size in bytes.
        pid: Python process ID.
        results:
        start_time: Start time of session.
        test_name: Current test name.
    """

    __slots__ = ("results",)

    def __init__(self, pid: int, start_time: float) -> None:
        super().__init__(pid, start_time)
        self.results = SimpleResultCounter(pid)

    @classmethod
    def start(cls) -> SimpleStatus:
        """Create a unique SimpleStatus object.

        Args:
            None

        Returns:
            Active status report.
        """
        return cls(getpid(), time())


class Status(BaseStatus):
    """Status records status information and stores it in a database.

    Attributes:
        _db_file: Database file containing data.
        _enable_profiling: Profiling support status.
        _profiles: Profiling data.
        ignored: Ignored result count.
        iteration: Iteration count.
        log_size: Log size in bytes.
        pid: Python process ID.
        results: Results data. Used to count occurrences of results.
        start_time: Start time of session.
        test_name: Current test name.
        timestamp: Last time data was saved to database.
    """

    __slots__ = ("_db_file", "_enable_profiling", "results", "timestamp")

    def __init__(
        self,
        pid: int,
        start_time: float,
        db_file: Path,
        enable_profiling: bool = False,
        life_time: float = REPORTS_EXPIRE,
        report_limit: int = 0,
    ) -> None:
        super().__init__(pid, start_time)
        assert life_time >= 0
        assert report_limit >= 0
        self._db_file = db_file
        self._enable_profiling = enable_profiling
        self._init_db(db_file, pid, life_time)
        self.results = ResultCounter(pid, db_file, report_limit=report_limit)
        self.timestamp = start_time

    @staticmethod
    def _init_db(db_file: Path, pid: int, life_time: float) -> None:
        # prepare database
        LOG.debug("status using db %s", db_file)
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
    def measure(self, name: str) -> Generator[None, None, None]:
        """Used to simplify collecting profiling data.

        Args:
            name: Used to group the entries.

        Yields:
            None
        """
        if self._enable_profiling:
            mark = perf_counter()
            yield
            self.record(name, perf_counter() - mark)
        else:
            yield

    def record(self, name: str, duration: float) -> None:
        """Used to add profiling data. This is intended to be used to make rough
        calculations to identify major configuration issues.

        Args:
            name: Used to group the entries.
            duration: Stored to be later used for measurements.

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

    def report(self, force: bool = False, report_rate: int = REPORT_RATE) -> bool:
        """Write status report to database. Reports are only written periodically.
        It is limited by `report_rate`. The specified number of seconds must
        elapse before another write will be performed unless `force` is True.

        Args:
            force: Ignore report frequency limiting.
            report_rate: Minimum number of seconds between writes to database.

        Returns:
            True if the report was successful otherwise False.
        """
        now = time()
        if self.results.last_found > self.timestamp:
            LOG.debug("results have been found since last report, force update")
            force = True
        assert report_rate >= 0
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
    def start(
        cls, db_file: Path, enable_profiling: bool = False, report_limit: int = 0
    ) -> Status:
        """Create a unique Status object.

        Args:
            db_file: Database containing status data.
            enable_profiling: Record profiling data.
            report_limit: Number of times a unique result will be reported.

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


@dataclass(frozen=True)
class ReductionStep:
    name: str
    duration: float | None
    successes: int | None
    attempts: int | None
    size: int | None
    iterations: int | None


@dataclass(frozen=True)
class _MilestoneTimer:
    name: str
    start: float
    attempts: int
    iterations: int
    successes: int


class ReductionStatus:
    """Status for a single grizzly reduction"""

    def __init__(
        self,
        strategies: list[str] | None = None,
        testcase_size_cb: Callable[[], int] | None = None,
        crash_id: int | None = None,
        db_file: Path | None = None,
        pid: int | None = None,
        tool: str | None = None,
        life_time: float = REPORTS_EXPIRE,
    ) -> None:
        """Initialize a ReductionStatus instance.

        Arguments:
            strategies: List of strategies to be run.
            testcase_size_cb: Callback to get testcase size.
            crash_id: CrashManager ID of original testcase.
            db_file: Database file containing data.
            tool: The tool name used for reporting to FuzzManager.
            life_time:
        """
        self.analysis: dict[str, float] = {}
        self.attempts = 0
        self.iterations = 0
        # TODO: make RunParams dataclass?
        self.run_params: dict[str, bool | int] = {}
        # TODO: make SigInfo dataclass?
        self.signature_info: dict[str, bool | str] = {}
        self.successes = 0
        self.current_strategy_idx: int | None = None
        self._testcase_size_cb = testcase_size_cb
        self.crash_id = crash_id
        self.finished_steps: list[ReductionStep] = []
        self._in_progress_steps: list[_MilestoneTimer] = []
        self.strategies = strategies
        self._db_file = db_file
        self.pid = pid
        self.timestamp = time()
        self.tool = tool
        self._current_size: int | None = None
        # this holds results from Reporter.submit()
        self.last_reports: list[str] = []

        # prepare database
        if self._db_file:
            LOG.debug("status using db %s", self._db_file)
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
        db_file: Path,
        strategies: list[str] | None = None,
        testcase_size_cb: Callable[[], int] | None = None,
        crash_id: int | None = None,
        tool: str | None = None,
    ) -> ReductionStatus:
        """Create a unique ReductionStatus object.

        Args:
            db_file: Database containing status data.
            strategies: List of strategies to be run.
            testcase_size_cb: Callback to get testcase size.
            crash_id: CrashManager ID of original testcase.
            tool: The tool name used for reporting to FuzzManager.

        Returns:
            Active status report.
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

    def report(self, force: bool = False, report_rate: float = REPORT_RATE) -> bool:
        """Write status report to database. Reports are only written periodically.
        It is limited by `report_rate`. The specified number of seconds must
        elapse before another write will be performed unless `force` is True.

        Args:
            force: Ignore report frequently limiting.
            report_rate: Minimum number of seconds between writes.

        Returns:
            True if the report was successful otherwise false.
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
                finished = dumps([astuple(step) for step in self.finished_steps])
                in_prog = dumps([astuple(step) for step in self._in_progress_steps])
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
    def load_all(
        cls, db_file: Path, time_limit: float = 300
    ) -> Generator[ReductionStatus, None, None]:
        """Load all reduction status reports found in `db_file`.

        Args:
            db_file: Database containing status data.
            time_limit: Only include entries with a timestamp that is within the
                        given number of seconds. Use zero for no limit.

        Yields:
            Successfully loaded read-only status objects.
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
                    (time() - time_limit if time_limit else 0,),
                )
                entries = cur.fetchall()
            except OperationalError as exc:
                if not str(exc).startswith("no such table:"):
                    raise  # pragma: no cover
                entries = []

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
            status.finished_steps = [ReductionStep(*step) for step in loads(entry[8])]
            status._in_progress_steps = [
                _MilestoneTimer(*step) for step in loads(entry[9])
            ]
            status._current_size = entry[11]
            status.current_strategy_idx = entry[12]
            status.timestamp = entry[13]
            status.last_reports = loads(entry[15])
            yield status

    def _testcase_size(self) -> int | None:
        if self._db_file is None:
            return self._current_size
        assert self._testcase_size_cb is not None
        return self._testcase_size_cb()

    def __deepcopy__(self, memo: dict[int, Any] | None) -> ReductionStatus:
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
        for tmr in reversed(self._in_progress_steps):
            step = self._tmr_to_step(tmr)
            result.record(
                step.name,
                attempts=step.attempts,
                duration=step.duration,
                iterations=step.iterations,
                successes=step.successes,
                report=False,
            )
        return result

    def _tmr_to_step(self, tmr: _MilestoneTimer) -> ReductionStep:
        if self._db_file is None:
            duration = self.timestamp - tmr.start
        else:
            duration = time() - tmr.start
        return ReductionStep(
            tmr.name,
            duration=duration,
            successes=self.successes - tmr.successes,
            attempts=self.attempts - tmr.attempts,
            size=None,
            iterations=self.iterations - tmr.iterations,
        )

    @property
    def current_strategy(self) -> ReductionStep | None:
        if self._in_progress_steps:
            return self._tmr_to_step(self._in_progress_steps[-1])
        if self.finished_steps:
            return self.finished_steps[-1]
        return None

    @property
    def total(self) -> ReductionStep | None:
        if self._in_progress_steps:
            return self._tmr_to_step(self._in_progress_steps[0])
        if self.finished_steps:
            return self.finished_steps[-1]
        return None

    @property
    def original(self) -> ReductionStep | None:
        if self.finished_steps:
            return self.finished_steps[0]
        return None

    def record(
        self,
        name: str,
        duration: float | None = None,
        iterations: int | None = None,
        attempts: int | None = None,
        successes: int | None = None,
        report: bool = True,
    ) -> None:
        """Record reduction status for a given point in time:

        - name of the milestone (eg. init, strategy name completed)
        - elapsed time (seconds)
        - # of iterations
        - # of total attempts
        - # of successful attempts

        Arguments:
            name: name of milestone
            duration: seconds elapsed for period recorded
            iterations: # of iterations performed
            attempts: # of attempts performed
            successes: # of attempts successful
            report: Automatically force a report.

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

    @contextmanager
    def measure(self, name: str, report: bool = True) -> Generator[None, None, None]:
        """Time and record the period leading up to a reduction milestone.
        eg. a strategy being run.

        Arguments:
            name: name of milestone
            report: Automatically force a report.

        Yields:
            None
        """

        tmr = _MilestoneTimer(
            name, time(), self.attempts, self.iterations, self.successes
        )
        self._in_progress_steps.append(tmr)
        yield
        assert self._in_progress_steps.pop() is tmr
        step = self._tmr_to_step(tmr)
        self.record(
            name,
            attempts=step.attempts,
            duration=step.duration,
            iterations=step.iterations,
            successes=step.successes,
            report=report,
        )

    def copy(self) -> ReductionStatus:
        """Create a deep copy of this instance.

        Arguments:
            None

        Returns:
            Clone of self
        """
        return deepcopy(self)

    def add_to_reporter(
        self, reporter: FuzzManagerReporter, expected: bool = True
    ) -> None:
        """Add the reducer status to reported metadata for the given reporter.

        Arguments:
            reporter: Reporter to update.
            expected: Add detailed stats.

        Returns:
            None
        """
        # only add detailed stats for expected results
        if expected:
            reporter.add_extra_metadata(
                "reducer-stats", [astuple(step) for step in self.finished_steps]
            )
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
