# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status"""
# pylint: disable=protected-access

from multiprocessing import Event, Process
from time import sleep, time

from pytest import mark

from .status import ResultCounter, Status, _db_version_check


def test_status_01(mocker, tmp_path):
    """test Status.start()"""
    mocker.patch("grizzly.common.status.time", autospec=True, return_value=1.0)
    status = Status.start(str(tmp_path / "status.db"))
    assert status is not None
    assert status._db_file is not None
    assert status.start_time > 0
    assert status.timestamp >= status.start_time
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.rate == 0
    assert status.results.total == 0
    assert int(status.runtime) == 0
    assert status.pid is not None
    assert not status._enable_profiling
    assert not status._profiles


def test_status_02(tmp_path):
    """test Status.report()"""
    status = Status.start(str(tmp_path / "status.db"))
    status.results.count("uid1", "sig1")
    # try to report before REPORT_FREQ elapses
    assert not status.report()
    # REPORT_FREQ elapses
    status.timestamp = 0
    assert status.report()
    assert status.timestamp > 0
    # force report
    future = int(time()) + 1000
    status.timestamp = future
    assert status.report(force=True)
    assert status.timestamp < future


def test_status_03(tmp_path):
    """test Status.load()"""
    db_file = str(tmp_path / "status.db")
    # create simple entry
    status = Status.start(db_file, enable_profiling=True)
    status.results.count("uid1", "sig1")
    status.record("test", 123.45)
    status.report(force=True)
    assert status.results.total == 1
    loaded = next(Status.loadall(db_file))
    assert status.start_time == loaded.start_time
    assert status.timestamp == loaded.timestamp
    assert status.runtime >= loaded.runtime
    assert status.ignored == loaded.ignored
    assert status.iteration == loaded.iteration
    assert status.log_size == loaded.log_size
    assert status.pid == loaded.pid
    assert loaded.results.get("uid1") == (1, "sig1")
    assert not loaded._enable_profiling
    assert "test" in loaded._profiles


def test_status_04(mocker, tmp_path):
    """test Status.loadall()"""
    getpid = mocker.patch("grizzly.common.status.getpid", autospec=True)
    db_file = str(tmp_path / "status.db")
    for pid in range(5):
        getpid.return_value = pid
        Status.start(db_file)
    assert len(tuple(Status.loadall(db_file))) == 5


def test_status_05(mocker, tmp_path):
    """test Status.runtime and Status.rate calculations"""
    fake_time = mocker.patch("grizzly.common.status.time", autospec=True)
    fake_time.return_value = 1.0
    db_file = str(tmp_path / "status.db")
    status = Status.start(db_file)
    assert status.start_time == 1
    # test no iterations
    fake_time.return_value = 3.0
    assert status.runtime == 2.0
    assert status.rate == 0
    # test one iteration
    status.iteration = 1
    # timestamp should be ignored when calculating rate and runtime on active object
    fake_time.return_value = 5.0
    status.timestamp = 100
    assert status.runtime == 4.0
    assert status.rate == 0.25
    # test loaded
    status.report(force=True)
    loaded = next(Status.loadall(db_file))
    assert loaded.runtime == 4.0
    assert loaded.rate == 0.25
    # timestamp should be used when calculating rate and runtime on loaded object
    loaded.timestamp = 2.0
    assert loaded.runtime == 1.0
    assert loaded.rate == 1.0


def _client_writer(done, reported, db_file):
    """Used by test_status_06"""
    # NOTE: this must be at the top level to work on Windows
    status = Status.start(db_file)
    while not done.is_set():
        status.iteration += 1
        status.report(force=True)
        # perform two reports before setting flag
        if not reported.is_set() and status.iteration > 1:
            reported.set()
        sleep(0.01)


def test_status_06(tmp_path):
    """test Status.loadall() with multiple active reporters"""
    db_file = str(tmp_path / "status.db")
    done = Event()
    procs = list()
    report_events = list()
    try:
        # launch processes
        for _ in range(10):
            report_events.append(Event())
            procs.append(
                Process(target=_client_writer, args=(done, report_events[-1], db_file))
            )
            procs[-1].start()
        # wait for processes to launch and report
        for event in report_events:
            assert event.wait(timeout=60)
        # collect reports
        reports = tuple(Status.loadall(db_file))
        assert len(reports) == len(procs)
        assert max(x.rate for x in reports) > 0
    finally:
        done.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()


def test_status_07(tmp_path):
    """test Status.measure() and Status.record() - profiling support"""
    db_file = str(tmp_path / "status.db")
    # profiling disabled
    status = Status.start(db_file, enable_profiling=False)
    status.record("x", 10.1)
    assert not status._profiles
    with status.measure("x"):
        pass
    assert not status._profiles
    # profiling enabled
    status = Status.start(db_file, enable_profiling=True)
    assert not status._profiles
    # initial entry
    status.record("test1", 10.1)
    assert "test1" in status._profiles
    assert status._profiles["test1"]["count"] == 1
    assert status._profiles["test1"]["max"] == 10.1
    assert status._profiles["test1"]["min"] == 10.1
    assert status._profiles["test1"]["total"] == 10.1
    entry = next(status.profile_entries())
    assert entry.name == "test1"
    assert entry.count == 1
    assert entry.max == 10.1
    assert entry.min == 10.1
    assert entry.total == 10.1
    # new min
    status.record("test1", 0.4)
    entry = next(status.profile_entries())
    assert entry.count == 2
    assert entry.max == 10.1
    assert entry.min == 0.4
    assert entry.total == 10.5
    # entry
    status.record("test1", 2)
    entry = next(status.profile_entries())
    assert entry.count == 3
    assert entry.max == 10.1
    assert entry.min == 0.4
    assert entry.total == 12.5
    # new max
    status.record("test1", 99.12)
    entry = next(status.profile_entries())
    assert entry.count == 4
    assert entry.max == 99.12
    assert entry.min == 0.4
    assert entry.total == 111.62
    # new name
    status.record("test2", 1)
    assert "test2" in status._profiles
    assert len(status._profiles) == 2
    assert status._profiles["test2"]["count"] == 1
    assert status._profiles["test2"]["max"] == 1
    assert status._profiles["test2"]["min"] == 1
    assert status._profiles["test2"]["total"] == 1
    status.record("test2", 1)
    assert status._profiles["test2"]["count"] == 2
    assert status._profiles["test2"]["max"] == 1
    assert status._profiles["test2"]["min"] == 1
    assert status._profiles["test2"]["total"] == 2
    # test measure
    with status.measure("no-op"):
        pass
    assert len(status._profiles) == 3
    assert "no-op" in status._profiles
    assert len(tuple(status.profile_entries())) == 3


@mark.parametrize(
    "keys, counts, limit, local_only",
    [
        # no records
        (["a"], [0], 1, True),
        (["a"], [0], 1, False),
        # single record (not frequent)
        (["a"], [1], 2, True),
        (["a"], [1], 2, False),
        # single record (frequent)
        (["a"], [1], 1, True),
        (["a"], [1], 1, False),
        # single record no limit
        (["a"], [1], 0, True),
        (["a"], [1], 0, False),
        # multiple records
        (["a", "b", "c"], [1, 2, 10], 5, True),
        (["a", "b", "c"], [1, 2, 10], 5, False),
    ],
)
def test_report_counter_01(tmp_path, keys, counts, limit, local_only):
    """test ResultCounter local functionality"""
    db_path = None if local_only else str(tmp_path / "storage.db")
    counter = ResultCounter(1, db_file=db_path, freq_limit=limit)
    for report_id, count in zip(keys, counts):
        assert counter.get(report_id) == (0, None)
        assert not counter.is_frequent(report_id)
        # call count() with report_id 'count' times
        for current in range(1, count + 1):
            assert counter.count(report_id, "desc") == current
        if sum(counts) > 0:
            assert counter.get(report_id) == (count, "desc")
        else:
            assert counter.get(report_id) == (count, None)
        if count >= limit > 0:
            assert counter.is_frequent(report_id)
        else:
            assert not counter.is_frequent(report_id)
            counter.mark_frequent(report_id)
            assert counter.is_frequent(report_id) or limit == 0
    for _report_id, count, _desc in counter.all():
        assert count > 0
    assert counter.total == sum(counts)


def test_report_counter_02(mocker, tmp_path):
    """test ResultCounter multi instance functionality"""
    mocker.patch("grizzly.common.status.time", autospec=True, return_value=1)
    db_path = str(tmp_path / "storage.db")
    counter_a = ResultCounter(1, db_file=db_path, freq_limit=2)
    counter_b = ResultCounter(2, db_file=db_path, freq_limit=2)
    counter_c = ResultCounter(3, db_file=db_path, freq_limit=2)
    # local (counter_a, bucket a) count is 0, global (all counters) count is 0
    assert not counter_a.is_frequent("a")
    assert not counter_b.is_frequent("a")
    assert not counter_c.is_frequent("a")
    assert counter_a.count("a", "desc") == 1
    # local (counter_a, bucket a) count is 1, global (all counters) count is 1
    assert not counter_a.is_frequent("a")
    assert not counter_b.is_frequent("a")
    assert not counter_c.is_frequent("a")
    assert counter_b.count("a", "desc") == 1
    # local (counter_b, bucket a) count is 1, global (all counters) count is 2
    assert counter_a.is_frequent("a")
    assert counter_b.is_frequent("a")
    assert counter_c.is_frequent("a")
    assert counter_c.count("a", "desc") == 1
    # local (counter_c, bucket a) count is 1, global (all counters) count is 3
    assert counter_a.is_frequent("a")
    assert counter_b.is_frequent("a")
    assert counter_c.is_frequent("a")
    # local (counter_a, bucket x) count is 0, global (all counters) count is 0
    assert not counter_a.is_frequent("x")
    # remove 'expired' reports
    mocker.patch("grizzly.common.status.time", autospec=True, return_value=1000)
    counter_d = ResultCounter(4, db_file=db_path, freq_limit=2, exp_limit=10)
    # local (counter_d, bucket a) count is 0, global (all counters) count is 0
    assert not counter_d.is_frequent("a")
    assert counter_a.total == 1
    assert counter_b.total == 1
    assert counter_c.total == 1
    assert counter_d.total == 0


def test_report_counter_03(mocker, tmp_path):
    """test ResultCounter.load()"""
    fake_time = mocker.patch("grizzly.common.status.time", autospec=True)
    fake_time.return_value = 1
    db_path = str(tmp_path / "storage.db")
    # load empty db
    ResultCounter.load(db_path, 123, 10)
    # create counter
    counter = ResultCounter(123, db_file=db_path, exp_limit=1)
    counter.count("a", "desc_a")
    fake_time.return_value = 2
    counter.count("a", "desc_a")
    fake_time.return_value = 3
    counter.count("b", "desc_b")
    # filter out reports by time
    fake_time.return_value = 4
    # last 1 second
    loaded = ResultCounter.load(db_path, counter._pid, 1)
    assert loaded.total == 0
    # last 2 seconds
    loaded = ResultCounter.load(db_path, counter._pid, 2)
    assert loaded.total == 1
    assert loaded.get("b") == (1, "desc_b")
    # last 3 seconds
    loaded = ResultCounter.load(db_path, counter._pid, 3)
    assert loaded.get("a") == (2, "desc_a")
    assert loaded.total == 3
    # increase time limit
    fake_time.return_value = 4
    loaded = ResultCounter.load(db_path, counter._pid, 10)
    assert loaded.total == counter.total == 3
    assert loaded.get("a") == (2, "desc_a")
    assert loaded.get("b") == (1, "desc_b")


def test_report_counter_04(mocker, tmp_path):
    """test ResultCounter remove old entries"""
    fake_time = mocker.patch("grizzly.common.status.time", autospec=True)
    fake_time.return_value = 1
    db_path = str(tmp_path / "storage.db")
    counter = ResultCounter(123, db_file=db_path, exp_limit=0)
    counter.count("a", "desc_a")
    fake_time.return_value = 100
    counter.count("b", "desc_b")
    loaded = ResultCounter.load(db_path, counter._pid, 100)
    assert loaded.total == 2
    # set exp_limit to zero to skip removing expired results
    ResultCounter(123, db_file=db_path, exp_limit=0)
    loaded = ResultCounter.load(db_path, counter._pid, 100)
    assert loaded.total == 2
    # clear expired records from database by setting exp_limit
    ResultCounter(123, db_file=db_path, exp_limit=10)
    loaded = ResultCounter.load(db_path, counter._pid, 100)
    assert loaded.total == 1


def test_db_version_check_01(tmp_path):
    """test _db_version_check()"""
    db_path = str(tmp_path / "storage.db")
    # empty db
    _db_version_check(db_path, expected=1)
    # no update needed
    Status.start(db_path)
    _db_version_check(db_path, expected=1)
    # force update
    _db_version_check(db_path, expected=2)
    # verify everything works after update
    Status.start(db_path)
