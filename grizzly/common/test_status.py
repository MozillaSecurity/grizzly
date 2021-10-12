# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status"""
# pylint: disable=protected-access

from multiprocessing import Event, Process
from time import sleep, time

from pytest import mark

from .status import DB_VERSION, ResultCounter, Status, _db_version_check


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
    assert not any(status.blockers())


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
    """test Status.loadall()"""
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


# NOTE: this function must be at the top level to work on Windows
def _client_writer(db_file, begin, count):
    """Used by test_status_06"""
    begin.wait(timeout=45)
    status = Status.start(db_file)
    for _ in range(count):
        status.iteration += 1
        status.report(force=True)
        sleep(0.01)


@mark.parametrize(
    "loads_in_parallel",
    [
        # only test reporting in parallel
        0,
        # test reporting and loading in parallel
        5,
    ],
)
def test_status_06(tmp_path, loads_in_parallel):
    """test Status.loadall() with multiple active clients in parallel"""
    begin = Event()
    clients = 10
    db_file = str(tmp_path / "status.db")
    iter_count = 5
    procs = list()
    try:
        # create and launch client processes
        for _ in range(clients):
            procs.append(
                Process(target=_client_writer, args=(db_file, begin, iter_count))
            )
            procs[-1].start()
        # synchronize client processes (not perfect but good enough)
        begin.set()
        # attempt parallel loads
        for _ in range(loads_in_parallel):
            tuple(Status.loadall(db_file))
        # wait for processes to report and exit
        for proc in procs:
            proc.join(timeout=60)
            assert proc.exitcode == 0
        # collect reports
        reports = tuple(Status.loadall(db_file))
        # check that each process created a report
        assert len(reports) == clients
        # check reported data
        assert max(x.rate for x in reports) > 0
        assert sum(x.iteration for x in reports) == iter_count * clients
    finally:
        for proc in procs:
            if proc.exitcode is None:
                proc.terminate()
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


def test_status_08(tmp_path):
    """test Status.blockers()"""
    status = Status.start(str(tmp_path / "status.db"))
    status.iteration = 10
    assert not any(status.blockers())
    status.results.count("uid1", "sig1")
    assert not any(status.blockers(iters_per_result=3))
    status.results.count("uid2", "sig2")
    status.results.count("uid2", "sig2")
    assert not any(status.blockers(iters_per_result=2))
    blockers = tuple(status.blockers(iters_per_result=5))
    assert len(blockers) == 1
    assert blockers[0] == (2, "sig2")
    blockers = tuple(status.blockers(iters_per_result=10))
    assert len(blockers) == 2


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
        # test get()
        if sum(counts) > 0:
            assert counter.get(report_id) == (count, "desc")
        else:
            assert counter.get(report_id) == (count, None)
        # test is_frequent()
        if count > limit > 0:
            assert counter.is_frequent(report_id)
        elif limit > 0:
            assert not counter.is_frequent(report_id)
            # test mark_frequent()
            counter.mark_frequent(report_id)
            assert counter.is_frequent(report_id)
        else:
            assert limit == 0
    for _report_id, count, _desc in counter.all():
        assert count > 0
    assert counter.total == sum(counts)


def test_report_counter_02(mocker, tmp_path):
    """test ResultCounter multi instance functionality"""
    mocker.patch("grizzly.common.status.time", autospec=True, return_value=1)
    db_path = str(tmp_path / "storage.db")
    counter_a = ResultCounter(1, db_file=db_path, freq_limit=0)
    counter_b = ResultCounter(2, db_file=db_path, freq_limit=1)
    counter_c = ResultCounter(3, db_file=db_path, freq_limit=2)
    # local counts are 0, global (all counters) count is 0
    assert not counter_a.is_frequent("a")
    assert not counter_b.is_frequent("a")
    assert not counter_c.is_frequent("a")
    # local (counter_a, bucket a) count is 1, global (all counters) count is 1
    assert counter_a.count("a", "desc") == 1
    assert not counter_a.is_frequent("a")
    assert not counter_b.is_frequent("a")
    assert not counter_c.is_frequent("a")
    # local (counter_b, bucket a) count is 1, global (all counters) count is 2
    assert counter_b.count("a", "desc") == 1
    assert not counter_a.is_frequent("a")
    assert not counter_b.is_frequent("a")
    assert not counter_c.is_frequent("a")
    # local (counter_b, bucket a) count is 2, global (all counters) count is 3
    # locally exceeded
    assert counter_b.count("a", "desc") == 2
    assert counter_b.is_frequent("a")
    # local (counter_c, bucket a) count is 1, global (all counters) count is 4
    assert counter_c.count("a", "desc") == 1
    assert not counter_a.is_frequent("a")
    assert counter_b.is_frequent("a")
    assert not counter_c.is_frequent("a")
    # local (counter_a, bucket a) count is 2, global (all counters) count is 5
    # no limit
    assert counter_a.count("a", "desc") == 2
    assert not counter_a.is_frequent("a")
    # local (counter_c, bucket a) count is 2, global (all counters) count is 6
    # locally not exceeded, globally exceeded
    assert counter_c.count("a", "desc") == 2
    assert counter_c.is_frequent("a")
    # local (counter_a, bucket x) count is 0, global (all counters) count is 0
    assert not counter_a.is_frequent("x")
    # remove 'expired' reports
    mocker.patch("grizzly.common.status.time", autospec=True, return_value=1000)
    counter_d = ResultCounter(4, db_file=db_path, freq_limit=2, exp_limit=10)
    # local (counter_d, bucket a) count is 0, global (all counters) count is 0
    assert not counter_d.is_frequent("a")
    assert counter_a.total == 2
    assert counter_b.total == 2
    assert counter_c.total == 2
    assert counter_d.total == 0


def test_report_counter_03(mocker, tmp_path):
    """test ResultCounter.load()"""
    fake_time = mocker.patch("grizzly.common.status.time", autospec=True)
    fake_time.return_value = 1
    db_path = str(tmp_path / "storage.db")
    # load empty db
    assert not ResultCounter.load(db_path, 10)
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
    assert not ResultCounter.load(db_path, 1)
    # last 2 seconds
    loaded = ResultCounter.load(db_path, 2)[0]
    assert loaded.total == 1
    assert loaded.get("b") == (1, "desc_b")
    # last 3 seconds
    loaded = ResultCounter.load(db_path, 3)[0]
    assert loaded.get("a") == (2, "desc_a")
    assert loaded.total == 3
    # increase time limit
    fake_time.return_value = 4
    loaded = ResultCounter.load(db_path, 10)[0]
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
    loaded = ResultCounter.load(db_path, 100)[0]
    assert loaded.total == 2
    # set exp_limit to zero to skip removing expired results
    ResultCounter(124, db_file=db_path, exp_limit=0)
    loaded = ResultCounter.load(db_path, 100)[0]
    assert loaded.total == 2
    # clear expired records from database by setting exp_limit
    ResultCounter(125, db_file=db_path, exp_limit=10)
    loaded = ResultCounter.load(db_path, 100)[0]
    assert loaded.total == 1


def test_db_version_check_01(tmp_path):
    """test _db_version_check()"""
    db_path = str(tmp_path / "storage.db")
    # empty db
    assert _db_version_check(db_path, expected=DB_VERSION)
    # no update needed
    assert not _db_version_check(db_path, expected=DB_VERSION)
    # add db contents
    Status.start(db_path)
    # force update
    assert _db_version_check(db_path, expected=DB_VERSION + 1)
