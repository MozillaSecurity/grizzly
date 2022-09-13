# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status"""
# pylint: disable=protected-access

from multiprocessing import Event, Process
from sqlite3 import connect
from time import sleep, time

from pytest import mark

from .reporter import FuzzManagerReporter
from .status import (
    DB_VERSION,
    ReductionStatus,
    ReductionStep,
    ResultCounter,
    Status,
    _db_version_check,
)


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
    # load from empty db
    assert not any(Status.loadall(db_file))
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
    assert loaded.results.get("uid1") == ("uid1", 1, "sig1")
    assert not loaded._enable_profiling
    assert "test" in loaded._profiles


def test_status_04(mocker, tmp_path):
    """test Status.loadall() - multiple entries"""
    getpid = mocker.patch("grizzly.common.status.getpid", autospec=True)
    db_file = str(tmp_path / "status.db")
    for pid in range(5):
        getpid.return_value = pid
        Status.start(db_file)
    assert len(tuple(Status.loadall(db_file))) == 5


def test_status_05(mocker, tmp_path):
    """test Status.loadall() - filter entries by time"""
    fake_time = mocker.patch("grizzly.common.status.time", autospec=True)
    fake_time.return_value = 1.0
    db_file = str(tmp_path / "status.db")
    # create entry
    status = Status.start(db_file)
    status.results.count("uid1", "sig1")
    assert status.results.total == 1
    status.report(force=True)
    # load entry
    assert any(Status.loadall(db_file, time_limit=60))
    # load with expired entry
    fake_time.return_value = 1200.0
    assert not any(Status.loadall(db_file, time_limit=60))
    # load with no limit
    assert any(Status.loadall(db_file, time_limit=0))
    # load long running entry with a one month old result
    fake_time.return_value = 2592000.0
    status.report(force=True)
    loaded = next(Status.loadall(db_file, time_limit=60))
    assert status.start_time == loaded.start_time
    assert status.timestamp == loaded.timestamp
    assert status.runtime >= loaded.runtime
    assert status.ignored == loaded.ignored
    assert status.iteration == loaded.iteration
    assert status.log_size == loaded.log_size
    assert status.pid == loaded.pid
    assert loaded.results.get("uid1") == ("uid1", 1, "sig1")


def test_status_06(mocker, tmp_path):
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
def test_status_07(tmp_path, loads_in_parallel):
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


def test_status_08(tmp_path):
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
    "buckets, ratio, iterations, blockers",
    [
        # no results
        ([], 1, 1, 0),
        # one result seen once (not blocker since count == 1)
        ([("uid1", "sig1", 1)], 1, 1, 0),
        # one result seen 10x (not blocker)
        ([("uid1", "sig1", 10)], 100, 10000, 0),
        # one result seen 10x (blocker)
        ([("uid1", "sig1", 10)], 100, 1000, 1),
        # one result seen 95x (blocker)
        ([("uid1", "sig1", 95)], 100, 1000, 1),
        # multiple results seen once (not blocker since count == 1)
        ([("uid1", "sig1", 1), ("uid2", "sig2", 1)], 1, 1, 0),
        # multiple results seen once (one blockers)
        ([("uid1", "sig1", 1), ("uid2", "sig2", 10)], 1000, 100, 1),
        # multiple results seen once (two blockers)
        ([("uid1", "sig1", 99), ("uid2", "sig2", 10)], 1000, 100, 2),
    ],
)
def test_status_09(tmp_path, buckets, ratio, iterations, blockers):
    """test Status.blockers()"""
    status = Status.start(str(tmp_path / "status.db"))
    status.iteration = iterations
    # populate counter
    for report_id, desc, count in buckets:
        for _ in range(count):
            status.results.count(report_id, desc)
    # check for blockers
    assert len(tuple(status.blockers(iters_per_result=ratio))) == blockers


def test_status_10(mocker, tmp_path):
    """test Status() - purge expired entries"""
    fake_time = mocker.patch("grizzly.common.status.time", autospec=True)
    db_file = str(tmp_path / "status.db")
    # purge due to exp_limit
    fake_time.return_value = 1.0
    status = Status(db_file=db_file, start_time=1.0, pid=123, exp_limit=10)
    status.report(force=True)
    assert any(Status.loadall(db_file, time_limit=60))
    fake_time.return_value = 20.0
    Status(db_file=db_file, start_time=20.0, pid=456, exp_limit=10)
    assert not any(Status.loadall(db_file, time_limit=60))
    # purge due matching pid
    fake_time.return_value = 1.0
    status = Status(db_file=db_file, start_time=1.0, pid=123, exp_limit=10)
    status.report(force=True)
    assert any(Status.loadall(db_file, time_limit=60))
    Status(db_file=db_file, start_time=1.0, pid=123, exp_limit=10)
    assert not any(Status.loadall(db_file, time_limit=60))


def test_reduce_status_01(mocker, tmp_path):
    """test ReductionStatus()"""
    mocker.patch("grizzly.common.status.time", autospec=True, return_value=1.0)
    strategies = ["strategy_%d" % (idx,) for idx in range(5)]

    def fake_tc_size():
        return 47

    status = ReductionStatus.start(
        str(tmp_path / "status.db"),
        strategies=strategies,
        testcase_size_cb=fake_tc_size,
    )
    assert status is not None
    assert status.analysis == {}
    assert status.attempts == 0
    assert status.iterations == 0
    assert status.run_params == {}
    assert status.signature_info == {}
    assert status.successes == 0
    assert status.current_strategy_idx is None
    assert status._testcase_size_cb is fake_tc_size
    assert status.crash_id is None
    assert status.finished_steps == []
    assert status._in_progress_steps == []
    assert status.strategies == strategies
    assert status._db_file is not None
    assert status.pid is not None
    assert status.timestamp > 0.0
    assert status._current_size is None


def test_reduce_status_02(tmp_path):
    """test ReductionStatus.report()"""
    status = ReductionStatus.start(
        str(tmp_path / "status.db"),
        testcase_size_cb=lambda: 47,
    )
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


def test_reduce_status_03(tmp_path):
    """test ReductionStatus.loadall()"""
    db_file = str(tmp_path / "status.db")
    strategies = ["strategy_%d" % (idx,) for idx in range(5)]
    # create simple entry
    status = ReductionStatus.start(
        str(tmp_path / "status.db"),
        strategies=strategies,
        testcase_size_cb=lambda: 47,
    )
    loaded = tuple(ReductionStatus.loadall(db_file))
    assert len(loaded) == 1
    loaded = loaded[0]
    assert status.analysis == loaded.analysis
    assert status.attempts == loaded.attempts
    assert status.iterations == loaded.iterations
    assert status.run_params == loaded.run_params
    assert status.signature_info == loaded.signature_info
    assert status.successes == loaded.successes
    assert status.current_strategy_idx == loaded.current_strategy_idx
    assert loaded._testcase_size_cb is None
    assert status.crash_id == loaded.crash_id
    assert status.finished_steps == loaded.finished_steps
    assert status._in_progress_steps == loaded._in_progress_steps
    assert status.strategies == loaded.strategies
    assert status._db_file is not None
    assert status.pid == loaded.pid
    assert status.timestamp == loaded.timestamp
    assert loaded._current_size == 47
    assert loaded._testcase_size() == 47


def test_reduce_status_04(mocker, tmp_path):
    """test ReductionStatus.loadall()"""
    getpid = mocker.patch("grizzly.common.status.getpid", autospec=True)
    db_file = str(tmp_path / "status.db")
    for pid in range(5):
        getpid.return_value = pid
        ReductionStatus.start(
            db_file,
            testcase_size_cb=lambda: 47,
        )
    assert len(tuple(ReductionStatus.loadall(db_file))) == 5


def test_reduce_status_05(mocker, tmp_path):
    """test ReductionStatus milestone measurements"""
    strategies = ["strategy_%d" % (idx,) for idx in range(5)]

    # (time, testcase_size) steps to manually advance through
    ticks = [
        (0, 1000),
        (1, 900),
        (2, 800),
        (3, 700),
        (4, 600),
        (5, 500),
    ]

    mocker.patch(
        "grizzly.common.status.time",
        autospec=True,
        side_effect=lambda: ticks[0][0],
    )
    testcase_size_cb = mocker.Mock(side_effect=lambda: ticks[0][1])
    status = ReductionStatus.start(
        str(tmp_path / "status.db"),
        strategies=strategies,
        testcase_size_cb=testcase_size_cb,
    )
    status.record("begin")
    assert status.original.name == "begin"
    assert status.total.name == "begin"
    assert status.current_strategy.name == "begin"
    with status.measure("overall"):
        assert status.original.name == "begin"
        assert status.total.name == "overall"
        assert status.current_strategy.name == "overall"
        for idx in range(5):
            with status.measure(strategies[idx]):
                ticks.pop(0)
                status.attempts += 2
                status.successes += 1
                status.iterations += 10
                assert status.original.name == "begin"
                assert status.total.name == "overall"
                assert status.current_strategy.name == "strategy_%d" % (idx,)
    assert status.finished_steps == [
        ReductionStep("begin", None, None, None, 1000, None),
        ReductionStep("strategy_0", 1, 1, 2, 900, 10),
        ReductionStep("strategy_1", 1, 1, 2, 800, 10),
        ReductionStep("strategy_2", 1, 1, 2, 700, 10),
        ReductionStep("strategy_3", 1, 1, 2, 600, 10),
        ReductionStep("strategy_4", 1, 1, 2, 500, 10),
        ReductionStep("overall", 5, 5, 10, 500, 50),
    ]
    assert status.original.name == "begin"
    assert status.total.name == "overall"
    assert status.current_strategy.name == "overall"


def test_reduce_status_06(mocker, tmp_path):
    """test ReductionStatus in-progress milestones"""
    mocker.patch("grizzly.common.status.time", autospec=True, return_value=1.0)
    status = ReductionStatus.start(
        str(tmp_path / "status.db"),
        testcase_size_cb=lambda: 47,
    )
    with status.measure("milestone"):
        assert len(status.finished_steps) == 0
        status2 = status.copy()
        assert len(status2.finished_steps) == 1

    assert status.analysis == status2.analysis
    assert status.attempts == status2.attempts
    assert status.iterations == status2.iterations
    assert status.run_params == status2.run_params
    assert status.signature_info == status2.signature_info
    assert status.successes == status2.successes
    assert status.current_strategy_idx == status2.current_strategy_idx
    assert status._testcase_size_cb is status2._testcase_size_cb
    assert status.crash_id == status2.crash_id
    assert status.finished_steps == status2.finished_steps
    assert status._in_progress_steps == status2._in_progress_steps
    assert status.strategies == status2.strategies
    assert status._db_file is not None
    assert status2._db_file is not None
    assert status.pid == status2.pid
    assert status.timestamp == status2.timestamp

    with status.measure("milestone2"):
        status.report(force=True)

        loaded_status = tuple(ReductionStatus.loadall(str(tmp_path / "status.db")))
        assert len(loaded_status) == 1
        loaded_status = loaded_status[0]

    assert loaded_status.finished_steps == status.finished_steps[:1]
    assert len(loaded_status._in_progress_steps) == 1

    loaded_status = loaded_status.copy()
    assert len(loaded_status.finished_steps) == 2
    assert len(loaded_status._in_progress_steps) == 0
    assert loaded_status.original == status.original
    for field in ReductionStep._fields:
        if field == "size":
            continue
        assert getattr(loaded_status.total, field) == getattr(status.total, field)
    assert loaded_status.total.size is None


def test_reduce_status_07(mocker, tmp_path):
    """test ReductionStatus metadata"""
    reporter = mocker.Mock(spec_set=FuzzManagerReporter)
    status = ReductionStatus.start(
        str(tmp_path / "status.db"),
        testcase_size_cb=lambda: 47,
        crash_id=123,
    )
    status.analysis["thing"] = "done"
    status.record("init")
    status.run_params["knob"] = "turned"
    status.signature_info["dumb"] = True
    status.add_to_reporter(reporter)
    assert reporter.add_extra_metadata.call_args_list == [
        mocker.call("reducer-stats", status.finished_steps),
        mocker.call("reducer-analysis", status.analysis),
        mocker.call("reducer-params", status.run_params),
        mocker.call("reducer-sig", status.signature_info),
        mocker.call("reducer-input", status.crash_id),
    ]


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
        assert counter.get(report_id) == (report_id, 0, None)
        assert not counter.is_frequent(report_id)
        # call count() with report_id 'count' times
        for current in range(1, count + 1):
            assert counter.count(report_id, "desc") == current
        # test get()
        if sum(counts) > 0:
            assert counter.get(report_id) == (report_id, count, "desc")
        else:
            assert counter.get(report_id) == (report_id, count, None)
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
    fake_time = mocker.patch("grizzly.common.status.time", autospec=True)
    fake_time.return_value = 1
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
    fake_time.return_value = 1000
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
    assert loaded.get("b") == ("b", 1, "desc_b")
    # last 3 seconds
    loaded = ResultCounter.load(db_path, 3)[0]
    assert loaded.get("a") == ("a", 2, "desc_a")
    assert loaded.total == 3
    # increase time limit
    fake_time.return_value = 4
    loaded = ResultCounter.load(db_path, 10)[0]
    assert loaded.total == counter.total == 3
    assert loaded.get("a") == ("a", 2, "desc_a")
    assert loaded.get("b") == ("b", 1, "desc_b")


def test_report_counter_04(mocker, tmp_path):
    """test ResultCounter remove expired entries"""
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
    # clear expired records from database by using duplicate pid
    ResultCounter(123, db_file=db_path, exp_limit=1000)
    assert not ResultCounter.load(db_path, 100)


def test_db_version_check_01(tmp_path):
    """test _db_version_check()"""
    db_path = str(tmp_path / "storage.db")
    try:
        con = connect(db_path)
        # empty db
        assert _db_version_check(con, expected=DB_VERSION)
        # no update needed
        assert not _db_version_check(con, expected=DB_VERSION)
        # add db contents
        Status.start(db_path)
        # force update
        assert _db_version_check(con, expected=DB_VERSION + 1)
    finally:
        con.close()
