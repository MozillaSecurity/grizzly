# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status"""
# pylint: disable=protected-access

from multiprocessing import Event, Process
from time import sleep, time

from .status import Status


def test_status_01(mocker, tmp_path):
    """test Status.start()"""
    mocker.patch("grizzly.common.status.time", return_value=1.0)
    status = Status.start(db_file=str(tmp_path / "status.db"))
    assert status is not None
    assert status._db_file is not None
    assert status.start_time > 0
    assert status.timestamp >= status.start_time
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.rate == 0
    assert status.results == 0
    assert int(status.runtime) == 0
    assert status.pid is not None
    assert not status._enable_profiling
    assert not status._profiles


def test_status_02(tmp_path):
    """test Status.report()"""
    status = Status.start(db_file=str(tmp_path / "status.db"))
    status.count_result("uid1", "sig1")
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


def test_status_03(mocker, tmp_path):
    """test Status.load()"""
    mocker.patch("grizzly.common.status.time", return_value=1.0)
    db_file = str(tmp_path / "status.db")
    # create simple entry
    status = Status.start(db_file=db_file, enable_profiling=True)
    status.count_result("uid1", "sig1")
    status.record("test", 123.45)
    status.report(force=True)
    assert status.results == 1
    loaded = next(Status.loadall(db_file=db_file))
    assert status.start_time == loaded.start_time
    assert status.timestamp == loaded.timestamp
    assert status.runtime == loaded.runtime
    assert status.ignored == loaded.ignored
    assert status.iteration == loaded.iteration
    assert status.log_size == loaded.log_size
    assert status.pid == loaded.pid
    assert status.results == loaded.results
    assert not loaded._enable_profiling
    assert "test" in loaded._profiles


def test_status_04(mocker, tmp_path):
    """test Status.loadall()"""
    getpid = mocker.patch("grizzly.common.status.getpid")
    db_file = str(tmp_path / "status.db")
    for pid in range(5):
        getpid.return_value = pid
        Status.start(db_file=db_file)
    assert len(tuple(Status.loadall(db_file=db_file))) == 5


def test_status_05(mocker, tmp_path):
    """test Status.runtime and Status.rate calculations"""
    mocker.patch(
        "grizzly.common.status.time",
        side_effect=(
            1.0,
            1.0,
            3.0,
            3.0,
            5.0,
            5.0,
            5.0,
            5.0,
            5.0,
        ),
    )
    db_file = str(tmp_path / "status.db")
    status = Status.start(db_file=db_file)
    assert status.start_time == 1
    # test no iterations
    assert status.runtime == 2.0
    assert status.rate == 0
    # test one iteration
    status.iteration = 1
    # timestamp should be ignored when calculating rate and runtime on active object
    status.timestamp = 100
    assert status.runtime == 4.0
    assert status.rate == 0.25
    # test loaded
    status.report(force=True)
    loaded = next(Status.loadall(db_file=db_file))
    assert loaded.runtime == 4.0
    assert loaded.rate == 0.25
    # timestamp should be used when calculating rate and runtime on loaded object
    loaded.timestamp = 2.0
    assert loaded.runtime == 1.0
    assert loaded.rate == 1.0


def _client_writer(done, reported, db_file):
    """Used by test_status_08"""
    # NOTE: this must be at the top level to work on Windows
    status = Status.start(db_file=db_file)
    while not done.is_set():
        status.iteration += 1
        status.report(force=True)
        # perform two reports before setting flag
        if not reported.is_set() and status.iteration > 1:
            reported.set()
        sleep(0.01)


def test_status_08(tmp_path):
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
        for has_reported in report_events:
            assert has_reported.wait(timeout=60)
        # collect reports
        reports = tuple(Status.loadall(db_file))
        assert len(reports) == len(procs)
        assert max(x.rate for x in reports) > 0
    finally:
        done.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()


def test_status_09(tmp_path):
    """test Status.count_result() and Status.result_entries()"""
    status = Status.start(db_file=str(tmp_path / "status.db"))
    assert status.count_result("uid1", "sig1") == 1
    assert status.count_result("uid2", "sig2") == 1
    assert status.count_result("uid1", "sig1") == 2
    assert status.count_result("uid3", "sig3") == 1
    assert status.results == 4
    found = dict()
    for _, result in status.result_entries():
        found[result["desc"]] = result["count"]
    assert "sig1" in found
    assert found["sig1"] == 2
    assert "sig2" in found
    assert found["sig2"] == 1
    assert "sig3" in found
    assert found["sig3"] == 1


def test_status_10(tmp_path):
    """test Status.measure() and Status.record() - profiling support"""
    db_file = str(tmp_path / "status.db")
    # profiling disabled
    status = Status.start(db_file=db_file, enable_profiling=False)
    status.record("x", 10.1)
    assert not status._profiles
    with status.measure("x"):
        pass
    assert not status._profiles
    # profiling enabled
    status = Status.start(db_file=db_file, enable_profiling=True)
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
