# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status"""
# pylint: disable=protected-access

from multiprocessing import Event, Process
from os import remove, stat
from os.path import isfile
from time import sleep, time

from .status import Status


def test_status_01(mocker, tmp_path):
    """test Status.start()"""
    mocker.patch("grizzly.common.status.time", return_value=1.0)
    status = Status.start(path=str(tmp_path))
    assert status is not None
    assert status.data_file is not None
    assert isfile(status.data_file)
    assert stat(status.data_file).st_size > 0
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
    """test Status.cleanup()"""
    status = Status.start(path=str(tmp_path))
    dfile = status.data_file
    status.cleanup()
    assert status.data_file is None
    assert not isfile(dfile)
    # call 2nd time
    status.cleanup()
    # missing data file
    status = Status.start(path=str(tmp_path))
    remove(status.data_file)
    status.cleanup()


def test_status_03(tmp_path):
    """test Status.report()"""
    status = Status.start(path=str(tmp_path))
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
    status.cleanup()


def test_status_04(tmp_path):
    """test Status.load() failure paths"""
    # load no db
    assert Status.load(str(tmp_path / "missing.json")) is None
    # load empty
    bad = tmp_path / "bad.json"
    bad.touch()
    assert Status.load(str(bad)) is None
    # load invalid/incomplete json
    bad.write_bytes(b"{}")
    assert Status.load(str(bad)) is None


def test_status_05(mocker, tmp_path):
    """test Status.load()"""
    mocker.patch("grizzly.common.status.time", return_value=1.0)
    # create simple entry
    status = Status.start(path=str(tmp_path), enable_profiling=True)
    status.count_result("uid1", "sig1")
    status.record("test", 123.45)
    status.report(force=True)
    assert status.results == 1
    loaded = Status.load(status.data_file)
    assert loaded.data_file is None
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
    loaded.cleanup()
    assert isfile(status.data_file)
    data_file = status.data_file
    status.cleanup()
    assert not isfile(data_file)


def test_status_06(tmp_path):
    """test Status.loadall()"""
    # missing path
    assert not any(Status.loadall("missing"))
    # no status data
    assert not any(Status.loadall(str(tmp_path)))
    # add more entries
    for _ in range(5):
        Status.start(path=str(tmp_path))
    (tmp_path / "empty.json").touch()
    assert len(tuple(Status.loadall(str(tmp_path)))) == 5


def test_status_07(mocker, tmp_path):
    """test Status.runtime and Status.rate calculations"""
    mocker.patch(
        "grizzly.common.status.time", side_effect=(1.0, 1.0, 3.0, 3.0, 5.0, 5.0, 5.0)
    )
    status = Status.start(path=str(tmp_path))
    assert status.data_file is not None
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
    loaded = Status.load(status.data_file)
    assert loaded.runtime == 4.0
    assert loaded.rate == 0.25
    # timestamp should be used when calculating rate and runtime on loaded object
    loaded.timestamp = 2.0
    assert loaded.runtime == 1.0
    assert loaded.rate == 1.0


def _client_writer(done, reported, working_path):
    """Used by test_status_08"""
    # NOTE: this must be at the top level to work on Windows
    status = Status.start(path=working_path)
    try:
        while not done.is_set():
            status.iteration += 1
            status.report(force=True)
            # perform two reports before setting flag
            if not reported.is_set() and status.iteration > 1:
                reported.set()
            sleep(0.01)
    finally:
        status.cleanup()


def test_status_08(tmp_path):
    """test Status.loadall() with multiple active reporters"""
    done = Event()
    procs = list()
    report_events = list()
    try:
        # launch processes
        for _ in range(5):
            report_events.append(Event())
            procs.append(
                Process(
                    target=_client_writer, args=(done, report_events[-1], str(tmp_path))
                )
            )
            procs[-1].start()
        # wait for processes to launch and report
        for has_reported in report_events:
            assert has_reported.wait(timeout=60)
        # collect reports
        reports = tuple(Status.loadall(str(tmp_path)))
        assert len(reports) == len(procs)
        assert max(x.rate for x in reports) > 0
    finally:
        done.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()
    # verify cleanup
    assert not any(Status.loadall(str(tmp_path)))


def test_status_09(tmp_path):
    """test Status.count_result() and Status.result_entries()"""
    status = Status.start(path=str(tmp_path))
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
    # profiling disabled
    status = Status.start(path=str(tmp_path), enable_profiling=False)
    status.record("x", 10.1)
    assert not status._profiles
    with status.measure("x"):
        pass
    assert not status._profiles
    status.cleanup()
    # profiling enabled
    status = Status.start(path=str(tmp_path), enable_profiling=True)
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
