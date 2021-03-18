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


def test_status_01(tmp_path):
    """test Status.start()"""
    Status.PATH = str(tmp_path)
    status = Status.start()
    assert status is not None
    assert status.data_file is not None
    assert isfile(status.data_file)
    assert stat(status.data_file).st_size > 0
    assert status.start_time > 0
    assert status.timestamp >= status.start_time
    assert int(status.duration) == 0
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.rate == 0
    assert status.results == 0
    assert status.pid is not None
    assert not status._enable_profiling
    assert not status._profiles


def test_status_02(tmp_path):
    """test Status.cleanup()"""
    Status.PATH = str(tmp_path)
    status = Status.start()
    dfile = status.data_file
    status.cleanup()
    assert status.data_file is None
    assert not isfile(dfile)
    # call 2nd time
    status.cleanup()
    # missing data file
    status = Status.start()
    remove(status.data_file)
    status.cleanup()


def test_status_03(tmp_path):
    """test Status.report()"""
    Status.PATH = str(tmp_path)
    status = Status.start()
    status.count_result("sig1")
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
    Status.PATH = str(tmp_path)
    # load no db
    assert Status.load(str(tmp_path / "missing.json")) is None
    # load empty
    bad = tmp_path / "bad.json"
    bad.touch()
    assert Status.load(str(bad)) is None
    # load invalid/incomplete json
    bad.write_bytes(b"{}")
    assert Status.load(str(bad)) is None


def test_status_05(tmp_path):
    """test Status.load()"""
    Status.PATH = str(tmp_path)
    # create simple entry
    status = Status.start(enable_profiling=True)
    status.count_result("sig1")
    status.record("test", 123.45)
    status.report(force=True)
    assert status.results == 1
    loaded = Status.load(status.data_file)
    assert loaded.data_file is None
    assert status.start_time == loaded.start_time
    assert status.timestamp == loaded.timestamp
    assert status.duration == loaded.duration
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
    working_path = tmp_path / "status"
    Status.PATH = str(working_path)
    # missing path
    assert not any(Status.loadall())
    # no status data
    working_path.mkdir()
    assert not any(Status.loadall())
    # add more entries
    for _ in range(5):
        Status.start()
    (working_path / "empty.json").touch()
    assert len(tuple(Status.loadall())) == 5


def test_status_07(tmp_path):
    """test Status.duration and Status.rate calculations"""
    Status.PATH = str(tmp_path)
    status = Status.start()
    status.start_time = 1
    status.timestamp = 2
    status.iteration = 0
    assert status.duration == 1
    assert status.rate == 0
    status.iteration = 1
    assert status.rate == 1
    status.timestamp += 1
    assert status.rate == 0.5


def _client_writer(done, reported, working_path):
    """Used by test_status_08"""
    # NOTE: this must be at the top level to work on Windows
    Status.PATH = working_path
    status = Status.start()
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
    Status.PATH = str(tmp_path)
    done = Event()
    procs = list()
    report_events = list()
    try:
        # launch processes
        for _ in range(5):
            report_events.append(Event())
            procs.append(
                Process(
                    target=_client_writer, args=(done, report_events[-1], Status.PATH)
                )
            )
            procs[-1].start()
        # wait for processes to launch and report
        for has_reported in report_events:
            assert has_reported.wait(timeout=60)
        # collect reports
        reports = tuple(Status.loadall())
        assert len(reports) == len(procs)
        assert max(x.rate for x in reports) > 0
    finally:
        done.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()
    # verify cleanup
    assert not any(Status.loadall())


def test_status_09(tmp_path):
    """test Status.count_result() and Status.signatures()"""
    Status.PATH = str(tmp_path)
    status = Status.start()
    status.count_result("sig1")
    status.count_result("sig2")
    status.count_result("sig1")
    status.count_result("sig3")
    assert status.results == 4
    found = dict()
    for sig, count in status.signatures():
        found[sig] = count
    assert "sig1" in found
    assert found["sig1"] == 2
    assert "sig2" in found
    assert found["sig2"] == 1
    assert "sig3" in found
    assert found["sig3"] == 1


def test_status_10(tmp_path):
    """test Status.measure() and Status.record() - profiling support"""
    Status.PATH = str(tmp_path)
    # profiling disabled
    status = Status.start(enable_profiling=False)
    status.record("x", 10.1)
    assert not status._profiles
    with status.measure("x"):
        pass
    assert not status._profiles
    status.cleanup()
    # profiling enabled
    status = Status.start(enable_profiling=True)
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
