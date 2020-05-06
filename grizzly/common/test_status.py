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

from .status import ReducerStats, Status


def test_status_01(tmp_path):
    """test Status.start()"""
    working_path = tmp_path / "grzstatus"
    Status.PATH = str(working_path)
    status = Status.start()
    assert status is not None
    assert working_path.is_dir()
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

def test_status_02(tmp_path):
    """test Status.cleanup()"""
    Status.PATH = str(tmp_path / "grzstatus")
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
    Status.PATH = str(tmp_path / "grzstatus")
    status = Status.start()
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

def test_status_04(tmp_path):
    """test Status.load() failure paths"""
    working_path = tmp_path / "grzstatus"
    working_path.mkdir()
    Status.PATH = str(working_path)
    # load no db
    assert Status.load(str(tmp_path / "missing")) is None
    # load empty
    bad = (working_path / "bad.json")
    bad.touch()
    assert Status.load(str(bad)) is None
    # load invalid/incomplete json
    bad.write_bytes(b"{}")
    assert Status.load(str(bad)) is None

def test_status_05(tmp_path):
    """test Status.load()"""
    Status.PATH = str(tmp_path / "grzstatus")
    # create simple entry
    status = Status.start()
    loaded = Status.load(status.data_file)
    assert loaded is not None
    assert status.start_time == loaded.start_time
    assert status.timestamp == loaded.timestamp
    assert status.duration == loaded.duration
    assert status.ignored == loaded.ignored
    assert status.iteration == loaded.iteration
    assert status.log_size == loaded.log_size
    assert status.results == loaded.results

def test_status_06(tmp_path):
    """test Status.loadall()"""
    working_path = tmp_path / "grzstatus"
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
    Status.PATH = str(tmp_path / "grzstatus")
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

def _client_writer(done, working_path):
    """Used by test_status_08"""
    # NOTE: this must be at the top level to work on Windows
    Status.PATH = working_path
    status = Status.start()
    try:
        while not done.is_set():
            status.iteration += 1
            status.report(force=True)
            sleep(0.01)
    finally:
        status.cleanup()

def test_status_08(tmp_path):
    """test Status.loadall() with multiple active reporters"""
    Status.PATH = str(tmp_path / "grzstatus")
    best_rate = 0
    done = Event()
    procs = list()
    try:
        for _ in range(5):
            procs.append(Process(target=_client_writer, args=(done, Status.PATH)))
            procs[-1].start()
        deadline = time() + 60
        while len(tuple(Status.loadall())) < len(procs):
            sleep(0.1)
            assert time() < deadline, "timeout waiting for processes to launch!"
        for _ in range(20):
            for obj in Status.loadall():
                if obj.rate > best_rate:
                    best_rate = obj.rate
    finally:
        done.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()
    assert best_rate > 0
    assert not any(Status.loadall())

def test_reducer_stats_01(tmp_path):
    """test ReducerStats() empty"""
    ReducerStats.PATH = str(tmp_path)
    with ReducerStats() as stats:
        assert stats.error == 0
        assert stats.failed == 0
        assert stats.passed == 0
        stats_file = stats._file
        assert not isfile(stats_file)
    assert isfile(stats_file)

def test_reducer_stats_02(tmp_path):
    """test ReducerStats() simple"""
    ReducerStats.PATH = str(tmp_path)
    with ReducerStats() as stats:
        stats.error += 1
        stats.failed += 1
        stats.passed += 1
    with ReducerStats() as stats:
        assert stats.error == 1
        assert stats.failed == 1
        assert stats.passed == 1

def test_reducer_stats_03(tmp_path):
    """test ReducerStats() empty/incomplete/invalid data file"""
    ReducerStats.PATH = str(tmp_path)
    stats_file = tmp_path / ReducerStats.FILE
    # missing file
    with ReducerStats() as stats:
        stats.passed += 1
    # invalid empty file
    stats_file.write_bytes(b"")
    with ReducerStats() as stats:
        assert stats.passed == 0
    # incomplete file
    stats_file.write_bytes(b"{}")
    with ReducerStats() as stats:
        assert stats.passed == 0

def _reducer_client(working_path, limit, unrestrict):
    """Used by test_reducer_stats_04"""
    # NOTE: this must be at the top level to work on Windows
    ReducerStats.PATH = working_path
    for _ in range(50):
        with ReducerStats() as stats:
            stats.passed += 1
            if stats.passed == limit:
                unrestrict.set()
        unrestrict.wait(timeout=60)

def test_reducer_stats_04(tmp_path):
    """test ReducerStats() with multiple processes"""
    ReducerStats.PATH = str(tmp_path)
    procs = list()
    unrestrict = Event()  # used to sync client procs
    try:
        proc_count = 5
        for _ in range(proc_count):
            procs.append(Process(
                target=_reducer_client, args=(ReducerStats.PATH, proc_count, unrestrict)))
            procs[-1].start()
    finally:
        unrestrict.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()
    with ReducerStats() as stats:
        assert stats.passed == 250
