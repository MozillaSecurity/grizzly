# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status"""
# pylint: disable=protected-access

import multiprocessing
import os
import time

from .status import ReducerStats, Status


def test_status_01(tmp_path):
    """test Status.start()"""
    working_path = tmp_path / "grzstatus"
    Status.PATH = str(working_path)
    status = Status.start()
    assert status is not None
    assert working_path.is_dir()
    assert os.path.isfile(status.data_file)
    assert os.stat(status.data_file).st_size > 0
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
    assert not os.path.isfile(dfile)
    # call 2nd time
    status.cleanup()
    # missing data file
    status = Status.start()
    os.remove(status.data_file)
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
    future = int(time.time()) + 1000
    status.timestamp = future
    assert status.report(force=True)
    assert status.timestamp < future

def test_status_04(tmp_path):
    """test Status.load()"""
    working_path = tmp_path / "grzstatus"
    Status.PATH = str(working_path)
    # load no db
    assert Status.load(str(tmp_path / "missing")) is None
    # load empty/invalid json
    working_path.mkdir()
    empty = (working_path / "empty.json")
    empty.touch()
    assert Status.load(str(empty)) is None
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

def test_status_05(tmp_path):
    """test Status.loadall()"""
    working_path = tmp_path / "grzstatus"
    Status.PATH = str(working_path)
    # missing path
    assert not tuple(Status.loadall())
    # no status data
    working_path.mkdir()
    assert not tuple(Status.loadall())
    # add more entries
    st_objs = list()
    for _ in range(5):
        st_objs.append(Status.start())
    (working_path / "empty.json").touch()
    assert len(tuple(Status.loadall())) == 5

def test_status_06(tmp_path):
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
    """Used by test_status_07"""
    Status.PATH = working_path
    status = Status.start()
    try:
        while not done.is_set():
            status.iteration += 1
            status.report(force=True)
            time.sleep(0.01)
    finally:
        status.cleanup()

def test_status_07(tmp_path):
    """test Status.loadall() with multiple active reporters"""
    Status.PATH = str(tmp_path / "grzstatus")
    best_rate = 0
    done = multiprocessing.Event()
    procs = list()
    try:
        for _ in range(5):
            procs.append(multiprocessing.Process(target=_client_writer, args=(done, Status.PATH)))
            procs[-1].start()
        deadline = time.time() + 60
        while len(tuple(Status.loadall())) < len(procs):
            time.sleep(0.1)
            assert time.time() < deadline, "timeout waiting for processes to launch!"
        for _ in range(20):
            st_objs = tuple(Status.loadall())
            for obj in st_objs:
                if obj.rate > best_rate:
                    best_rate = obj.rate
    finally:
        done.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()
    assert best_rate > 0
    assert not tuple(Status.loadall())

def test_reducer_stats_01(tmp_path):
    """test ReducerStats() empty"""
    ReducerStats.PATH = str(tmp_path)
    with ReducerStats() as stats:
        assert stats.error == 0
        assert stats.failed == 0
        assert stats.passed == 0
        stats_file = stats._file
        assert not os.path.isfile(stats_file)
    assert os.path.isfile(stats_file)

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
    """test ReducerStats() empty/invalid data file"""
    ReducerStats.PATH = str(tmp_path)
    with ReducerStats() as stats:
        stats.passed += 1
        stats_file = stats._file
    with open(stats_file, "w"):
        pass
    with ReducerStats() as stats:
        assert stats.passed == 0

def _reducer_client(working_path, limit, unrestrict):
    """Used by test_reducer_stats_04"""
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
    unrestrict = multiprocessing.Event()  # used to sync client procs
    try:
        proc_count = 5
        for _ in range(proc_count):
            procs.append(multiprocessing.Process(
                target=_reducer_client, args=(ReducerStats.PATH, proc_count, unrestrict)))
            procs[-1].start()
    finally:
        unrestrict.set()
        for proc in procs:
            if proc.pid is not None:
                proc.join()
    with ReducerStats() as stats:
        assert stats.passed == 250
