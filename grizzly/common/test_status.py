# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status"""
import time

import pytest

from .status import Status

def test_status_01(tmp_path):
    """test Status.start() and Status.close()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # create db
    assert not test_db.is_file()
    status = Status.start()
    assert status is not None
    assert status.conn is not None
    status.close()
    assert status.start_time > 0
    assert status.timestamp == status.start_time
    assert status.duration == 0
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.rate == 0
    assert status.results == 0
    assert status.uid == 1
    assert status.conn is None
    # call close 2nd time (already closed)
    status.close()
    # existing db
    assert test_db.is_file()
    status = Status.start()
    status.close()
    assert status.uid == 2
    # pass uid
    status = Status.start(uid=1234)
    status.close()
    assert status.uid == 1234

def test_status_02(tmp_path):
    """test Status.report()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    # report with no connection
    with pytest.raises(AssertionError):
        Status(123, 1557934564).report()
    # normal report
    status = Status.start()
    try:
        status.report()
        # REPORT_FREQ elapses
        status.timestamp = 0
        status.report()
        assert status.timestamp > 0
        # try to report before REPORT_FREQ elapses
        future = int(time.time()) + 1000
        status.timestamp = future
        status.report()
        assert status.timestamp == future
        # force report
        status.report(force=True)
        assert status.timestamp < future
    finally:
        status.close()

def test_status_03(tmp_path):
    """test Status.load() single"""
    Status.DB_FILE = str(tmp_path / "test.db")
    # load no db
    assert not tuple(Status.load(uid=1))
    # create simple entry
    status = Status.start()
    status.close()
    assert status.uid == 1
    # invalid uid
    assert not tuple(Status.load(uid=1337))
    # load default status entry
    entries = tuple(Status.load(uid=status.uid))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    status = entries[0]
    assert status is not None
    assert status.start_time > 0
    assert status.timestamp > 0
    assert status.duration == 0
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.results == 0

def test_status_04(tmp_path):
    """test Status.load() multiple"""
    Status.DB_FILE = str(tmp_path / "test.db")
    status = Status.start()
    status.close()
    # load all status entries
    conn = Status.open_connection()
    try:
        entries = tuple(Status.load(conn=conn))
    finally:
        conn.close()
    assert len(entries) == 1
    # should be read only since uid was not specified
    assert entries[0].conn is None
    # call close() on read only entry
    entries[0].close()
    # add more entries
    for _ in range(4):
        status = Status.start()
        status.close()
    # load single entry when many are available
    entries = tuple(Status.load(uid=1))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    # load all entries
    conn = Status.open_connection()
    try:
        entries = tuple(Status.load(conn=conn))
    finally:
        conn.close()
    assert len(entries) == 5
    # verify shared connection is not passed to status objects
    for entry in entries:
        assert entry.conn is None

def test_status_05(tmp_path):
    """test Status.reset()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    # reset with no connection
    with pytest.raises(AssertionError):
        Status(123, 1557934564).reset()
    status = Status.start()
    try:
        status.ignored = 1
        status.iteration = 5
        status.log_size = 2
        status.results = 3
        assert status.start_time > 0
        assert status.timestamp == status.start_time
        status.report(force=True)
        status.reset()
    finally:
        status.close()
    assert status.uid == status.uid
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.results == 0
    entries = tuple(Status.load(uid=status.uid))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    assert entries[0].uid == status.uid
    assert entries[0].ignored == status.ignored
    assert entries[0].iteration == status.iteration
    assert entries[0].log_size == status.log_size
    assert entries[0].results == status.results
    assert entries[0].start_time == status.start_time
    assert entries[0].timestamp == status.timestamp

def test_status_06(tmp_path):
    """test Status.load() and Status.report()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    status = Status.start()
    try:
        status.ignored = 1
        status.iteration = 5
        status.log_size = 2
        status.results = 3
        assert status.start_time > 0
        assert status.timestamp == status.start_time
        status.report(force=True)
    finally:
        status.close()
    entries = tuple(Status.load(uid=status.uid))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    assert entries[0].uid == status.uid
    assert entries[0].ignored == status.ignored
    assert entries[0].iteration == status.iteration
    assert entries[0].log_size == status.log_size
    assert entries[0].results == status.results
    assert entries[0].start_time == status.start_time
    assert entries[0].timestamp == status.timestamp
    entries[0].timestamp += 1
    assert entries[0].duration > 0
    assert entries[0].rate > 0

def test_status_07(tmp_path):
    """test Status.cleanup()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    # cleanup with no connection
    Status(123, 1557934564).cleanup()
    # normal operation
    status = Status.start()
    status.close()
    entries = tuple(Status.load(uid=status.uid))
    assert len(entries) == 1
    entries[0].cleanup()
    entries = tuple(Status.load(uid=status.uid))
    assert not entries
    # nothing to cleanup
    status.cleanup()

def test_status_08(tmp_path):
    """test Status.duration and Status.rate calculations"""
    Status.DB_FILE = str(tmp_path / "test.db")
    status = Status.start()
    status.close()
    status.timestamp += 1
    status.iteration = 0
    assert status.duration == 1
    assert status.rate == 0
    status.iteration = 1
    assert status.rate == 1
    status.timestamp += 1
    assert status.rate == 0.5
