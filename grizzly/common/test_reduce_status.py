# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status reports"""
# pylint: disable=protected-access
import pytest

from .status import Status
from .reduce_status import ReduceStatus

def test_reduce_status_01(tmp_path):
    """test ReduceStatus.start()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # create db
    assert not test_db.is_file()
    status = ReduceStatus.start()
    assert status is not None
    status.close()
    assert status.uid == 1
    assert status.start_time > 0
    assert status.timestamp > 0
    assert status.duration == 0
    assert status.iteration == 0
    assert status.rate == 0
    assert status.reduce_error == 0
    assert status.reduce_fail == 0
    assert status.reduce_pass == 0
    # existing db
    assert test_db.is_file()
    status = Status.start()
    status.close()
    assert status.uid == 2
    # pass uid
    status = Status.start(1234)
    status.close()
    assert status.uid == 1234

def test_reduce_status_02(tmp_path):
    """test ReduceStatus.report()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    # report with empty db
    with pytest.raises(AssertionError):
        ReduceStatus(Status(123, 1557934564)).report()
    # normal report
    status = ReduceStatus.start()
    try:
        status.report()
        # try to report before REPORT_FREQ elapses
        status.report()
    finally:
        status.close()

def test_reduce_status_03(tmp_path):
    """test ReduceStatus.load()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    # load with empty db
    assert not tuple(ReduceStatus.load(uid=1))
    conn = ReduceStatus.open_connection()
    try:
        assert not tuple(ReduceStatus.load(conn=conn))
    finally:
        conn.close()
    # create simple report
    status = ReduceStatus.start()
    status.close()
    assert status.uid == 1
    # invalid uid
    assert not tuple(ReduceStatus.load(uid=1337))
    # load all entries
    conn = ReduceStatus.open_connection()
    try:
        assert len(tuple(Status.load(conn=conn))) == 1
    finally:
        conn.close()
    # load default reduce status report
    entries = tuple(ReduceStatus.load(uid=status.uid))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    assert status.start_time > 0
    assert status.timestamp > 0
    assert status.duration == 0
    assert status.iteration == 0
    assert status.reduce_error == 0
    assert status.reduce_fail == 0
    assert status.reduce_pass == 0

def test_reduce_status_04(tmp_path):
    """test ReportStatus.load() on Status object"""
    Status.DB_FILE = str(tmp_path / "test.db")
    # create simple report
    status = Status.start()
    assert status is not None
    status.close()
    assert not tuple(ReduceStatus.load(uid=status.uid))

def test_reduce_status_05(tmp_path):
    """test ReduceStatus.cleanup()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    status = ReduceStatus.start()
    # nothing to cleanup
    status.cleanup()
    # cleanup one entry
    status = ReduceStatus.start()
    status.close()
    entries = tuple(ReduceStatus.load(uid=status.uid))
    assert len(entries) == 1
    entries[0].cleanup()
    conn = ReduceStatus.open_connection()
    try:
        assert not tuple(Status.load(conn=conn))
    finally:
        conn.close()

def test_reduce_status_06(tmp_path):
    """test ReduceStatus.load() and ReduceStatus.report()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    status = ReduceStatus.start()
    try:
        status.ignored += 1
        status.iteration = 12345
        status.reduce_error = 33
        status.reduce_fail = 22
        status.reduce_pass = 11
        status.results = 10
        status.report(force=True)
    finally:
        status.close()
    entries = tuple(ReduceStatus.load(uid=status.uid))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    assert entries[0].uid == status.uid
    assert status.ignored == 1
    assert status.results == 10
    assert entries[0].ignored == status.ignored
    assert entries[0].iteration == status.iteration
    assert entries[0].reduce_error == status.reduce_error
    assert entries[0].reduce_fail == status.reduce_fail
    assert entries[0].reduce_pass == status.reduce_pass
    assert entries[0].results == status.results
    assert entries[0].start_time == status.start_time
    assert entries[0].timestamp == status.timestamp

def test_reduce_status_07(tmp_path):
    """test ReduceStatus.report(reset_status=True)"""
    Status.DB_FILE = str(tmp_path / "test.db")
    status = ReduceStatus.start()
    try:
        status.ignored += 1
        status.iteration = 12345
        status.reduce_error = 33
        status.reduce_fail = 22
        status.reduce_pass = 11
        status.results = 10
        status.report(force=True)
        status.report(reset_status=True)
    finally:
        status.close()
    entries = tuple(ReduceStatus.load(uid=status.uid))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    assert entries[0].uid == status.uid
    assert entries[0].duration == 0
    assert entries[0].ignored == 0
    assert entries[0].iteration == 0
    assert entries[0].results == 0
    assert entries[0].reduce_error == 33
    assert entries[0].reduce_fail == 22
    assert entries[0].reduce_pass == 11

def test_reduce_status_08(tmp_path):
    """test ReduceStatus.load() with Status and ReduceStatus"""
    Status.DB_FILE = str(tmp_path / "test.db")
    status = Status.start()
    try:
        status.iteration = 11
        status.report(force=True)
        status = ReduceStatus.start()
        status.iteration = 22
        status.report(force=True)
    finally:
        status.close()
    entries = tuple(ReduceStatus.load(uid=status.uid))
    for entry in entries:
        entry.close()
    assert len(entries) == 1
    assert entries[0].uid == status.uid
    assert entries[0].iteration == 22
