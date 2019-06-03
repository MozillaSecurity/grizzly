# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status reports"""
# pylint: disable=protected-access

from .status import Status
from .reduce_status import ReduceStatus

def test_reduce_status_01(tmp_path):
    """test ReduceStatus.start()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # create db
    assert not test_db.is_file()
    status = ReduceStatus.start()
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
    assert status.uid == 2
    # pass uid
    status = Status.start(1234)
    assert status.uid == 1234

def test_reduce_status_02(tmp_path):
    """test ReduceStatus.report()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # report with empty db
    ReduceStatus(Status(123, 1557934564)).report()
    # normal report
    status = ReduceStatus.start()
    status.report()
    # try to report before REPORT_FREQ elapses
    status.report()

def test_reduce_status_03(tmp_path):
    """test ReduceStatus.load()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # load no db
    assert ReduceStatus.load(1) is None
    # create simple report
    status = ReduceStatus.start()
    assert status.uid == 1
    # invalid uid
    assert ReduceStatus.load(1337) is None
    # load default reduce status report
    status = ReduceStatus.load(status.uid)
    assert status is not None
    assert status.start_time > 0
    assert status.timestamp > 0
    assert status.duration == 0
    assert status.iteration == 0
    assert status.reduce_error == 0
    assert status.reduce_fail == 0
    assert status.reduce_pass == 0

def test_reduce_status_04(tmp_path):
    """test ReportStatus.load() on Status object"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # create simple report
    status = Status.start()
    assert status is not None
    assert ReduceStatus.load(status.uid) is None

def test_reduce_status_05(tmp_path):
    """test ReduceStatus.cleanup()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = ReduceStatus.start()
    assert Status.load(status.uid) is not None
    status.cleanup()
    assert Status.load(status.uid) is None
    # nothing to cleanup
    status.cleanup()

def test_reduce_status_06(tmp_path):
    """test ReduceStatus.load() and ReduceStatus.report()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = ReduceStatus.start()
    status.ignored += 1
    status.iteration = 12345
    status.reduce_error = 33
    status.reduce_fail = 22
    status.reduce_pass = 11
    status.results = 10
    status.report(force=True)
    ld_status = ReduceStatus.load(status.uid)
    assert ld_status.uid == status.uid
    assert status.ignored == 1
    assert status.results == 10
    assert ld_status.ignored == status.ignored
    assert ld_status.iteration == status.iteration
    assert ld_status.reduce_error == status.reduce_error
    assert ld_status.reduce_fail == status.reduce_fail
    assert ld_status.reduce_pass == status.reduce_pass
    assert ld_status.results == status.results
    assert ld_status.start_time == status.start_time
    assert ld_status.timestamp == status.timestamp

def test_reduce_status_07(tmp_path):
    """test ReduceStatus.report(reset_status=True)"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = ReduceStatus.start()
    status.ignored += 1
    status.iteration = 12345
    status.reduce_error = 33
    status.reduce_fail = 22
    status.reduce_pass = 11
    status.results = 10
    status.report(force=True)
    ld_status = ReduceStatus.load(status.uid)
    ld_status.report(reset_status=True)
    ld_status = ReduceStatus.load(status.uid)
    assert ld_status.uid == status.uid
    assert ld_status.duration == 0
    assert ld_status.ignored == 0
    assert ld_status.iteration == 0
    assert ld_status.results == 0
    assert ld_status.reduce_error == 33
    assert ld_status.reduce_fail == 22
    assert ld_status.reduce_pass == 11

def test_reduce_status_08(tmp_path):
    """test ReduceStatus.load() with Status and ReduceStatus"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.iteration = 11
    status.report(force=True)
    status = ReduceStatus.start()
    status.iteration = 22
    status.report(force=True)
    ld_status = ReduceStatus.load(status.uid)
    assert ld_status.uid == status.uid
    assert ld_status.iteration == 22
