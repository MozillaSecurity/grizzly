# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status reports"""
# pylint: disable=protected-access

import time

from .status import Status

def test_status_01(tmp_path):
    """test Status.start()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # create db
    assert not test_db.is_file()
    status = Status.start()
    assert status is not None
    assert status.start_time > 0
    assert status.timestamp == status.start_time
    assert status.duration == 0
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.rate == 0
    assert status.results == 0
    assert status.uid == 1
    # existing db
    assert test_db.is_file()
    status = Status.start()
    assert status.uid == 2
    # pass uid
    status = Status.start(uid=1234)
    assert status.uid == 1234

def test_status_02(tmp_path):
    """test Status.report()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # report with empty db
    Status(123, 1557934564).report()
    # normal report
    status = Status.start()
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

def test_status_03(tmp_path):
    """test Status.load()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # load no db
    assert Status.load(1) is None
    # create simple report
    status = Status.start()
    assert status.uid == 1
    # invalid uid
    assert Status.load(1337) is None
    # load default status report
    status = Status.load(status.uid)
    assert status is not None
    assert status.start_time > 0
    assert status.timestamp > 0
    assert status.duration == 0
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.results == 0

def test_status_04(tmp_path):
    """test Status.reset()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # reset with empty db
    Status(123, 1557934564).reset()
    status = Status.start()
    status.ignored = 1
    status.iteration = 5
    status.log_size = 2
    status.results = 3
    assert status.start_time > 0
    assert status.timestamp == status.start_time
    status.report(force=True)
    status.reset()
    assert status.uid == status.uid
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.results == 0
    ld_status = Status.load(status.uid)
    assert ld_status.uid == status.uid
    assert ld_status.ignored == status.ignored
    assert ld_status.iteration == status.iteration
    assert ld_status.log_size == status.log_size
    assert ld_status.results == status.results
    assert ld_status.start_time == status.start_time
    assert ld_status.timestamp == status.timestamp

def test_status_05(tmp_path):
    """test Status.load() and Status.report()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.ignored = 1
    status.iteration = 5
    status.log_size = 2
    status.results = 3
    assert status.start_time > 0
    assert status.timestamp == status.start_time
    status.report(force=True)
    ld_status = Status.load(status.uid)
    assert ld_status.uid == status.uid
    assert ld_status.ignored == status.ignored
    assert ld_status.iteration == status.iteration
    assert ld_status.log_size == status.log_size
    assert ld_status.results == status.results
    assert ld_status.start_time == status.start_time
    assert ld_status.timestamp == status.timestamp
    ld_status.timestamp += 1
    assert ld_status.duration > 0
    assert ld_status.rate > 0

def test_status_06(tmp_path):
    """test Status.cleanup()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # report with empty db
    Status(123, 1557934564).cleanup()
    # normal operation
    status = Status.start()
    assert Status.load(status.uid) is not None
    status.cleanup()
    assert Status.load(status.uid) is None
    # nothing to cleanup
    status.cleanup()

def test_status_07(tmp_path):
    """test Status.duration and Status.rate calculations"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.timestamp += 1
    status.iteration = 0
    assert status.duration == 1
    assert status.rate == 0
    status.iteration = 1
    assert status.rate == 1
    status.timestamp += 1
    assert status.rate == 0.5
