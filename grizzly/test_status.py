# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status reports"""
# pylint: disable=protected-access

import re
import time

from .status import main, Status, StatusReporter, TracebackReport

def test_status_01(tmp_path):
    """test Status.start()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # create db
    assert not test_db.is_file()
    status = Status.start()
    assert status._id == 1
    assert status._start_time is not None
    # existing db
    assert test_db.is_file()
    status = Status.start()
    assert status._id == 2

def test_status_02(tmp_path):
    """test Status.report()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # report with empty db
    Status(123).report()
    # normal report
    status = Status.start()
    status.report()
    # try to report before REPORT_FREQ elapses
    status.report()
    # try to report 'loaded' report
    status.timestamp = 0
    status._start_time = None
    status.report()
    assert status.timestamp == 0

def test_status_03(tmp_path):
    """test Status.load()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # load no db
    assert Status.load(1) is None
    # create simple report
    status = Status.start()
    assert status._id == 1
    # invalid uid
    assert Status.load(1337) is None
    # load default status report
    status = Status.load(status._id)
    assert status is not None
    assert status._start_time is None
    assert status.timestamp > 0
    assert status.duration == 0
    assert status.ignored == 0
    assert status.iteration == 0
    assert status.log_size == 0
    assert status.results == 0

def test_status_04(tmp_path):
    """test Status.load() and Status.report()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.duration = 10
    status.ignored = 1
    status.iteration = 5
    status.log_size = 2
    status.results = 3
    assert status.timestamp == 0
    status.report()
    assert status.timestamp > 0
    ld_status = Status.load(status._id)
    assert ld_status._id == status._id
    assert ld_status.duration > 0
    assert ld_status.ignored == status.ignored
    assert ld_status.iteration == status.iteration
    assert ld_status.log_size == status.log_size
    assert ld_status.rate > 0
    assert ld_status.results == status.results
    assert ld_status.timestamp == int(status.timestamp)

def test_status_05(tmp_path):
    """test Status.cleanup()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # report with empty db
    Status(123).cleanup()
    # normal operation
    status = Status.start()
    assert Status.load(status._id) is not None
    status.cleanup()
    assert Status.load(status._id) is None
    # nothing to cleanup
    status.cleanup()

def test_status_reporter_01(tmp_path):
    """test basic StatusReporter"""
    st_rpt = StatusReporter(list())
    out = st_rpt._specific()
    assert "No status reports loaded" in out
    report = tmp_path / "output.txt"
    st_rpt.dump_specific(str(report))
    assert report.is_file()
    st_rpt.print_specific()
    out = st_rpt._summary()
    assert "No status reports loaded" in out
    report.unlink()
    st_rpt.dump_summary(str(report))
    assert report.is_file()
    st_rpt.print_summary()

def test_status_reporter_02(tmp_path):
    """test StatusReporter.load()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    st_rpt = StatusReporter.load(tb_path="no_dir", db_file=str(test_db))
    assert isinstance(st_rpt.reports, list)
    assert isinstance(st_rpt.tracebacks, list)
    assert not st_rpt.reports
    assert not st_rpt.tracebacks
    st_rpt = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert isinstance(st_rpt.reports, list)
    assert isinstance(st_rpt.tracebacks, list)
    assert not st_rpt.reports
    assert not st_rpt.tracebacks

def test_status_reporter_03():
    """test StatusReporter._sys_info()"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    sysinfo = StatusReporter._sys_info()
    lines = sysinfo.split("\n")
    assert len(lines) == 3
    assert "CPU & Load : " in lines[0]
    assert "Memory : " in lines[1]
    assert "Disk : " in lines[2]
    # verify alignment
    position = len(lines[0].split(":")[0])
    for line in lines:
        assert line[position] == ":"

def test_status_reporter_04(tmp_path):
    """test StatusReporter._scan()"""
    re_filter = re.compile("TEST_FILE")
    files = tuple(StatusReporter._scan("none", re_filter))
    assert not files
    boring = tmp_path / "somefile.txt"
    boring.touch()
    test_path = tmp_path / "TEST_FILE"
    test_path.mkdir()
    files = tuple(StatusReporter._scan(str(tmp_path), re_filter))
    assert not files
    test_path.rmdir()
    test_path.touch()
    files = tuple(StatusReporter._scan(str(tmp_path), re_filter))
    assert not files
    test_path.write_bytes(b"test")
    files = tuple(StatusReporter._scan(str(tmp_path), re_filter))
    assert files

def test_status_reporter_05(tmp_path):
    """test StatusReporter._summary()"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.duration = 0.0
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.rate = 0.1
    status.results = 0
    status.report()
    rptr = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert rptr.reports is not None
    assert len(rptr.reports) == 1
    output = rptr._summary(runtime=False)
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "ignored" not in output
    assert "Logs" not in output
    assert "Runtime" not in output
    assert "Timestamp" not in output
    assert len(output.split("\n")) == 3
    status = Status.start()
    status.duration = 66.0
    status.ignored = 1
    status.iteration = 8
    status.log_size = 86900000
    status.rate = 0.121
    status.results = 0
    status.report()
    rptr = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert len(rptr.reports) == 2
    output = rptr._summary(sysinfo=True, timestamp=True)
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "ignored" in output
    assert "Logs" in output
    assert "Runtime" in output
    assert "Timestamp" in output
    lines = output.split("\n")
    assert len(lines) == 9
    # verify alignment
    position = len(lines[0].split(":")[0])
    for line in lines:
        assert re.match(r"\s:\s\S", line[position - 1:])

def test_status_reporter_06(tmp_path):
    """test StatusReporter._specific()"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.duration = 0.0
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.rate = 0.1
    status.results = 0
    status.report()
    rptr = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert rptr.reports is not None
    output = rptr._specific()
    lines = output.split("\n")[:-1]
    assert len(lines) == 2
    assert "Ignored" in output
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "EXPIRED" not in output
    status = Status.start()
    status.duration = 864123.2
    status.ignored = 1
    status.iteration = 432422
    status.log_size = 86900000
    status.rate = 1.1
    status.results = 123
    status._start_time = time.time() - 68000
    status.report()
    rptr = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert len(rptr.reports) == 2
    output = rptr._specific()
    lines = output.split("\n")[:-1]
    assert len(lines) == 4
    assert "Ignored" in output
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output

def test_status_reporter_07(tmp_path):
    """test StatusReporter.load_reports() with traceback"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.duration = 0.0
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.rate = 0.1
    status.results = 0
    status.report()
    # create boring screenlog
    test_log = tmp_path / "screenlog.0"
    test_log.write_bytes(b"boring\ntest\n123\n")
    # create first screenlog
    test_log = tmp_path / "screenlog.1"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert len(rptr.tracebacks) == 1
    # create second screenlog
    test_log = tmp_path / "screenlog.1234"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"foo.bar.error: blah\n")
    rptr = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert len(rptr.tracebacks) == 2
    # create third screenlog
    test_log = tmp_path / "screenlog.3"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"KeyboardInterrupt\n")
    rptr = StatusReporter.load(tb_path=str(tmp_path), db_file=str(test_db))
    assert len(rptr.tracebacks) == 2
    merged_log = rptr._summary()
    assert len(merged_log.splitlines()) == 14
    assert "screenlog.1" in merged_log
    assert "screenlog.1234" in merged_log
    assert "IndexError" in merged_log
    assert "foo.bar.error" in merged_log
    assert "screenlog.3" not in merged_log

def test_traceback_report_01():
    """test simple TracebackReport"""
    tbr = TracebackReport("log.txt", ["0", "1", "2"], prev_lines=["-2", "-1"])
    output = str(tbr)
    assert len(output.splitlines()) == 6
    assert "log.txt" in output
    assert "2" in output
    assert "-2" in output

def test_traceback_report_02():
    """test empty TracebackReport"""
    tbr = TracebackReport("log.txt", [])
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 1
    assert "log.txt" in output

def test_traceback_report_03(tmp_path):
    """test TracebackReport.from_file()"""
    test_log = tmp_path / "screenlog.0"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"start junk\npre1\npre2\npre3\npre4\npre5\n")
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  File \"foo.py\", line 556, in <module>\n")
        test_fp.write(b"    main(parse_args())\n")
        test_fp.write(b"  File \"foo.py\", line 207, in bar\n")
        test_fp.write(b"    a = b[10]\n")
        test_fp.write(b"IndexError: list index out of range\n")
        test_fp.write(b"end junk\n")
    tbr = TracebackReport.from_file(str(test_log))
    assert len(tbr.prev_lines) == 5
    assert len(tbr.lines) == 6
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 12
    assert "pre1" in output
    assert "IndexError" in output
    assert "screenlog.0" in output
    assert "junk" not in output

    with test_log.open("wb") as test_fp:
        test_fp.write(b"start junk\n")
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  File \"foo.py\", line 556, in <module>\n")
        test_fp.write(b"    main(parse_args())\n")
        test_fp.write(b"  File \"foo.py\", line 207, in bar\n")
        test_fp.write(b"    a = b[10]\n")
        test_fp.write(b"foo.bar.error: blah\n")
        test_fp.write(b"end junk\n")
    tbr = TracebackReport.from_file(str(test_log), max_preceeding=0)
    assert len(tbr.lines) == 6
    assert not tbr.prev_lines
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 7
    assert "screenlog.0" in output
    assert "foo.bar.error" in output
    assert "junk" not in output
    # kbi
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  File \"foo.py\", line 556, in <module>\n")
        test_fp.write(b"    main(parse_args())\n")
        test_fp.write(b"  File \"foo.py\", line 207, in bar\n")
        test_fp.write(b"    a = b[10]\n")
        test_fp.write(b"KeyboardInterrupt\n")
        test_fp.write(b"end junk\n")
    tbr = TracebackReport.from_file(str(test_log))
    assert tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 7
    assert "KeyboardInterrupt" in output

def test_traceback_report_04(tmp_path):
    """test TracebackReport.from_file() exceed size limit"""
    test_log = tmp_path / "screenlog.0"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        for _ in range(TracebackReport.MAX_LINES * 2):
            test_fp.write(b"  File \"foo.py\", line 556, in <module>\n")
            test_fp.write(b"    main()\n")
        test_fp.write(b"  File \"foo.py\", line 207, in bar\n")
        test_fp.write(b"    a = b[10]\n")
        test_fp.write(b"END_WITH_BLANK_LINE\n\n")
        test_fp.write(b"end junk\n")
    tbr = TracebackReport.from_file(str(test_log))
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 17
    assert "..." in output
    assert "END_WITH_BLANK_LINE" in output

def test_traceback_report_05(tmp_path):
    """test TracebackReport.from_file() cut off"""
    test_log = tmp_path / "screenlog.0"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        for i in range(TracebackReport.MAX_LINES * 2):
            test_fp.write(b"  File \"foo.py\", line 5, in <module>\n")
            test_fp.write(b"    func_%d()\n" % i)
    tbr = TracebackReport.from_file(str(test_log))
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 17
    assert "..." in output
    assert "func_%d" % (TracebackReport.MAX_LINES * 2 - 1) in output

def test_main_01(tmp_path):
    """test main() with no reports"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    main([])

def test_main_02(tmp_path):
    """test main() with a report"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    assert status._start_time is not None
    assert status.timestamp == 0
    status.duration = 0.0
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.rate = 0.1
    status.results = 0
    status.report()
    assert status.timestamp != 0
    assert test_db.is_file()
    main([])

def test_main_03(tmp_path):
    """test main() --dump"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.duration = 0.0
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.rate = 0.1
    status.results = 0
    status.report()
    assert test_db.is_file()
    dump_file = tmp_path / "output.txt"
    main(["--dump", str(dump_file)])
    assert dump_file.is_file()
