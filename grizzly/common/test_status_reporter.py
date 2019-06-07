# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status reporter"""
# pylint: disable=protected-access

import re

import pytest

from .status_reporter import main, ReduceStatus, ReduceStatusReporter
from .status_reporter import Status, StatusReporter, TracebackReport

def test_status_reporter_01(tmp_path):
    """test basic StatusReporter"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    st_rpt = StatusReporter(list())
    out = st_rpt._specific()
    assert "No status reports available" in out
    report = tmp_path / "output.txt"
    st_rpt.dump_specific(str(report))
    assert report.is_file()
    st_rpt.print_specific()
    out = st_rpt._summary()
    assert "No status reports available" in out
    report.unlink()
    st_rpt.dump_summary(str(report))
    assert report.is_file()
    st_rpt.print_summary()

def test_status_reporter_02(tmp_path):
    """test StatusReporter.load()"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    st_rpt = StatusReporter.load(str(test_db), tb_path="no_dir")
    assert isinstance(st_rpt.reports, list)
    assert isinstance(st_rpt.tracebacks, list)
    assert not st_rpt.reports
    assert not st_rpt.tracebacks
    st_rpt = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
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
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.results = 0
    status.report(force=True)
    rptr = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
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
    status.start_time += 66.0
    status.ignored = 1
    status.iteration = 8
    status.log_size = 86900000
    status.results = 0
    status.report(force=True)
    rptr = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
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
        assert re.match(r"\S\s:\s\S", line[position - 2:])

def test_status_reporter_06(tmp_path):
    """test StatusReporter._specific()"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.results = 0
    status.report(force=True)
    rptr = StatusReporter.load(str(test_db))
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
    status.ignored = 1
    status.iteration = 432422
    status.results = 123
    status.report(force=True)
    rptr = StatusReporter.load(str(test_db))
    assert len(rptr.reports) == 2
    output = rptr._specific()
    lines = output.split("\n")[:-1]
    assert len(lines) == 4
    assert "Ignored" in output
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output

def test_status_reporter_07(tmp_path):
    """test StatusReporter.load() with traceback"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.results = 0
    status.report(force=True)
    # create boring screenlog
    test_log = tmp_path / "screenlog.0"
    test_log.write_bytes(b"boring\ntest\n123\n")
    # create first screenlog
    test_log = tmp_path / "screenlog.1"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 1
    # create second screenlog
    test_log = tmp_path / "screenlog.1234"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"foo.bar.error: blah\n")
    rptr = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 2
    # create third screenlog
    test_log = tmp_path / "screenlog.3"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"KeyboardInterrupt\n")
    rptr = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 2
    merged_log = rptr._summary()
    assert len(merged_log.splitlines()) == 14
    assert "screenlog.1" in merged_log
    assert "screenlog.1234" in merged_log
    assert "IndexError" in merged_log
    assert "foo.bar.error" in merged_log
    assert "screenlog.3" not in merged_log

def test_status_reporter_08(tmp_path):
    """test StatusReporter.load() no reports with traceback"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    # create screenlog with tb
    test_log = tmp_path / "screenlog.1"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 1
    output = rptr._summary()
    assert len(output.splitlines()) == 7
    assert "No status reports available" in output
    assert "IndexError" in output

def test_status_reporter_09(tmp_path):
    """test StatusReporter.summary() limit with traceback"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    # create reports
    status = Status.start()
    status.ignored = 100
    status.iteration = 1000
    status.log_size = 9999999999
    status.results = 123
    status.report(force=True)
    status = Status.start()
    status.ignored = 9
    status.iteration = 192938
    status.log_size = 0
    status.results = 3
    status.report(force=True)
    # create screenlogs with tracebacks
    for i in range(10):
        test_log = tmp_path / ("screenlog.%d" % (i,))
        with test_log.open("wb") as test_fp:
            test_fp.write(b"Traceback (most recent call last):\n")
            for j in range(TracebackReport.MAX_LINES):
                test_fp.write(b"  File \"some/long/path/name/foobar.py\", line 5000, in <module>\n")
                test_fp.write(b"    some_long_name_for_a_func_%04d()\n" % (j,))
            test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(str(test_db), tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 10
    merged_log = rptr._summary(runtime=True, sysinfo=True, timestamp=True)
    assert len(merged_log) < StatusReporter.SUMMARY_LIMIT

def test_reduce_status_reporter_01(tmp_path):
    """test empty ReduceStatusReporter"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    rptr = ReduceStatusReporter.load(str(test_db))
    assert not rptr.reports
    output = rptr._specific()
    assert "No status reports available" in output
    output = rptr._summary()
    assert "No status reports available" in output

def test_reduce_status_reporter_02(tmp_path):
    """test ReduceStatusReporter._specific()"""
    ReduceStatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = ReduceStatus.start()
    status.iteration = 1
    status.report(force=True)
    rptr = ReduceStatusReporter.load(str(test_db))
    assert rptr.reports is not None
    output = rptr._specific()
    lines = output.split("\n")[:-1]
    assert len(lines) == 2
    assert "Iteration" in output
    assert "Rate" in output
    status = ReduceStatus.start()
    status.ignored = 12
    status.iteration = 432422
    status.results = 123
    status.report(force=True)
    rptr = ReduceStatusReporter.load(str(test_db))
    assert len(rptr.reports) == 2
    output = rptr._specific()
    lines = output.split("\n")[:-1]
    assert len(lines) == 4
    assert "Iteration" in output
    assert "Rate" in output

def test_reduce_status_reporter_03(tmp_path):
    """test ReduceStatusReporter._summary()"""
    ReduceStatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = ReduceStatus.start()
    status.iteration = 1
    status.report(force=True)
    rptr = ReduceStatusReporter.load(str(test_db))
    assert rptr.reports is not None
    assert len(rptr.reports) == 1
    output = rptr._summary(runtime=False)
    assert "Processed" in output
    assert "Active" in output
    assert "Iteration" in output
    assert "Mismatch" in output
    assert "Rate" in output
    assert "Runtime" in output
    assert "ignored" not in output
    assert "Timestamp" not in output
    assert len(output.split("\n")) == 9
    status = ReduceStatus.start()
    status.reduce_error = 1
    status.reduce_fail = 2
    status.reduce_pass = 10
    status.ignored = 4
    status.iteration = 13
    status.results = 3
    status.report(force=True)
    rptr = ReduceStatusReporter.load(str(test_db))
    assert len(rptr.reports) == 2
    output = rptr._summary(sysinfo=True, timestamp=True)
    assert "Processed" in output
    assert "Reduced" in output
    assert "No Repro" in output
    assert "Error" in output
    assert "Iteration" in output
    assert "Rate" in output
    assert "Mismatch" in output
    assert "ignored" in output
    assert "Runtime" in output
    assert "Timestamp" in output
    lines = output.split("\n")
    assert len(lines) == 13
    # verify alignment
    position = len(lines[1].split(":")[0])
    for line in lines:
        if line.startswith("-"):
            continue
        assert re.match(r"\S\s:\s\S", line[position - 2:])

def test_reduce_status_reporter_04(tmp_path):
    """test ReduceStatusReporter._summary() ignore inactive"""
    ReduceStatusReporter.CPU_POLL_INTERVAL = 0.01
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = ReduceStatus.start()
    status.reduce_error = 1
    status.reduce_fail = 2
    status.reduce_pass = 10
    status.report(force=True)
    rptr = ReduceStatusReporter.load(str(test_db))
    assert rptr.reports is not None
    assert len(rptr.reports) == 1
    output = rptr._summary(sysinfo=True, timestamp=True)
    assert "Processed" in output
    assert "Reduced" in output
    assert "No Repro" in output
    assert "Error" in output
    assert "Timestamp" in output
    assert "Active" not in output
    assert "Iteration" not in output
    assert "Mismatch" not in output
    assert "Rate" not in output
    assert "Runtime" not in output
    assert "ignored" not in output
    lines = output.split("\n")
    assert len(lines) == 8
    # verify alignment
    position = len(lines[1].split(":")[0])
    for line in lines:
        if line.startswith("-"):
            continue
        assert re.match(r"\S\s:\s\S", line[position - 2:])

def test_traceback_report_01():
    """test simple TracebackReport"""
    tbr = TracebackReport("log.txt", ["0", "1", "2"], prev_lines=["-2", "-1"])
    output = str(tbr)
    assert len(output.splitlines()) == 6
    assert len(tbr) == 26
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
        test_fp.write(b"  File \"foo.py\", line 5, in <module>\n")
        test_fp.write(b"    first()\n")
        test_fp.write(b"  File \"foo.py\", line 5, in <module>\n")
        test_fp.write(b"    second()\n")
        for i in reversed(range(TracebackReport.MAX_LINES)):
            test_fp.write(b"  File \"foo.py\", line 5, in <module>\n")
            test_fp.write(b"    func_%02d()\n" % i)
        test_fp.write(b"END_WITH_BLANK_LINE\n\n")
        test_fp.write(b"end junk\n")
    tbr = TracebackReport.from_file(str(test_log))
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 18
    assert "<--- TRACEBACK TRIMMED--->" in output
    assert "first()" in output
    assert "func_05()" in output
    assert "second()" not in output
    assert "func_06()" not in output
    assert "END_WITH_BLANK_LINE" in output

def test_traceback_report_05(tmp_path):
    """test TracebackReport.from_file() cut off"""
    test_log = tmp_path / "screenlog.0"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  File \"foo.py\", line 5, in <module>\n")
        test_fp.write(b"    first()\n")
        for i in range(TracebackReport.MAX_LINES * 2):
            test_fp.write(b"  File \"foo.py\", line 5, in <module>\n")
            test_fp.write(b"    func_%d()\n" % i)
    tbr = TracebackReport.from_file(str(test_log))
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 18
    assert "first()" in output
    assert "func_%d" % (TracebackReport.MAX_LINES * 2 - 1) in output

def test_traceback_report_06(tmp_path):
    """test TracebackReport.from_file() single word error"""
    test_log = tmp_path / "screenlog.0"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  File \"foo.py\", line 5, in <module>\n")
        test_fp.write(b"    first()\n")
        test_fp.write(b"AssertionError\n")
        test_fp.write(b"end junk\n")
    tbr = TracebackReport.from_file(str(test_log))
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 5
    assert "first()" in output
    assert "AssertionError" in output
    assert "end junk" not in output

def test_main_01(tmp_path):
    """test main() with no reports"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    main([])
    assert test_db.is_file()

def test_main_02(tmp_path):
    """test main() with a report"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.iteration = 1
    status.report(force=True)
    assert test_db.is_file()
    main([])

def test_main_03(tmp_path):
    """test main() --dump"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = Status.start()
    status.iteration = 1
    status.report(force=True)
    assert test_db.is_file()
    dump_file = tmp_path / "output.txt"
    main(["--dump", str(dump_file)])
    assert dump_file.is_file()

def test_main_04(tmp_path):
    """test main() with --mode reduce-status"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    status = ReduceStatus.start()
    status.iteration = 1
    status.report(force=True)
    assert test_db.is_file()
    main(["--mode", "reduce-status"])

def test_main_05(tmp_path):
    """test main() with invalid mode"""
    test_db = tmp_path / "test.db"
    Status.DB_FILE = str(test_db)
    with pytest.raises(SystemExit):
        main(["--mode", "invalid"])
