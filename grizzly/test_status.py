# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status reports"""
# pylint: disable=protected-access

import re

from .status import Status, StatusReporter, TracebackReport

def test_status_01(tmp_path):
    """test Status report()"""
    status = Status()
    # fake loading report from file and try to report
    report = tmp_path / "report.json"
    status.report_path = str(report)
    status._start_time = None
    status.report()
    assert not report.is_file(), "overwrote file the data was loaded from"
    # normal operation
    status._start_time = 0
    status.report()
    assert report.is_file()
    # write report when a previous report exists (update)
    status._last_report = 0
    status.report()
    assert report.is_file()
    report.unlink()
    # verify report has not been written because report_freq has not elapsed
    status.report(report_freq=100)
    assert not report.is_file()

def test_status_02(tmp_path):
    """test Status cleanup()"""
    report = tmp_path / "report.json"
    status = Status(str(report))
    status.report()
    assert report.is_file()
    status.cleanup()
    assert not report.is_file()
    # nothing to cleanup
    status.cleanup()

def test_status_03(tmp_path):
    """test Status load()"""
    # load missing file
    assert Status.load("no_file.json") is None
    # load empty file
    report = tmp_path / "report.json"
    report.touch()
    assert Status.load(str(report)) is None
    report.unlink()
    # create simple report
    status = Status(str(report))
    assert status is not None
    status.duration = 10.0
    status.ignored = 1
    status.iteration = 10
    status.log_size = 1
    status.results = 2
    status.report()
    assert report.is_file()
    # load simple report
    ld_status = Status.load(str(report))
    assert ld_status.date is not None
    assert ld_status.duration > 0
    assert ld_status.ignored == status.ignored
    assert ld_status.iteration == status.iteration
    assert ld_status.log_size == status.log_size
    assert ld_status.rate > 0
    assert ld_status.results == status.results
    ld_status.cleanup()
    assert not report.is_file()

def test_status_reporter_01(tmp_path):
    """test basic StatusReporter"""
    st_rpt = StatusReporter()
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
    """test StatusReporter.load_reports()"""
    st_rpt = StatusReporter()
    st_rpt.load_reports("no_dir", tracebacks=True)
    assert st_rpt.reports is None
    assert st_rpt.tracebacks is None
    st_rpt.load_reports(str(tmp_path), tracebacks=True)
    assert isinstance(st_rpt.reports, list)
    assert isinstance(st_rpt.tracebacks, list)

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
    report = tmp_path / "grz_status_1.json"
    report.write_bytes(b"""{
        "Duration": 0.0,
        "Ignored": 0,
        "Iteration": 1,
        "Logsize": 0,
        "Rate": 0.1,
        "Results": 0}""")
    rptr = StatusReporter()
    assert rptr.reports is None
    rptr.load_reports(str(tmp_path))
    assert rptr.reports is not None
    output = rptr._summary(runtime=False)
    lines = output.split("\n")
    assert lines
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "ignored" not in output
    assert "Logs" not in output
    assert "Runtime" not in output
    assert "Timestamp" not in output
    report = tmp_path / "grz_status_9999.json"
    report.write_bytes(b"""{
        "Duration": 66.0,
        "Ignored": 1,
        "Iteration": 8,
        "Logsize": 86900000,
        "Rate": 0.121,
        "Results": 0}""")
    rptr.load_reports(str(tmp_path))
    assert len(rptr.reports) == 2
    output = rptr._summary(sysinfo=True, timestamp=True)
    lines = output.split("\n")
    assert lines
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "ignored" in output
    assert "Logs" in output
    assert "Runtime" in output
    assert "Timestamp" in output
    # verify alignment
    position = len(lines[0].split(":")[0])
    for line in lines:
        assert line[position] == ":"

def test_status_reporter_06(tmp_path):
    """test StatusReporter._specific()"""
    StatusReporter.CPU_POLL_INTERVAL = 0.01
    report = tmp_path / "grz_status_123.json"
    report.write_bytes(b"""{
        "Duration": 0.0,
        "Ignored": 0,
        "Iteration": 1,
        "Logsize": 0,
        "Rate": 0.1,
        "Results": 0}""")
    rptr = StatusReporter()
    assert rptr.reports is None
    rptr.load_reports(str(tmp_path))
    assert rptr.reports is not None
    output = rptr._specific()
    lines = output.split("\n")[:-1]
    assert len(lines) == 2
    assert "Ignored" in output
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "EXPIRED" not in output
    report = tmp_path / "grz_status_213.json"
    report.write_bytes(b"""{
        "Duration": 1234,
        "Ignored": 0,
        "Iteration": 0,
        "Logsize": 0,
        "Rate": 0,
        "Results": 0}""")
    report = tmp_path / "grz_status_321.json"
    report.write_bytes(b"""{
        "Duration": 864123.2,
        "Ignored": 1,
        "Iteration": 432422,
        "Logsize": 86900000,
        "Rate": 1.1,
        "Results": 213}""")
    rptr.load_reports(str(tmp_path))
    assert len(rptr.reports) == 3
    # test expired reports
    for rpt in rptr.reports:
        if rpt.duration == 1234:
            rpt.date = 0
            break
    output = rptr._specific()
    lines = output.split("\n")[:-1]
    assert len(lines) == 5
    assert "Ignored" in output
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "EXPIRED" in output and "EXPIRED" in lines[-1]

def test_status_reporter_07(tmp_path):
    """test StatusReporter.load_reports() with traceback"""
    report = tmp_path / "grz_status_1.json"
    report.write_bytes(b"""{
        "Duration": 0.0,
        "Ignored": 0,
        "Iteration": 1,
        "Logsize": 0,
        "Rate": 0.1,
        "Results": 0}""")
    # create boring screenlog
    test_log = tmp_path / "screenlog.0"
    test_log.write_bytes(b"boring\ntest\n123\n")
    # create first screenlog
    test_log = tmp_path / "screenlog.1"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter()
    assert rptr.tracebacks is None
    rptr.load_reports(str(tmp_path), tracebacks=True)
    assert len(rptr.tracebacks) == 1
    # create second screenlog
    test_log = tmp_path / "screenlog.1234"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"foo.bar.error: blah\n")
    rptr.load_reports(str(tmp_path), tracebacks=True)
    assert len(rptr.tracebacks) == 2
    # create third screenlog
    test_log = tmp_path / "screenlog.3"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"KeyboardInterrupt\n")
    rptr.load_reports(str(tmp_path), tracebacks=True)
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
