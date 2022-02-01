# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly status reporter"""
# pylint: disable=protected-access

from itertools import count
from re import match
from unittest.mock import Mock

from pytest import mark, raises

from .status_reporter import (
    ReductionStatus,
    ReductionStatusReporter,
    Status,
    StatusReporter,
    TracebackReport,
    main,
)

GBYTES = 1_073_741_824


def _fake_sys_info():
    return [
        ("CPU & Load", "64 @ 93% (85.25, 76.21, 51.06)"),
        ("Memory", "183.9GB of 251.9GB free"),
        ("Disk", "22.2GB of 28.7GB free"),
    ]


def test_reduce_status_reporter_01():
    """test basic ReductionStatusReporter"""
    st_rpt = ReductionStatusReporter(None)
    assert not st_rpt.has_results
    st_rpt._sys_info = _fake_sys_info
    assert "No status reports available" in st_rpt.specific()
    assert "No status reports available" in st_rpt.summary()


def test_reduce_status_reporter_02(mocker, tmp_path):
    """test ReductionStatusReporter.load()"""
    # missing reports path
    st_rpt = ReductionStatusReporter.load(str(tmp_path / "status.db"))
    assert not st_rpt.reports

    # empty reports and tb paths
    st_rpt = ReductionStatusReporter.load(
        str(tmp_path / "status.db"), tb_path=str(tmp_path)
    )
    assert not st_rpt.reports
    assert isinstance(st_rpt.tracebacks, list)
    assert not st_rpt.tracebacks

    # multiple reports
    size_cb = mocker.Mock(side_effect=count(start=1000, step=-100))
    db_file = str(tmp_path / "status.db")
    ReductionStatus.start(
        db_file=db_file,
        testcase_size_cb=size_cb,
    )
    status2 = ReductionStatus(
        db_file=db_file,
        pid=1,
        testcase_size_cb=size_cb,
    )
    status2.report(force=True)
    st_rpt = ReductionStatusReporter.load(db_file)
    assert len(st_rpt.reports) > 1


def test_reduce_status_reporter_03(mocker, tmp_path):
    """test ReductionStatusReporter.summary()"""
    mocker.patch("grizzly.common.status.getpid", side_effect=(1, 2))
    mocker.patch("grizzly.common.status.time", side_effect=count(start=1.0, step=1.0))
    size_cb = mocker.Mock(side_effect=count(start=1000, step=-100))
    db_file = str(tmp_path / "status.db")
    # single report
    status = ReductionStatus.start(
        db_file=db_file,
        testcase_size_cb=size_cb,
        crash_id=123,
        tool="fuzzmatic",
    )
    status.analysis["ran"] = True
    status.run_params["speed"] = 123.0
    status.signature_info["info"] = "crash"
    status.last_reports.append(45678)
    status.record("init")
    with status.measure("total"):
        with status.measure("strategy_0"):
            status.attempts += 1
            status.successes += 1
            status.iterations += 1
        with status.measure("strategy_1"):
            status.attempts += 3
            status.successes += 1
            status.iterations += 3
    status.report(force=True)

    rptr = ReductionStatusReporter.load(db_file)
    rptr._sys_info = _fake_sys_info
    assert rptr.reports
    output = rptr.summary(sysinfo=True, timestamp=True)
    assert "duration" in output
    assert "successes" in output
    assert "attempts" in output
    assert "init" in output
    assert "strategy_0" in output
    assert "strategy_1" in output
    assert "total" in output
    assert "Timestamp" in output
    assert len(output.splitlines()) == 16


def test_reduce_status_reporter_04(mocker, tmp_path):
    """test ReductionStatusReporter.specific()"""
    mocker.patch("grizzly.common.status.getpid", side_effect=(1, 2))
    db_file = str(tmp_path / "status.db")
    # single report
    status = ReductionStatus.start(
        db_file=db_file,
        strategies=["strategy_0"],
        testcase_size_cb=lambda: 47,
        crash_id=12,
        tool="fuzzmatic",
    )
    assert status.original is None
    rptr = ReductionStatusReporter.load(db_file)
    assert rptr.reports
    output = rptr.specific()
    assert len(output.splitlines()) == 1
    status.analysis["ran"] = True
    status.run_params["splines"] = "reticulated"
    status.last_reports.append(45678)
    status.record("init")
    with status.measure("total"):
        with status.measure("strategy_0"):
            status.iterations = 1
            status.attempts = 1
            status.successes = 1
    status.report(force=True)
    rptr = ReductionStatusReporter.load(db_file)
    assert rptr.reports
    output = rptr.specific()
    assert len(output.splitlines()) == 8
    assert "Analysis" in output
    assert "Run Parameters" in output
    assert "Current Strategy" in output
    assert "Current/Original" in output
    assert "Results" in output
    assert "Time Elapsed" in output


def test_reduce_status_reporter_05(tmp_path):
    """test ReductionStatusReporter.load() with traceback"""
    db_file = str(tmp_path / "status.db")
    status = ReductionStatus.start(
        db_file=db_file,
        testcase_size_cb=lambda: 47,
    )
    with status.measure("total"):
        status.iteration = 1
    status.report(force=True)
    # create boring screenlog
    (tmp_path / "screenlog.0").write_bytes(b"boring\ntest\n123\n")
    # create first screenlog
    with (tmp_path / "screenlog.1").open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(db_file, tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 1
    # create second screenlog
    with (tmp_path / "screenlog.1234").open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"foo.bar.error: blah\n")
    rptr = StatusReporter.load(db_file, tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 2
    # create third screenlog
    with (tmp_path / "screenlog.3").open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"KeyboardInterrupt\n")
    rptr = ReductionStatusReporter.load(db_file, tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 2
    merged_log = rptr.summary()
    assert len(merged_log.splitlines()) == 13
    assert "screenlog.1" in merged_log
    assert "screenlog.1234" in merged_log
    assert "IndexError" in merged_log
    assert "foo.bar.error" in merged_log
    assert "screenlog.3" not in merged_log


def test_status_reporter_01():
    """test basic StatusReporter"""
    st_rpt = StatusReporter(list())
    assert not st_rpt.has_results
    st_rpt._sys_info = _fake_sys_info
    assert "No status reports available" in st_rpt.specific()
    assert "No status reports available" in st_rpt.summary()


def test_status_reporter_02(tmp_path):
    """test StatusReporter.load()"""
    # missing reports path
    st_rpt = StatusReporter.load(str(tmp_path / "status.db"))
    assert not st_rpt.reports
    # empty reports and tb paths
    st_rpt = StatusReporter.load(str(tmp_path / "status.db"), tb_path=str(tmp_path))
    assert isinstance(st_rpt.reports, list)
    assert not st_rpt.reports
    assert isinstance(st_rpt.tracebacks, list)
    assert not st_rpt.tracebacks


@mark.parametrize(
    "disk, memory, getloadavg",
    [
        (Mock(free=12, total=GBYTES), Mock(available=12, total=GBYTES), None),
        (
            Mock(free=10.23 * GBYTES, total=100 * GBYTES),
            Mock(available=1.1 * GBYTES, total=2 * GBYTES),
            None,
        ),
        (
            Mock(free=12, total=GBYTES),
            Mock(available=12, total=GBYTES),
            lambda: (0.12, 0.34, 0.56),
        ),
    ],
)
def test_status_reporter_03(mocker, disk, memory, getloadavg):
    """test StatusReporter._sys_info()"""
    mocker.patch(
        "grizzly.common.status_reporter.cpu_count", autospec=True, return_value=4
    )
    mocker.patch(
        "grizzly.common.status_reporter.cpu_percent", autospec=True, return_value=10
    )
    mocker.patch(
        "grizzly.common.status_reporter.disk_usage", autospec=True, return_value=disk
    )
    mocker.patch(
        "grizzly.common.status_reporter.virtual_memory",
        autospec=True,
        return_value=memory,
    )
    if getloadavg is None:
        # simulate platform that does not have os.getloadavg()
        mocker.patch("grizzly.common.status_reporter.getloadavg", None)
    else:
        mocker.patch(
            "grizzly.common.status_reporter.getloadavg", side_effect=getloadavg
        )
    sysinfo = StatusReporter._sys_info()
    assert len(sysinfo) == 3
    assert sysinfo[0][0] == "CPU & Load"
    assert sysinfo[1][0] == "Memory"
    assert sysinfo[2][0] == "Disk"
    if getloadavg is not None:
        assert sysinfo[0][-1].endswith(" (0.1, 0.3, 0.6)")
    if disk.free < GBYTES or memory.available < GBYTES:
        assert "MB" in sysinfo[1][-1]
        assert "MB" in sysinfo[2][-1]
    else:
        assert "MB" not in sysinfo[1][-1]
        assert "MB" not in sysinfo[2][-1]


def test_status_reporter_04(tmp_path):
    """test StatusReporter._scan()"""
    (tmp_path / "somefile.txt").touch()
    test_path = tmp_path / "TEST_FILE"
    test_path.mkdir()
    assert not any(StatusReporter._scan(str(tmp_path), "TEST_FILE"))
    test_path.rmdir()
    test_path.touch()
    assert not any(StatusReporter._scan(str(tmp_path), "TEST_FILE"))
    test_path.write_bytes(b"test")
    assert any(StatusReporter._scan(str(tmp_path), "TEST_FILE"))


def test_status_reporter_05(mocker, tmp_path):
    """test StatusReporter.summary()"""
    mocker.patch("grizzly.common.status.getpid", side_effect=(1, 2))
    mocker.patch("grizzly.common.status.time", side_effect=count(start=1.0, step=1.0))
    db_file = str(tmp_path / "status.db")
    # single report
    status = Status.start(db_file=db_file)
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.report(force=True)
    rptr = StatusReporter.load(db_file)
    rptr._sys_info = _fake_sys_info
    assert rptr.reports is not None
    assert len(rptr.reports) == 1
    output = rptr.summary(runtime=False)
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "Blockers" not in output
    assert "Ignored" not in output
    assert "Logs" not in output
    assert "Runtime" not in output
    assert "Timestamp" not in output
    assert len(output.split("\n")) == 3
    # multiple reports
    status = Status.start(db_file=db_file)
    status.ignored = 1
    status.iteration = 8
    status.log_size = 86900000
    status.results.count("test", "test")
    status.results.count("test", "test")
    status.report(force=True)
    rptr = StatusReporter.load(db_file)
    rptr._sys_info = _fake_sys_info
    assert len(rptr.reports) == 2
    output = rptr.summary(sysinfo=True, timestamp=True)
    assert "Iteration" in output
    assert "Rate" in output
    assert "Results" in output
    assert "Ignored" in output
    assert "Logs" in output
    assert "Runtime" in output
    assert "Timestamp" in output
    lines = output.split("\n")
    assert len(lines) == 10
    # verify alignment
    position = len(lines[0].split(":")[0])
    for line in lines:
        assert match(r"\S\s:\s\S", line[position - 2 :])


def test_status_reporter_06(mocker, tmp_path):
    """test StatusReporter.specific()"""
    mocker.patch("grizzly.common.status.getpid", side_effect=(1, 2))
    db_file = str(tmp_path / "status.db")
    # single report
    status = Status.start(db_file=db_file)
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.report(force=True)
    rptr = StatusReporter.load(db_file)
    assert rptr.reports is not None
    output = rptr.specific()
    assert len(output.strip().split("\n")) == 4
    assert "Ignored" not in output
    assert "Iterations" in output
    assert "Results" in output
    assert "(Blockers detected)" not in output
    assert "Runtime" in output
    # multiple reports
    status = Status.start(db_file=db_file, enable_profiling=True)
    status.ignored = 1
    status.iteration = 50
    status.results.count("uid1", "sig1")
    status.results.count("uid1", "sig1")
    status.results.count("uid1", "sig1")
    status.record("test1", 0.91)
    status.record("test1", 1.0)
    status.record("test1", 1.23456)
    status.record("test2", 1201.1)
    status.report(force=True)
    rptr = StatusReporter.load(db_file)
    assert len(rptr.reports) == 2
    output = rptr.specific()
    assert len(output.strip().split("\n")) == 13
    assert "Ignored" in output
    assert "Iterations" in output
    assert "Results" in output
    assert "Runtime" in output
    assert "(Blockers detected)" in output
    assert "Profiling entries" in output
    assert "test1" in output
    assert "test2" in output


def test_status_reporter_07(mocker, tmp_path):
    """test StatusReporter.results()"""
    mocker.patch("grizzly.common.status.getpid", side_effect=(1, 2, 3))
    db_file = str(tmp_path / "status.db")
    # single report without results
    status = Status.start(db_file=db_file)
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.report(force=True)
    rptr = StatusReporter.load(db_file)
    assert rptr.reports is not None
    assert len(rptr.reports) == 1
    assert not rptr.has_results
    assert rptr.results() == "No results available\n"
    # multiple reports with results
    status = Status.start(db_file=db_file)
    status.iteration = 1
    status.results.count("uid1", "[@ test1]")
    status.results.count("uid2", "[@ test2]")
    status.results.count("uid1", "[@ test1]")
    status.report(force=True)
    status = Status.start(db_file=db_file)
    status.iteration = 1
    status.results.count("uid1", "[@ test1]")
    status.results.count("uid3", "[@ longsignature123]")
    status.report(force=True)
    rptr = StatusReporter.load(db_file)
    assert rptr.has_results
    assert len(rptr.reports) == 3
    output = rptr.results(max_len=19)
    assert "3 : [@ test1]" in output
    assert "1 : [@ test2]" in output
    assert "1 : [@ longsignature..." in output
    assert "(* = Blocker)" in output
    assert len(output.strip().split("\n")) == 4


def test_status_reporter_08(tmp_path):
    """test StatusReporter.load() with traceback"""
    db_file = str(tmp_path / "status.db")
    status = Status.start(db_file=db_file)
    status.ignored = 0
    status.iteration = 1
    status.log_size = 0
    status.report(force=True)
    # create boring screenlog
    (tmp_path / "screenlog.0").write_bytes(b"boring\ntest\n123\n")
    # create first screenlog
    with (tmp_path / "screenlog.1").open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(db_file, tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 1
    # create second screenlog
    with (tmp_path / "screenlog.1234").open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"foo.bar.error: blah\n")
    rptr = StatusReporter.load(db_file, tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 2
    # create third screenlog
    with (tmp_path / "screenlog.3").open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"KeyboardInterrupt\n")
    rptr = StatusReporter.load(db_file, tb_path=str(tmp_path))
    assert len(rptr.tracebacks) == 2
    merged_log = rptr.summary()
    assert len(merged_log.splitlines()) == 14
    assert "screenlog.1" in merged_log
    assert "screenlog.1234" in merged_log
    assert "IndexError" in merged_log
    assert "foo.bar.error" in merged_log
    assert "screenlog.3" not in merged_log


def test_status_reporter_09(tmp_path):
    """test StatusReporter.load() no reports with traceback"""
    # create screenlog with tb
    with (tmp_path / "screenlog.1").open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b"  blah\n")
        test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(str(tmp_path / "status.db"), tb_path=str(tmp_path))
    rptr._sys_info = _fake_sys_info
    assert len(rptr.tracebacks) == 1
    output = rptr.summary()
    assert len(output.splitlines()) == 7
    assert "No status reports available" in output
    assert "IndexError" in output


def test_status_reporter_10(mocker, tmp_path):
    """test StatusReporter.summary() limit with traceback"""
    mocker.patch("grizzly.common.status.getpid", side_effect=(1, 2))
    db_file = str(tmp_path / "status.db")
    # create reports
    status = Status.start(db_file=db_file)
    status.ignored = 100
    status.iteration = 1000
    status.log_size = 9999999999
    status.results.count("uid1", "[@ sig1]")
    status.results._count["uid1"] = 123
    status.report(force=True)
    status = Status.start(db_file=db_file)
    status.ignored = 9
    status.iteration = 192938
    status.log_size = 0
    status.results.count("uid2", "[@ sig2]")
    status.results._count["uid2"] = 3
    status.report(force=True)
    # create screenlogs with tracebacks
    for i in range(10):
        with (tmp_path / ("screenlog.%d" % (i,))).open("wb") as test_fp:
            test_fp.write(b"Traceback (most recent call last):\n")
            for j in range(TracebackReport.MAX_LINES):
                test_fp.write(
                    b'  File "some/long/path/name/foobar.py", line 5000, in <module>\n'
                )
                test_fp.write(b"    some_long_name_for_a_func_%04d()\n" % (j,))
            test_fp.write(b"IndexError: list index out of range\n")
    rptr = StatusReporter.load(db_file, tb_path=str(tmp_path))
    rptr._sys_info = _fake_sys_info
    assert len(rptr.tracebacks) == 10
    merged_log = rptr.summary(
        runtime=True, sysinfo=True, timestamp=True, iters_per_result=1
    )
    assert len(merged_log) < StatusReporter.SUMMARY_LIMIT


def test_status_reporter_11():
    """test StatusReporter.format_entries()"""
    assert StatusReporter.format_entries([]) == ""
    assert StatusReporter.format_entries([("test", None)]) == "test"
    assert StatusReporter.format_entries([("test", "1")]) == "test : 1"
    out = StatusReporter.format_entries(
        [("first", "1"), ("second", "2"), ("third", "3")]
    )
    assert out == " first : 1\nsecond : 2\n third : 3"


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
        test_fp.write(b'  File "foo.py", line 556, in <module>\n')
        test_fp.write(b"    main(parse_args())\n")
        test_fp.write(b'  File "foo.py", line 207, in bar\n')
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
        test_fp.write(b'  File "foo.py", line 556, in <module>\n')
        test_fp.write(b"    main(parse_args())\n")
        test_fp.write(b'  File "foo.py", line 207, in bar\n')
        test_fp.write(b"    a = b[10]\n")
        test_fp.write(b"foo.bar.error: blah\n")
        test_fp.write(b"end junk\n")
    tbr = TracebackReport.from_file(str(test_log), max_preceding=0)
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
        test_fp.write(b'  File "foo.py", line 556, in <module>\n')
        test_fp.write(b"    main(parse_args())\n")
        test_fp.write(b'  File "foo.py", line 207, in bar\n')
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
        test_fp.write(b'  File "foo.py", line 5, in <module>\n')
        test_fp.write(b"    first()\n")
        test_fp.write(b'  File "foo.py", line 5, in <module>\n')
        test_fp.write(b"    second()\n")
        for i in reversed(range(TracebackReport.MAX_LINES)):
            test_fp.write(b'  File "foo.py", line 5, in <module>\n')
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
        test_fp.write(b'  File "foo.py", line 5, in <module>\n')
        test_fp.write(b"    first()\n")
        for i in range(TracebackReport.MAX_LINES * 2):
            test_fp.write(b'  File "foo.py", line 5, in <module>\n')
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
        test_fp.write(b'  File "foo.py", line 5, in <module>\n')
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


def test_traceback_report_07(tmp_path):
    """test TracebackReport.from_file() with binary data"""
    test_log = tmp_path / "screenlog.0"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b'  File "foo.py", line 5, in <module>\n')
        test_fp.write(b"    bin\xd8()\n")
        test_fp.write(b"AssertionError\n")
    tbr = TracebackReport.from_file(str(test_log))
    assert not tbr.is_kbi
    output = str(tbr)
    assert "bin()" in output
    assert "AssertionError" in output


def test_traceback_report_08(tmp_path):
    """test TracebackReport.from_file() locate token across chunks"""
    test_log = tmp_path / "screenlog.0"
    with test_log.open("wb") as test_fp:
        test_fp.write(b"A" * (TracebackReport.READ_LIMIT - 5))
        test_fp.write(b"Traceback (most recent call last):\n")
        test_fp.write(b'  File "foo.py", line 5, in <module>\n')
        test_fp.write(b"    first()\n")
        test_fp.write(b"AssertionError\n")
    tbr = TracebackReport.from_file(str(test_log))
    assert not tbr.is_kbi
    output = str(tbr)
    assert len(output.splitlines()) == 5
    assert "first()" in output
    assert "AssertionError" in output


@mark.usefixtures("tmp_path_status_db")
def test_main_01(mocker):
    """test main() with no reports"""
    mocker.patch(
        "grizzly.common.status_reporter.StatusReporter.CPU_POLL_INTERVAL", 0.01
    )
    assert main([]) == 0


@mark.usefixtures("tmp_path_status_db")
def test_main_02(mocker):
    """test main() with a report"""
    mocker.patch(
        "grizzly.common.status_reporter.StatusReporter.CPU_POLL_INTERVAL", 0.01
    )
    status = Status.start()
    status.iteration = 1
    status.results.count("uid", "[@ test]")
    status.report(force=True)
    assert main([]) == 0


@mark.parametrize(
    "report_mode",
    [
        "fuzzing",
        "reducing",
    ],
)
@mark.parametrize(
    "report_type",
    [
        "active",
        "complete",
    ],
)
@mark.usefixtures("tmp_path_status_db", "tmp_path_reduce_status_db")
def test_main_03(mocker, tmp_path, report_type, report_mode):
    """test main() --dump"""
    mocker.patch(
        "grizzly.common.status_reporter.StatusReporter.CPU_POLL_INTERVAL", 0.01
    )
    if report_mode == "reducing":
        status = ReductionStatus.start(
            testcase_size_cb=lambda: 47,
            strategies=[],
        )
        with status.measure("total"):
            status.iteration = 1
        status.report(force=True)
    else:
        status = Status.start()
        status.iteration = 1
        status.report(force=True)
    dump_file = tmp_path / "output.txt"
    assert (
        main(
            [
                "--dump",
                str(dump_file),
                "--type",
                report_type,
                "--scan-mode",
                report_mode,
            ]
        )
        == 0
    )
    assert dump_file.is_file()
    if report_type == "active":
        assert b"Runtime" not in dump_file.read_bytes()
    else:
        assert b"Timestamp" not in dump_file.read_bytes()


@mark.usefixtures("tmp_path_status_db")
def test_main_04(capsys):
    """test main() with invalid args"""
    with raises(SystemExit):
        main(["--tracebacks", "missing"])
    assert "--tracebacks must be a directory" in capsys.readouterr()[-1]


@mark.parametrize(
    "report_type",
    [
        "active",
        "complete",
    ],
)
@mark.usefixtures("tmp_path_reduce_status_db")
def test_main_05(mocker, tmp_path, report_type):
    """test main() --dump"""
    mocker.patch(
        "grizzly.common.status_reporter.StatusReporter.CPU_POLL_INTERVAL", 0.01
    )
    status = ReductionStatus.start(
        testcase_size_cb=lambda: 47,
        strategies=[],
    )
    with status.measure("total"):
        status.iteration = 1
        status.report(force=True)
    dump_file = tmp_path / "output.txt"
    assert (
        main(
            [
                "--dump",
                str(dump_file),
                "--type",
                report_type,
                "--scan-mode",
                "reducing",
            ]
        )
        == 0
    )
    assert dump_file.is_file()
    if report_type == "active":
        assert b"Runtime" not in dump_file.read_bytes()
    else:
        assert b"Timestamp" not in dump_file.read_bytes()
