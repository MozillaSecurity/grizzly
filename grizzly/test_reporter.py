# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly Reporter"""

import glob
import os
import sys
import tarfile

import pytest

from .reporter import FilesystemReporter, FuzzManagerReporter, Report, Reporter, S3FuzzManagerReporter


def test_report_01():
    """test creating a simple Report"""
    report = Report("no_dir", dict())
    assert report.path == "no_dir"
    assert report.log_aux is None
    assert report.log_err is None
    assert report.log_out is None
    assert report.stack is None
    assert report.preferred is None
    report.cleanup()

def test_report_02(tmp_path):
    """test from_path() with boring logs (no stack)"""
    log_err = tmp_path / "log_stderr.txt"
    log_err.write_bytes(b"STDERR log")
    log_out = tmp_path / "log_stdout.txt"
    log_out.write_bytes(b"STDOUT log")
    report = Report.from_path(str(tmp_path))
    assert report.path == str(tmp_path)
    assert report.log_err.endswith("log_stderr.txt")
    assert report.log_out.endswith("log_stdout.txt")
    assert report.preferred.endswith("log_stderr.txt")
    assert report.log_aux is None
    assert report.stack is None
    assert Report.DEFAULT_MAJOR == report.major
    assert Report.DEFAULT_MINOR == report.minor
    assert report.prefix is not None
    report.cleanup()
    assert not tmp_path.exists()

def test_report_03(tmp_path):
    """test from_path()"""
    log_err = tmp_path / "log_stderr.txt"
    log_err.write_bytes(b"STDERR log")
    log_out = tmp_path / "log_stdout.txt"
    log_out.write_bytes(b"STDOUT log")
    log_crash = tmp_path / "log_asan_blah.txt"
    with log_crash.open("wb") as log_fp:
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19")
    report = Report.from_path(str(tmp_path))
    assert report.path == str(tmp_path)
    assert report.log_aux.endswith("log_asan_blah.txt")
    assert report.log_err.endswith("log_stderr.txt")
    assert report.log_out.endswith("log_stdout.txt")
    assert report.preferred.endswith("log_asan_blah.txt")
    assert report.stack is not None
    assert Report.DEFAULT_MAJOR != report.major
    assert Report.DEFAULT_MINOR != report.minor
    assert report.prefix is not None
    report.cleanup()

def test_report_04(tmp_path):
    """test Report.tail()"""
    tmp_file = tmp_path / "file.txt"
    tmp_file.write_bytes(b"blah\ntest\n123\xEF\x00FOO")
    length = tmp_file.stat().st_size
    # no size limit
    with pytest.raises(AssertionError):
        Report.tail(str(tmp_file), 0)
    assert tmp_file.stat().st_size == length
    Report.tail(str(tmp_file), 3)
    with tmp_file.open("rb") as test_fp:
        log_data = test_fp.read()
    assert log_data.startswith(b"[LOG TAILED]\n")
    assert log_data[13:] == b"FOO"

def test_report_05(tmp_path):
    """test Report.select_logs()"""
    # small log with nothing interesting
    tmp_log = tmp_path / "log_asan.txt.1"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("SHORT LOG\n")
        log_fp.write("filler line")
    # crash on another thread
    tmp_log = tmp_path / "log_asan.txt.2"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("GOOD LOG\n")
        log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x00000BADF00D")
        log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write("    #%d blah...\n" % l_no)
    # child log that should be ignored (created when parent crashes)
    tmp_log = tmp_path / "log_asan.txt.3"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("BAD LOG\n")
        log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000")
        log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write("    #%d blah...\n" % l_no)
    tmp_log = tmp_path / "log_mindump_blah.txt"
    tmp_log.write_bytes(b"minidump log")
    tmp_log = tmp_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = tmp_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    # should be ignored in favor of "GOOD LOG"
    tmp_log = tmp_path / "log_ffp_worker_blah.txt"
    tmp_log.write_bytes(b"worker log")
    log_map = Report.select_logs(str(tmp_path))
    with open(os.path.join(str(tmp_path), log_map["aux"]), "r") as log_fp:
        assert "GOOD LOG" in log_fp.read()
    with open(os.path.join(str(tmp_path), log_map["stderr"]), "r") as log_fp:
        assert "STDERR" in log_fp.read()
    with open(os.path.join(str(tmp_path), log_map["stdout"]), "r") as log_fp:
        assert "STDOUT" in log_fp.read()

def test_report_06(tmp_path):
    """test minidump with Report.select_logs()"""
    tmp_log = tmp_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = tmp_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    tmp_log = tmp_path / "log_minidump_01.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|SIGSEGV|0x0|0\n")
        log_fp.write(b"minidump log\n")
    tmp_log = tmp_path / "log_ffp_worker_blah.txt"
    tmp_log.write_bytes(b"worker log")
    log_map = Report.select_logs(str(tmp_path))
    assert os.path.isfile(os.path.join(str(tmp_path), log_map["stderr"]))
    assert os.path.isfile(os.path.join(str(tmp_path), log_map["stdout"]))
    with open(os.path.join(str(tmp_path), log_map["aux"]), "r") as log_fp:
        assert "minidump log" in log_fp.read()

def test_report_07(tmp_path):
    """test selecting preferred DUMP_REQUESTED minidump with Report.select_logs()"""
    tmp_log = tmp_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = tmp_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    tmp_log = tmp_path / "log_minidump_01.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|DUMP_REQUESTED|0x7f9518665d18|0\n")
        log_fp.write(b"0|0|bar.so|sadf|a.cc:739484451a63|3066|0x0\n")
        log_fp.write(b"0|1|gar.so|fdsa|b.cc:739484451a63|1644|0x12\n")
    tmp_log = tmp_path / "log_minidump_02.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|DUMP_REQUESTED|0x7f57ac9e2e14|0\n")
        log_fp.write(b"0|0|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|bar.cc:234|674|0xc\n")
        log_fp.write(b"0|1|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|bar.cc:4a2|645|0x8\n")
    tmp_log = tmp_path / "log_minidump_03.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|DUMP_REQUESTED|0x7f9518665d18|0\n")
        log_fp.write(b"0|0|bar.so|sadf|a.cc:1234|3066|0x0\n")
        log_fp.write(b"0|1|gar.so|fdsa|b.cc:4323|1644|0x12\n")
    log_map = Report.select_logs(str(tmp_path))
    assert os.path.isfile(os.path.join(str(tmp_path), log_map["stderr"]))
    assert os.path.isfile(os.path.join(str(tmp_path), log_map["stdout"]))
    with open(os.path.join(str(tmp_path), log_map["aux"]), "r") as log_fp:
        assert "google_breakpad::ExceptionHandler::WriteMinidump" in log_fp.read()

def test_report_08(tmp_path):
    """test selecting worker logs with Report.select_logs()"""
    tmp_log = tmp_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = tmp_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    tmp_log = tmp_path / "log_ffp_worker_blah.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("worker log")
    log_map = Report.select_logs(str(tmp_path))
    assert os.path.isfile(os.path.join(str(tmp_path), log_map["stderr"]))
    assert os.path.isfile(os.path.join(str(tmp_path), log_map["stdout"]))
    with open(os.path.join(str(tmp_path), log_map["aux"]), "r") as log_fp:
        assert "worker log" in log_fp.read()

def test_report_09(tmp_path):
    """test prioritizing *San logs with Report.select_logs()"""
    # crash
    tmp_log = tmp_path / "log_asan.txt.1"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("GOOD LOG\n")
        log_fp.write("==1942==ERROR: AddressSanitizer: heap-use-after-free on ... blah\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write("    #%d blah...\n" % l_no)
    # crash missing trace
    tmp_log = tmp_path / "log_asan.txt.2"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("BAD LOG\n")
        log_fp.write("==1984==ERROR: AddressSanitizer: SEGV on ... blah\n")  # must be 2nd line
        log_fp.write("missing trace...\n")
    # child log that should be ignored (created when parent crashes)
    tmp_log = tmp_path / "log_asan.txt.3"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("BAD LOG\n")
        log_fp.write("==1184==ERROR: AddressSanitizer: BUS on ... blah\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write("    #%d blah...\n" % l_no)
    tmp_log = tmp_path / "log_asan.txt.4"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("BAD LOG\n")
        log_fp.write("==9482==ERROR: AddressSanitizer: stack-overflow on ...\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write("    #%d blah...\n" % l_no)
    tmp_log = tmp_path / "log_asan.txt.5"
    with tmp_log.open("wb") as log_fp:
        log_fp.write("BAD LOG\n")
        log_fp.write("ERROR: Failed to mmap\n")  # must be 2nd line
    log_map = Report.select_logs(str(tmp_path))
    with open(os.path.join(str(tmp_path), log_map["aux"]), "r") as log_fp:
        assert "GOOD LOG" in log_fp.read()

def test_report_10(tmp_path):
    "test size_limit"
    tmp_log = tmp_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log\n" * 200)
    tmp_log = tmp_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log\n" * 200)
    tmp_log = tmp_path / "unrelated.txt"
    tmp_log.write_bytes(b"nothing burger\n" * 200)
    os.mkdir(os.path.join(str(tmp_path), "rr-trace"))
    size_limit = len("STDERR log\n")
    report = Report.from_path(str(tmp_path), size_limit=size_limit)
    assert report.path == str(tmp_path)
    assert report.log_err.endswith("log_stderr.txt")
    assert report.log_out.endswith("log_stdout.txt")
    assert report.preferred.endswith("log_stderr.txt")
    assert report.log_aux is None
    assert report.stack is None
    size_limit += len("[LOG TAILED]\n")
    assert os.stat(os.path.join(report.path, report.log_err)).st_size == size_limit
    assert os.stat(os.path.join(report.path, report.log_out)).st_size == size_limit
    assert os.stat(os.path.join(report.path, "unrelated.txt")).st_size == size_limit
    report.cleanup()
    assert not os.path.isdir(str(tmp_path))

def test_reporter_01(tmp_path):
    """test creating a simple Reporter"""
    class SimpleReporter(Reporter):
        def _pre_submit(self, report):
            pass
        def _reset(self):
            pass
        def _submit(self, report, test_cases):
            pass
    reporter = SimpleReporter()
    with pytest.raises(IOError) as exc:
        reporter.submit("fake_dir", [])
    assert "No such directory 'fake_dir'" in str(exc)
    with pytest.raises(IOError) as exc:
        reporter.submit(str(tmp_path), [])
    assert "No logs found in" in str(exc)

def test_filesystem_reporter_01(tmp_path):
    """test FilesystemReporter without testcases"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    tmp_log = log_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = log_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    tmp_log = log_path / "log_asan_blah.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19")
    report_path = tmp_path / "reports"
    report_path.mkdir()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.submit(str(log_path), [])

def test_filesystem_reporter_02(tmp_path):
    """test FilesystemReporter with testcases"""
    class DummyTest(object):
        def __init__(self):
            self.dump_called = False
        def dump(self, *_a, **_kw):
            assert not self.dump_called
            self.dump_called = True
    log_path = tmp_path / "logs"
    log_path.mkdir()
    tmp_log = log_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = log_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    tmp_log = log_path / "log_asan_blah.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19")
    testcases = list()
    for _ in range(10):
        testcases.append(DummyTest())
    report_path = tmp_path / "reports"
    assert not report_path.exists()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.submit(str(log_path), testcases)
    assert not log_path.exists()
    assert report_path.exists()
    assert len(os.listdir(str(report_path))) == 1
    for tstc in testcases:
        assert tstc.dump_called
    # call report a 2nd time
    log_path = tmp_path / "logs"
    log_path.mkdir()
    tmp_log = log_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = log_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    testcases = list()
    for _ in range(2):
        testcases.append(DummyTest())
    reporter.submit(str(log_path), testcases)
    for tstc in testcases:
        assert tstc.dump_called
    results = os.listdir(str(report_path))
    assert len(results) == 2
    assert "NO_STACK" in results

def test_filesystem_reporter_03(tmp_path):
    """test FilesystemReporter disk space failsafe"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    tmp_log = log_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = log_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    report_path = tmp_path / "reports"
    report_path.mkdir()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.DISK_SPACE_ABORT = 2 ** 50
    with pytest.raises(RuntimeError) as exc:
        reporter.submit(str(log_path), [])
    assert "Running low on disk space" in str(exc)

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RR only supported on Linux")
def test_filesystem_reporter_04(tmp_path):
    """test packaging rr traces"""
    # create fake logs
    log_path = tmp_path / "logs"
    log_path.mkdir()
    tmp_log = log_path / "log_stderr.txt"
    tmp_log.write_bytes(b"STDERR log")
    tmp_log = log_path / "log_stdout.txt"
    tmp_log.write_bytes(b"STDOUT log")
    tmp_log = log_path / "log_asan_blah.txt"
    with tmp_log.open("wb") as log_fp:
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19")
    # create fake trace
    rr_trace_path = log_path / "rr-traces" / "echo-0"
    rr_trace_path.mkdir(parents=True)
    tr_file = rr_trace_path / "fail_file"
    tr_file.touch()
    rr_trace_path = log_path / "rr-traces" / "echo-1"
    rr_trace_path.mkdir()
    tr_file = rr_trace_path / "cloned_data_5799_1"
    tr_file.touch()
    tr_file = rr_trace_path / "data"
    tr_file.write_bytes(b"test_data")
    tr_file = rr_trace_path / "events"
    tr_file.write_bytes(b"foo")
    tr_file = rr_trace_path / "mmap"
    tr_file.write_bytes(b"bar")
    tr_file = rr_trace_path / "tasks"
    tr_file.write_bytes(b"foo")
    tr_file = rr_trace_path / "version"
    tr_file.write_bytes(b"123")
    latest_path = log_path / "rr-traces" / "latest-trace"
    latest_path.symlink_to(str(rr_trace_path), target_is_directory=True)
    report_path = tmp_path / "reports"
    # report
    assert not report_path.exists()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.submit(str(log_path), [])
    assert report_path.exists()
    # verify report and archive
    report_log_dirs = glob.glob(str(report_path) + "/*/*_logs/")
    assert len(report_log_dirs) == 1
    report_log_dir = report_log_dirs[0]
    report_contents = os.listdir(report_log_dir)
    assert "rr.tar.bz2" in report_contents
    assert "rr-traces" not in report_contents
    arc_file = os.path.join(report_log_dir, "rr.tar.bz2")
    assert os.path.isfile(arc_file)
    with tarfile.open(arc_file, "r:bz2") as arc_fp:
        entries = arc_fp.getnames()
    assert "echo-1" in entries
    assert "echo-0" not in entries
    assert "latest-trace" not in entries

def test_fuzzmanager_reporter_01(tmp_path, mocker):
    """test FuzzManagerReporter.sanity_check()"""
    mocker.patch("grizzly.reporter.ProgramConfiguration")
    FuzzManagerReporter.FM_CONFIG = "no_file"
    fake_bin = tmp_path / "bin"
    fake_bin.touch()
    #with pytest.raises(IOError) as exc:
    with pytest.raises(IOError) as exc:
        FuzzManagerReporter.sanity_check(str(fake_bin))
    assert "Missing: no_file" in str(exc)
    fake_fmc = tmp_path / ".fuzzmanagerconf"
    fake_fmc.touch()
    FuzzManagerReporter.FM_CONFIG = str(fake_fmc)
    with pytest.raises(IOError) as exc:
        FuzzManagerReporter.sanity_check(str(fake_bin))
    assert "bin.fuzzmanagerconf" in str(exc)
    fake_bin_fmc = tmp_path / "bin.fuzzmanagerconf"
    fake_bin_fmc.touch()
    FuzzManagerReporter.sanity_check(str(fake_bin))

def test_s3fuzzmanager_reporter_01(tmp_path, mocker):
    """test S3FuzzManagerReporter.sanity_check()"""
    mocker.patch("grizzly.reporter.FuzzManagerReporter", autospec=True)
    fake_bin = tmp_path / "bin"
    with pytest.raises(EnvironmentError) as exc:
        S3FuzzManagerReporter.sanity_check(str(fake_bin))
    assert "'GRZ_S3_BUCKET' is not set in environment" in str(exc)
    os.environ["GRZ_S3_BUCKET"] = "test"
    try:
        S3FuzzManagerReporter.sanity_check(str(fake_bin))
    finally:
        os.environ.pop("GRZ_S3_BUCKET", None)

# TODO: fill out tests for FuzzManagerReporter and S3FuzzManagerReporter
