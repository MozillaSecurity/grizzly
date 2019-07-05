# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly Reporter"""
# pylint: disable=protected-access

import os
import sys
import tarfile

import pytest

from .reporter import FilesystemReporter, FuzzManagerReporter, Report, Reporter, S3FuzzManagerReporter
from .storage import TestCase


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
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
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
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    with (tmp_path / "log_asan_blah.txt").open("wb") as log_fp:
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
    with (tmp_path / "log_asan.txt.1").open("wb") as log_fp:
        log_fp.write(b"SHORT LOG\n")
        log_fp.write(b"filler line")
    # crash on another thread
    with (tmp_path / "log_asan.txt.2").open("wb") as log_fp:
        log_fp.write(b"GOOD LOG\n")
        log_fp.write(b"==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x00000BADF00D")
        log_fp.write(b" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % l_no)
    # child log that should be ignored (created when parent crashes)
    with (tmp_path / "log_asan.txt.3").open("wb") as log_fp:
        log_fp.write(b"BAD LOG\n")
        log_fp.write(b"==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000")
        log_fp.write(b" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % l_no)
    (tmp_path / "log_mindump_blah.txt").write_bytes(b"minidump log")
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    # should be ignored in favor of "GOOD LOG"
    (tmp_path / "log_ffp_worker_blah.txt").write_bytes(b"worker log")
    log_map = Report.select_logs(str(tmp_path))
    assert "GOOD LOG" in (tmp_path / log_map["aux"]).read_text()
    assert "STDERR" in (tmp_path / log_map["stderr"]).read_text()
    assert "STDOUT" in (tmp_path / log_map["stdout"]).read_text()

def test_report_06(tmp_path):
    """test minidump with Report.select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    with (tmp_path / "log_minidump_01.txt").open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|SIGSEGV|0x0|0\n")
        log_fp.write(b"minidump log\n")
    (tmp_path / "log_ffp_worker_blah.txt").write_bytes(b"worker log")
    log_map = Report.select_logs(str(tmp_path))
    assert (tmp_path / log_map["stderr"]).is_file()
    assert (tmp_path / log_map["stdout"]).is_file()
    assert "minidump log" in (tmp_path / log_map["aux"]).read_text()

def test_report_07(tmp_path):
    """test selecting preferred DUMP_REQUESTED minidump with Report.select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    with (tmp_path / "log_minidump_01.txt").open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|DUMP_REQUESTED|0x7f9518665d18|0\n")
        log_fp.write(b"0|0|bar.so|sadf|a.cc:739484451a63|3066|0x0\n")
        log_fp.write(b"0|1|gar.so|fdsa|b.cc:739484451a63|1644|0x12\n")
    with (tmp_path / "log_minidump_02.txt").open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|DUMP_REQUESTED|0x7f57ac9e2e14|0\n")
        log_fp.write(b"0|0|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|bar.cc:234|674|0xc\n")
        log_fp.write(b"0|1|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|bar.cc:4a2|645|0x8\n")
    with (tmp_path / "log_minidump_03.txt").open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|DUMP_REQUESTED|0x7f9518665d18|0\n")
        log_fp.write(b"0|0|bar.so|sadf|a.cc:1234|3066|0x0\n")
        log_fp.write(b"0|1|gar.so|fdsa|b.cc:4323|1644|0x12\n")
    log_map = Report.select_logs(str(tmp_path))
    assert (tmp_path / log_map["stderr"]).is_file()
    assert (tmp_path / log_map["stdout"]).is_file()
    assert "google_breakpad::ExceptionHandler::WriteMinidump" in (tmp_path / log_map["aux"]).read_text()

def test_report_08(tmp_path):
    """test selecting worker logs with Report.select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    (tmp_path / "log_ffp_worker_blah.txt").write_bytes(b"worker log")
    log_map = Report.select_logs(str(tmp_path))
    assert (tmp_path / log_map["stderr"]).is_file()
    assert (tmp_path / log_map["stdout"]).is_file()
    assert "worker log" in (tmp_path / log_map["aux"]).read_text()

def test_report_09(tmp_path):
    """test prioritizing *San logs with Report.select_logs()"""
    # crash
    with (tmp_path / "log_asan.txt.1").open("wb") as log_fp:
        log_fp.write(b"GOOD LOG\n")
        log_fp.write(b"==1942==ERROR: AddressSanitizer: heap-use-after-free on ... blah\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % l_no)
    # crash missing trace
    with (tmp_path / "log_asan.txt.2").open("wb") as log_fp:
        log_fp.write(b"BAD LOG\n")
        log_fp.write(b"==1984==ERROR: AddressSanitizer: SEGV on ... blah\n")  # must be 2nd line
        log_fp.write(b"missing trace...\n")
    # child log that should be ignored (created when parent crashes)
    with (tmp_path / "log_asan.txt.3").open("wb") as log_fp:
        log_fp.write(b"BAD LOG\n")
        log_fp.write(b"==1184==ERROR: AddressSanitizer: BUS on ... blah\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % l_no)
    with (tmp_path / "log_asan.txt.4").open("wb") as log_fp:
        log_fp.write(b"BAD LOG\n")
        log_fp.write(b"==9482==ERROR: AddressSanitizer: stack-overflow on ...\n")  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % l_no)
    with (tmp_path / "log_asan.txt.5").open("wb") as log_fp:
        log_fp.write(b"BAD LOG\n")
        log_fp.write(b"ERROR: Failed to mmap\n")  # must be 2nd line
    log_map = Report.select_logs(str(tmp_path))
    assert "GOOD LOG" in (tmp_path / log_map["aux"]).read_text()

def test_report_10(tmp_path):
    """test Report size_limit"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log\n" * 200)
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log\n" * 200)
    (tmp_path / "unrelated.txt").write_bytes(b"nothing burger\n" * 200)
    (tmp_path / "rr-trace").mkdir()
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
    assert not tmp_path.is_dir()

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
    assert "No such directory 'fake_dir'" in str(exc.value)
    with pytest.raises(IOError) as exc:
        reporter.submit(str(tmp_path), [])
    assert "No logs found in" in str(exc.value)

def test_filesystem_reporter_01(tmp_path):
    """test FilesystemReporter without testcases"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    with (log_path / "log_asan_blah.txt").open("wb") as log_fp:
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19")
    report_path = tmp_path / "reports"
    report_path.mkdir()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.submit(str(log_path), [])

def test_filesystem_reporter_02(tmp_path, mocker):
    """test FilesystemReporter with testcases"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    with (log_path / "log_asan_blah.txt").open("wb") as log_fp:
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19")
    testcases = list()
    for _ in range(10):
        testcases.append(mocker.Mock(spec=TestCase))
    report_path = tmp_path / "reports"
    assert not report_path.exists()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.submit(str(log_path), testcases)
    assert not log_path.exists()
    assert report_path.exists()
    assert len(os.listdir(str(report_path))) == 1
    for tstc in testcases:
        assert tstc.dump.call_count == 1
    # call report a 2nd time
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    testcases = list()
    for _ in range(2):
        testcases.append(mocker.Mock(spec=TestCase))
    reporter.submit(str(log_path), testcases)
    for tstc in testcases:
        assert tstc.dump.call_count == 1
    results = os.listdir(str(report_path))
    assert len(results) == 2
    assert "NO_STACK" in results

def test_filesystem_reporter_03(tmp_path):
    """test FilesystemReporter disk space failsafe"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    report_path = tmp_path / "reports"
    report_path.mkdir()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.DISK_SPACE_ABORT = 2 ** 50
    with pytest.raises(RuntimeError) as exc:
        reporter.submit(str(log_path), [])
    assert "Running low on disk space" in str(exc.value)

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RR only supported on Linux")
def test_filesystem_reporter_04(tmp_path):
    """test packaging rr traces"""
    # create fake logs
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    with (log_path / "log_asan_blah.txt").open("wb") as log_fp:
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19")
    # create fake trace
    rr_trace_path = log_path / "rr-traces" / "echo-0"
    rr_trace_path.mkdir(parents=True)
    (rr_trace_path / "fail_file").touch()
    rr_trace_path = log_path / "rr-traces" / "echo-1"
    rr_trace_path.mkdir()
    (rr_trace_path / "cloned_data_5799_1").touch()
    (rr_trace_path / "data").write_bytes(b"test_data")
    (rr_trace_path / "events").write_bytes(b"foo")
    (rr_trace_path / "mmap").write_bytes(b"bar")
    (rr_trace_path / "tasks").write_bytes(b"foo")
    (rr_trace_path / "version").write_bytes(b"123")
    (log_path / "rr-traces" / "latest-trace").symlink_to(str(rr_trace_path), target_is_directory=True)
    report_path = tmp_path / "reports"
    # report
    assert not report_path.exists()
    reporter = FilesystemReporter(report_path=str(report_path))
    reporter.submit(str(log_path), [])
    assert report_path.exists()
    # verify report and archive
    report_log_dirs = list(report_path.glob("*/*_logs/"))
    assert len(report_log_dirs) == 1
    report_log_dir = str(report_log_dirs[0])
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
    mocker.patch("grizzly.common.reporter.ProgramConfiguration")
    FuzzManagerReporter.FM_CONFIG = "no_file"
    fake_bin = tmp_path / "bin"
    fake_bin.touch()
    #with pytest.raises(IOError) as exc:
    with pytest.raises(IOError) as exc:
        FuzzManagerReporter.sanity_check(str(fake_bin))
    assert "Missing: no_file" in str(exc.value)
    fake_fmc = tmp_path / ".fuzzmanagerconf"
    fake_fmc.touch()
    FuzzManagerReporter.FM_CONFIG = str(fake_fmc)
    with pytest.raises(IOError) as exc:
        FuzzManagerReporter.sanity_check(str(fake_bin))
    assert "bin.fuzzmanagerconf" in str(exc.value)
    (tmp_path / "bin.fuzzmanagerconf").touch()
    FuzzManagerReporter.sanity_check(str(fake_bin))

def test_fuzzmanager_reporter_02(tmp_path):
    """test FuzzManagerReporter.submit() empty path"""
    reporter = FuzzManagerReporter("fake_bin")
    report_path = tmp_path / "report"
    report_path.mkdir()
    with pytest.raises(IOError) as exc:
        reporter.submit(str(report_path), [])
    assert "No logs found in" in str(exc.value)

def test_fuzzmanager_reporter_03(tmp_path, mocker):
    """test FuzzManagerReporter.submit()"""
    fake_crashinfo = mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_crashinfo.fromRawCrashData.return_value.createShortSignature.return_value = "test [@ test]"
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (None, None)
    fake_collector.return_value.generate.return_value = str(tmp_path / "fake_sig_file")
    reporter = FuzzManagerReporter(str("fake_bin"))
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    fake_test = mocker.Mock(spec=TestCase)
    fake_test.adapter_name = "adapter"
    fake_test.input_fname = "input"
    fake_test.env_vars = ("TEST=1",)
    reporter.submit(str(log_path), [fake_test])
    assert not log_path.is_dir()
    assert fake_test.dump.call_count == 1
    assert fake_collector.return_value.submit.call_count == 1

def test_fuzzmanager_reporter_04(tmp_path, mocker):
    """test FuzzManagerReporter.submit() hit frequent crash"""
    mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (None, {"frequent": True, "shortDescription": "[@ test]"})
    reporter = FuzzManagerReporter("fake_bin")
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    reporter.submit(str(log_path), [])
    fake_collector.return_value.submit.assert_not_called()

def test_fuzzmanager_reporter_05(tmp_path, mocker):
    """test FuzzManagerReporter.submit() hit existing crash"""
    mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (
        None, {"bug__id":1, "frequent": False, "shortDescription": "[@ test]"})
    reporter = FuzzManagerReporter("fake_bin")
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    reporter._ignored = lambda x: True
    reporter.submit(str(log_path), [])
    fake_collector.return_value.submit.assert_not_called()

def test_fuzzmanager_reporter_06(tmp_path, mocker):
    """test FuzzManagerReporter.submit() no signature"""
    mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (None, None)
    fake_collector.return_value.generate.return_value = None
    reporter = FuzzManagerReporter("fake_bin")
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    with pytest.raises(RuntimeError) as exc:
        reporter.submit(str(log_path), [])
    assert "Failed to create FM signature" in str(exc.value)
    fake_collector.return_value.submit.assert_not_called()
    # test ignore unsymbolized crash
    reporter._ignored = lambda x: True
    reporter.submit(str(log_path), [])
    fake_collector.return_value.submit.assert_not_called()

def test_s3fuzzmanager_reporter_01(tmp_path, mocker):
    """test S3FuzzManagerReporter.sanity_check()"""
    mocker.patch("grizzly.common.reporter.FuzzManagerReporter", autospec=True)
    fake_bin = tmp_path / "bin"
    with pytest.raises(EnvironmentError) as exc:
        S3FuzzManagerReporter.sanity_check(str(fake_bin))
    assert "'GRZ_S3_BUCKET' is not set in environment" in str(exc.value)
    os.environ["GRZ_S3_BUCKET"] = "test"
    try:
        S3FuzzManagerReporter.sanity_check(str(fake_bin))
    finally:
        os.environ.pop("GRZ_S3_BUCKET", None)

def test_s3fuzzmanager_reporter_02(tmp_path, mocker):
    """test S3FuzzManagerReporter._process_rr_trace()"""
    fake_boto3 = mocker.patch("grizzly.common.reporter.boto3", autospec=True)

    fake_report = mocker.Mock(spec=Report)
    fake_report.path = "no-path"
    reporter = S3FuzzManagerReporter("fake_bin")
    # test will missing rr-trace
    assert reporter._process_rr_trace(fake_report) is None
    assert not reporter._extra_metadata

    # test will exiting rr-trace
    trace_dir = tmp_path / "rr-traces" / "latest-trace"
    trace_dir.mkdir(parents=True)
    fake_report.minor = "1234abcd"
    fake_report.path = str(tmp_path)
    os.environ["GRZ_S3_BUCKET"] = "test"
    try:
        reporter._process_rr_trace(fake_report)
    finally:
        os.environ.pop("GRZ_S3_BUCKET", None)
    assert not os.listdir(str(tmp_path))
    assert "rr-trace" in reporter._extra_metadata
    assert fake_report.minor in reporter._extra_metadata["rr-trace"]
    fake_boto3.resource.return_value.meta.client.upload_file.assert_not_called()

    # test with new rr-trace
    reporter._extra_metadata.clear()
    trace_dir.mkdir(parents=True)
    (trace_dir / "trace-file").touch()
    class FakeClientError(Exception):
        def __init__(self, message, response):
            super(FakeClientError, self).__init__(message)
            self.response = response
    fake_botocore = mocker.patch("grizzly.common.reporter.botocore", autospec=True)
    fake_botocore.exceptions.ClientError = FakeClientError
    fake_boto3.resource.return_value.Object.side_effect = FakeClientError("test", {"Error": {"Code": "404"}})
    os.environ["GRZ_S3_BUCKET"] = "test"
    try:
        reporter._process_rr_trace(fake_report)
    finally:
        os.environ.pop("GRZ_S3_BUCKET", None)
    assert not os.listdir(str(tmp_path))
    assert "rr-trace" in reporter._extra_metadata
    assert fake_report.minor in reporter._extra_metadata["rr-trace"]
    assert fake_boto3.resource.return_value.meta.client.upload_file.call_count == 1

# TODO: fill out tests for FuzzManagerReporter and S3FuzzManagerReporter
