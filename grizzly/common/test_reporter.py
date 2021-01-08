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

from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo

from .reporter import FilesystemReporter, FuzzManagerReporter, Report, Reporter, S3FuzzManagerReporter
from .storage import TestCase

def _create_crash_log(log_path):
    with log_path.open("w") as log_fp:
        log_fp.write("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0")
        log_fp.write(" (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19")

def test_report_01(tmp_path):
    """test Report() with boring logs (no stack)"""
    (tmp_path / "not_a_log.txt").touch()
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    report = Report(str(tmp_path), "a.bin", size_limit=0)
    assert report._target_binary == "a.bin"
    assert report.path == str(tmp_path)
    assert report._logs.aux is None
    assert report._logs.stderr.endswith("log_stderr.txt")
    assert report._logs.stdout.endswith("log_stdout.txt")
    assert report.preferred.endswith("log_stderr.txt")
    assert report.stack is None
    assert Report.DEFAULT_MAJOR == report.major
    assert Report.DEFAULT_MINOR == report.minor
    assert report.prefix is not None
    report.cleanup()
    assert not tmp_path.exists()

def test_report_02(tmp_path):
    """test Report() with crash logs"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    report = Report(str(tmp_path), "bin")
    assert report.path == str(tmp_path)
    assert report._logs.aux.endswith("log_asan_blah.txt")
    assert report._logs.stderr.endswith("log_stderr.txt")
    assert report._logs.stdout.endswith("log_stdout.txt")
    assert report.preferred.endswith("log_asan_blah.txt")
    assert report.stack is not None
    assert Report.DEFAULT_MAJOR != report.major
    assert Report.DEFAULT_MINOR != report.minor
    assert report.prefix is not None
    report.cleanup()

def test_report_03(tmp_path):
    """test Report.tail()"""
    tmp_file = tmp_path / "file.txt"
    tmp_file.write_bytes(b"blah\ntest\n123\xEF\x00FOO")
    length = tmp_file.stat().st_size
    # no size limit
    with pytest.raises(AssertionError):
        Report.tail(str(tmp_file), 0)
    assert tmp_file.stat().st_size == length
    Report.tail(str(tmp_file), 3)
    log_data = tmp_file.read_bytes()
    assert log_data.startswith(b"[LOG TAILED]\n")
    assert log_data[13:] == b"FOO"

def test_report_04(tmp_path):
    """test Report.select_logs() uninteresting data"""
    # test with empty path
    assert Report.select_logs(str(tmp_path)) is None
    # empty file
    (tmp_path / "not_a_log.txt").touch()
    assert not any(Report.select_logs(str(tmp_path)))

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
    assert "GOOD LOG" in (tmp_path / log_map.aux).read_text()
    assert "STDERR" in (tmp_path / log_map.stderr).read_text()
    assert "STDOUT" in (tmp_path / log_map.stdout).read_text()

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
    assert (tmp_path / log_map.stderr).is_file()
    assert (tmp_path / log_map.stdout).is_file()
    assert "minidump log" in (tmp_path / log_map.aux).read_text()

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
    assert (tmp_path / log_map.stderr).is_file()
    assert (tmp_path / log_map.stdout).is_file()
    assert "google_breakpad::ExceptionHandler::WriteMinidump" in (tmp_path / log_map.aux).read_text()

def test_report_08(tmp_path):
    """test selecting worker logs with Report.select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    (tmp_path / "log_ffp_worker_1.txt").write_bytes(b"worker log")
    # we should only ever see one but if we see multiple we warn, so test that.
    (tmp_path / "log_ffp_worker_2.txt").write_bytes(b"worker log")
    log_map = Report.select_logs(str(tmp_path))
    assert (tmp_path / log_map.stderr).is_file()
    assert (tmp_path / log_map.stdout).is_file()
    assert "worker log" in (tmp_path / log_map.aux).read_text()

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
    assert "GOOD LOG" in (tmp_path / log_map.aux).read_text()

def test_report_10(tmp_path):
    """test Report() size_limit"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log\n" * 200)
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log\n" * 200)
    (tmp_path / "unrelated.txt").write_bytes(b"nothing burger\n" * 200)
    (tmp_path / "rr-trace").mkdir()
    size_limit = len("STDERR log\n")
    report = Report(str(tmp_path), "bin", size_limit=size_limit)
    assert report.path == str(tmp_path)
    assert report._logs.aux is None
    assert report._logs.stderr.endswith("log_stderr.txt")
    assert report._logs.stdout.endswith("log_stdout.txt")
    assert report.preferred.endswith("log_stderr.txt")
    assert report.stack is None
    size_limit += len("[LOG TAILED]\n")
    assert os.stat(os.path.join(report.path, report._logs.stderr)).st_size == size_limit
    assert os.stat(os.path.join(report.path, report._logs.stdout)).st_size == size_limit
    assert os.stat(os.path.join(report.path, "unrelated.txt")).st_size == size_limit
    report.cleanup()
    assert not tmp_path.is_dir()

def test_report_11(tmp_path):
    """test selecting Valgrind logs with Report.select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    (tmp_path / "log_valgrind.txt").write_bytes(b"valgrind log")
    log_map = Report.select_logs(str(tmp_path))
    assert (tmp_path / log_map.stderr).is_file()
    assert (tmp_path / log_map.stdout).is_file()
    assert "valgrind log" in (tmp_path / log_map.aux).read_text()

def test_report_12(tmp_path):
    """test Report.crash_info"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    # no binary.fuzzmanagerconf
    report = Report(str(tmp_path), target_binary="fake_bin")
    assert report._crash_info is None
    assert report.crash_info is not None
    assert report._crash_info is not None
    # with binary.fuzzmanagerconf
    with (tmp_path / "fake_bin.fuzzmanagerconf").open("wb") as conf:
        conf.write(b"[Main]\n")
        conf.write(b"platform = x86-64\n")
        conf.write(b"product = mozilla-central\n")
        conf.write(b"os = linux\n")
    report = Report(str(tmp_path), target_binary=str(tmp_path / "fake_bin"))
    assert report._crash_info is None
    assert report.crash_info is not None
    assert report._crash_info is not None

def test_report_13(mocker, tmp_path):
    """test Report.crash_signature and Report.crash_hash"""
    mocker.patch("grizzly.common.reporter.ProgramConfiguration", autospec=True)
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    report = Report(str(tmp_path), "bin")
    assert report._signature is None
    assert report.crash_signature
    assert report.crash_info.createShortSignature() == "[@ foo]"
    assert report.crash_hash

def test_report_14(mocker):
    """test Report.crash_signature_max_frames()"""
    info = mocker.Mock(spec=CrashInfo)
    info.backtrace = ("blah")
    assert Report.crash_signature_max_frames(info) == 8
    info.backtrace = ("std::panicking::rust_panic", "std::panicking::rust_panic_with_hook")
    assert Report.crash_signature_max_frames(info) == 14

def test_reporter_01(mocker):
    """test creating a simple Reporter"""
    class SimpleReporter(Reporter):
        def _pre_submit(self, report):
            pass
        def _post_submit(self):
            pass
        def _submit_report(self, report, test_cases):
            pass
    reporter = SimpleReporter()
    reporter.submit([], report=mocker.Mock(spec=Report))

def test_filesystem_reporter_01(tmp_path):
    """test FilesystemReporter without testcases"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    report_path = tmp_path / "reports"
    report_path.mkdir()
    reporter = FilesystemReporter(str(report_path))
    reporter.submit([], Report(str(log_path), "fake_bin"))
    buckets = tuple(report_path.iterdir())
    # check major bucket
    assert len(buckets) == 1
    assert buckets[0].is_dir()
    # check log path exists
    log_dirs = tuple(buckets[0].iterdir())
    assert len(log_dirs) == 1
    assert log_dirs[0].is_dir()
    assert "_logs" in str(log_dirs[0])

def test_filesystem_reporter_02(tmp_path, mocker):
    """test FilesystemReporter with testcases"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(log_path / "log_asan_blah.txt")
    tests = list(mocker.Mock(spec=TestCase) for _ in range(10))
    report_path = tmp_path / "reports"
    assert not report_path.exists()
    reporter = FilesystemReporter(str(report_path))
    reporter.submit(tests, Report(str(log_path), "fake_bin"))
    assert not log_path.exists()
    assert report_path.exists()
    assert len(tuple(report_path.glob("*"))) == 1
    assert all(x.dump.call_count == 1 for x in tests)
    # call report a 2nd time
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    tests = list(mocker.Mock(spec=TestCase) for _ in range(2))
    reporter.submit(tests, Report(str(log_path), "fake_bin"))
    assert all(x.dump.call_count == 1 for x in tests)
    assert len(tuple(report_path.glob("*"))) == 2
    assert len(tuple(report_path.glob("NO_STACK"))) == 1

def test_filesystem_reporter_03(tmp_path):
    """test FilesystemReporter disk space failsafe"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    reporter = FilesystemReporter(str(tmp_path / "reports"))
    reporter.DISK_SPACE_ABORT = 2 ** 50
    with pytest.raises(RuntimeError, match="Running low on disk space"):
        reporter.submit([], Report(str(log_path), "fake_bin"))

def test_filesystem_reporter_04(mocker, tmp_path):
    """test FilesystemReporter w/o major bucket"""
    fake_report = (tmp_path / "fake_report")
    fake_report.mkdir()
    report = mocker.Mock(
        spec=Report,
        path=str(fake_report),
        prefix="test_prefix")
    reporter = FilesystemReporter(str(tmp_path / "dst"), major_bucket=False)
    reporter.submit([], report)
    assert not fake_report.is_dir()
    assert not report.major.call_count
    assert any((tmp_path / "dst").glob("test_prefix_logs"))

def test_fuzzmanager_reporter_01(mocker, tmp_path):
    """test FuzzManagerReporter.sanity_check()"""
    fake_reporter = mocker.patch("grizzly.common.reporter.ProgramConfiguration")
    fake_reporter.fromBinary.return_value = mocker.Mock(spec=ProgramConfiguration)
    # missing global FM config file
    FuzzManagerReporter.FM_CONFIG = "no_file"
    with pytest.raises(IOError, match="Missing: no_file"):
        FuzzManagerReporter.sanity_check("fake")
    # missing binary FM config file
    fake_fmc = tmp_path / ".fuzzmanagerconf"
    fake_fmc.touch()
    fake_bin = tmp_path / "bin"
    fake_bin.touch()
    FuzzManagerReporter.FM_CONFIG = str(fake_fmc)
    with pytest.raises(IOError, match="bin.fuzzmanagerconf"):
        FuzzManagerReporter.sanity_check(str(fake_bin))
    # success
    (tmp_path / "bin.fuzzmanagerconf").touch()
    FuzzManagerReporter.sanity_check(str(fake_bin))
    assert fake_reporter.fromBinary.call_count == 1

def test_fuzzmanager_reporter_02(mocker, tmp_path):
    """test FuzzManagerReporter.submit()"""
    mocker.patch("grizzly.common.reporter.getcwd", autospec=True, return_value=str(tmp_path))
    mocker.patch("grizzly.common.reporter.getenv", autospec=True, return_value="0")
    fake_crashinfo = mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_crashinfo.fromRawCrashData.return_value.createShortSignature.return_value = "test [@ test]"
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (None, None)
    fake_collector.return_value.generate.return_value = str(tmp_path / "fm_file.signature")
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_ffp_worker_blah.txt").touch()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    (log_path / "rr-traces").mkdir()
    (tmp_path / "screenlog.0").touch()
    fake_test = mocker.Mock(
        spec=TestCase,
        adapter_name="adapter",
        env_vars={"TEST": "1"},
        input_fname="input")
    reporter = FuzzManagerReporter("fake_bin")
    reporter.submit([fake_test], Report(str(log_path), "fake_bin"))
    assert not log_path.is_dir()
    assert fake_test.dump.call_count == 1
    assert fake_collector.return_value.submit.call_count == 1
    meta_data = (tmp_path / "fm_file.metadata").read_text()
    assert "\"frequent\": false" in meta_data
    assert "\"_grizzly_seen_count\": 1" in meta_data
    assert "\"shortDescription\": \"test [@ test]\"" in meta_data

def test_fuzzmanager_reporter_03(mocker, tmp_path):
    """test FuzzManagerReporter.submit() - no test / mark as frequent"""
    mocker.patch("grizzly.common.reporter.getcwd", autospec=True, return_value=str(tmp_path))
    fake_crashinfo = mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_crashinfo.fromRawCrashData.return_value.createShortSignature.return_value = "test [@ test]"
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (None, None)
    fake_collector.return_value.generate.return_value = str(tmp_path / "fm_file.signature")
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    reporter = FuzzManagerReporter("fake_bin")
    reporter.MAX_REPORTS = 1
    reporter.submit([], Report(str(log_path), "fake_bin"))
    assert fake_collector.return_value.submit.call_count == 1
    meta_data = (tmp_path / "fm_file.metadata").read_text()
    assert "\"frequent\": true" in meta_data
    assert "\"_grizzly_seen_count\": 1" in meta_data
    assert "\"shortDescription\": \"test [@ test]\"" in meta_data

def test_fuzzmanager_reporter_04(mocker, tmp_path):
    """test FuzzManagerReporter.submit() hit frequent crash"""
    mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (
        None,
        {"frequent": True, "shortDescription": "[@ test]"})
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    reporter = FuzzManagerReporter("fake_bin")
    reporter.submit([], Report(str(log_path), "fake_bin"))
    fake_collector.return_value.submit.assert_not_called()

def test_fuzzmanager_reporter_05(mocker, tmp_path):
    """test FuzzManagerReporter.submit() hit existing crash"""
    mocker.patch("grizzly.common.reporter.CrashInfo", autospec=True)
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (
        None,
        {"bug__id":1, "frequent": False, "shortDescription": "[@ test]"})
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    reporter = FuzzManagerReporter("fake_bin")
    reporter._ignored = lambda x: True
    reporter.submit([], Report(str(log_path), "fake_bin"))
    fake_collector.return_value.submit.assert_not_called()

def test_fuzzmanager_reporter_06(mocker, tmp_path):
    """test FuzzManagerReporter.submit() no signature"""
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (None, None)
    fake_collector.return_value.generate.return_value = None
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    reporter = FuzzManagerReporter("fake_bin")
    with pytest.raises(RuntimeError, match="Failed to create FM signature"):
        reporter.submit([], Report(str(log_path), "fake_bin"))

def test_fuzzmanager_reporter_07(mocker, tmp_path):
    """test FuzzManagerReporter.submit() unsymbolized crash"""
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (None, None)
    fake_collector.return_value.generate.return_value = None
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    reporter = FuzzManagerReporter("fake_bin")
    reporter._ignored = lambda x: True
    reporter.submit([], Report(str(log_path), "fake_bin"))
    fake_collector.return_value.submit.assert_not_called()

def test_fuzzmanager_reporter_08():
    """test FuzzManagerReporter.quality_name()"""
    assert FuzzManagerReporter.quality_name(0) == "QUAL_REDUCED_RESULT"
    assert FuzzManagerReporter.quality_name(-1) == "unknown quality (-1)"

def test_fuzzmanager_reporter_09(mocker, tmp_path):
    """test FuzzManagerReporter._ignored()"""
    log_file = (tmp_path / "test.log")
    log_file.touch()
    report = mocker.Mock(spec=Report, path=str(tmp_path), preferred=str(log_file))
    # not ignored
    assert not FuzzManagerReporter._ignored(report)
    # ignored - sanitizer OOM missing stack
    log_file.write_bytes(b"ERROR: Failed to mmap")
    assert FuzzManagerReporter._ignored(report)
    # ignored - Valgrind OOM
    log_file.write_bytes(b"VEX temporary storage exhausted.")
    assert FuzzManagerReporter._ignored(report)

def test_s3fuzzmanager_reporter_01(mocker, tmp_path):
    """test S3FuzzManagerReporter.sanity_check()"""
    mocker.patch("grizzly.common.reporter.FuzzManagerReporter", autospec=True)
    fake_bin = tmp_path / "bin"
    # test GRZ_S3_BUCKET missing
    with pytest.raises(EnvironmentError, match="'GRZ_S3_BUCKET' is not set in environment"):
        S3FuzzManagerReporter.sanity_check(str(fake_bin))
    # test GRZ_S3_BUCKET set
    pytest.importorskip("boto3")
    mocker.patch("grizzly.common.reporter.getenv", autospec=True, return_value="test")
    S3FuzzManagerReporter.sanity_check(str(fake_bin))

def test_s3fuzzmanager_reporter_02(mocker, tmp_path):
    """test S3FuzzManagerReporter._pre_submit()"""
    pytest.importorskip("boto3")
    pytest.importorskip("botocore")
    mocker.patch("grizzly.common.reporter.getenv", autospec=True, return_value="test")
    fake_resource = mocker.patch("grizzly.common.reporter.resource", autospec=True)

    fake_report = mocker.Mock(spec=Report)
    fake_report.path = "no-path"
    reporter = S3FuzzManagerReporter("fake_bin")
    # test will missing rr-trace
    assert reporter._pre_submit(fake_report) is None
    assert not reporter._extra_metadata

    # test will exiting rr-trace
    trace_dir = tmp_path / "rr-traces" / "latest-trace"
    trace_dir.mkdir(parents=True)
    fake_report.minor = "1234abcd"
    fake_report.path = str(tmp_path)
    reporter._pre_submit(fake_report)
    assert not any(tmp_path.glob("*"))
    assert "rr-trace" in reporter._extra_metadata
    assert fake_report.minor in reporter._extra_metadata["rr-trace"]
    fake_resource.return_value.meta.client.upload_file.assert_not_called()

    # test with new rr-trace
    reporter._extra_metadata.clear()
    trace_dir.mkdir(parents=True)
    (trace_dir / "trace-file").touch()
    class FakeClientError(Exception):
        def __init__(self, message, response):
            super().__init__(message)
            self.response = response
    mocker.patch("grizzly.common.reporter.ClientError", new=FakeClientError)
    fake_resource.return_value.Object.side_effect = FakeClientError("test", {"Error": {"Code": "404"}})
    reporter._pre_submit(fake_report)
    assert not any(tmp_path.glob("*"))
    assert "rr-trace" in reporter._extra_metadata
    assert fake_report.minor in reporter._extra_metadata["rr-trace"]
    assert fake_resource.return_value.meta.client.upload_file.call_count == 1

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RR only supported on Linux")
def test_s3fuzzmanager_reporter_03(tmp_path):
    """test S3FuzzManagerReporter.compress_rr_trace()"""
    # create fake trace
    src = tmp_path / "rr-traces" / "echo-0"
    src.mkdir(parents=True)
    (src / "fail_file").touch()
    src = tmp_path / "rr-traces" / "echo-1"
    src.mkdir()
    (src / "cloned_data_5799_1").touch()
    (src / "data").write_bytes(b"test_data")
    (src / "events").write_bytes(b"foo")
    (src / "mmap").write_bytes(b"bar")
    (src / "tasks").write_bytes(b"foo")
    (src / "version").write_bytes(b"123")
    (tmp_path / "rr-traces" / "latest-trace").symlink_to(str(src), target_is_directory=True)
    src = tmp_path / "rr-traces"
    dest = tmp_path / "dest"
    dest.mkdir()
    S3FuzzManagerReporter.compress_rr_trace(str(src), str(dest))
    assert not src.is_dir()
    assert (dest / "rr.tar.bz2").is_file()
    with tarfile.open(str(dest / "rr.tar.bz2"), "r:bz2") as arc_fp:
        entries = arc_fp.getnames()
    assert "echo-1" in entries
    assert "echo-0" not in entries
    assert "latest-trace" not in entries

# TODO: fill out tests for FuzzManagerReporter and S3FuzzManagerReporter
