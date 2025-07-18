# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly Report"""

# pylint: disable=protected-access
from pathlib import Path

from FTB.Signatures.CrashInfo import CrashInfo, TraceParsingError
from pytest import mark, raises

from .report import Report


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
    report = Report(tmp_path, Path("a.bin"), size_limit=0)
    assert report._target_binary.name == "a.bin"
    assert report.path == tmp_path
    assert report._logs
    assert report._logs.aux is None
    assert report._logs.stderr.name == "log_stderr.txt"
    assert report._logs.stdout.name == "log_stdout.txt"
    assert report.preferred.name == "log_stderr.txt"
    assert report.stack is None
    assert report.major == Report.DEFAULT_MAJOR
    assert report.minor == Report.DEFAULT_MINOR
    assert report.prefix is not None
    report.cleanup()
    assert not tmp_path.exists()


def test_report_02(tmp_path):
    """test Report() with crash logs"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    report = Report(tmp_path, Path("bin"))
    assert report.path == tmp_path
    assert report._logs
    assert report._logs.aux.name == "log_asan_blah.txt"
    assert report._logs.stderr.name == "log_stderr.txt"
    assert report._logs.stdout.name == "log_stdout.txt"
    assert report.preferred.name == "log_asan_blah.txt"
    assert report.stack is not None
    assert report.major != Report.DEFAULT_MAJOR
    assert report.minor != Report.DEFAULT_MINOR
    assert report.prefix is not None
    report.cleanup()


def test_report_03(tmp_path):
    """test Report.tail()"""
    tmp_file = tmp_path / "file.txt"
    tmp_file.write_bytes(b"blah\ntest\n123\xef\x00FOO")
    length = tmp_file.stat().st_size
    # don't trim
    Report.tail(tmp_file, length + 1)
    assert tmp_file.stat().st_size == length
    # perform trim
    Report.tail(tmp_file, 3)
    log_data = tmp_file.read_bytes()
    assert log_data.startswith(b"[LOG TAILED]\n")
    assert log_data[13:] == b"FOO"


def test_report_04(tmp_path):
    """test Report._select_logs() uninteresting data"""
    # test with empty path
    assert Report._select_logs(tmp_path) is None
    # empty file
    (tmp_path / "not_a_log.txt").touch()
    assert Report._select_logs(tmp_path) is None


def test_report_05(tmp_path):
    """test Report._select_logs()"""
    # small log with nothing interesting
    with (tmp_path / "log_asan.txt.1").open("wb") as log_fp:
        log_fp.write(b"SHORT LOG\n")
        log_fp.write(b"filler line")
    # crash on another thread
    with (tmp_path / "log_asan.txt.2").open("wb") as log_fp:
        log_fp.write(b"GOOD LOG\n")
        log_fp.write(
            b"==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x00000BADF00D"
        )
        log_fp.write(
            b" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n"
        )  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % l_no)
    # child log that should be ignored (created when parent crashes)
    with (tmp_path / "log_asan.txt.3").open("wb") as log_fp:
        log_fp.write(b"BAD LOG\n")
        log_fp.write(
            b"==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000"
        )
        log_fp.write(
            b" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n"
        )  # must be 2nd line
        # pad out to 6 lines
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % l_no)
    (tmp_path / "log_mindump_blah.txt").write_bytes(b"minidump log")
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    # should be ignored in favor of "GOOD LOG"
    (tmp_path / "log_ffp_worker_blah.txt").write_bytes(b"worker log")
    log_map = Report._select_logs(tmp_path)
    assert log_map
    assert "GOOD LOG" in log_map.aux.read_text()
    assert "STDERR" in log_map.stderr.read_text()
    assert "STDOUT" in log_map.stdout.read_text()


def test_report_06(tmp_path):
    """test minidump with Report._select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    with (tmp_path / "log_minidump_01.txt").open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|SIGSEGV|0x0|0\n")
        log_fp.write(b"minidump log\n")
    (tmp_path / "log_ffp_worker_blah.txt").write_bytes(b"worker log")
    log_map = Report._select_logs(tmp_path)
    assert log_map
    assert log_map.stderr.is_file()
    assert log_map.stdout.is_file()
    assert "minidump log" in log_map.aux.read_text()


def test_report_07(tmp_path):
    """test selecting preferred DUMP_REQUESTED minidump with Report._select_logs()"""
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
        log_fp.write(
            b"0|0|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|"
            b"bar.cc:234|674|0xc\n"
        )
        log_fp.write(
            b"0|1|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|"
            b"bar.cc:4a2|645|0x8\n"
        )
    with (tmp_path / "log_minidump_03.txt").open("wb") as log_fp:
        log_fp.write(b"GPU|||\n")
        log_fp.write(b"Crash|DUMP_REQUESTED|0x7f9518665d18|0\n")
        log_fp.write(b"0|0|bar.so|sadf|a.cc:1234|3066|0x0\n")
        log_fp.write(b"0|1|gar.so|fdsa|b.cc:4323|1644|0x12\n")
    log_map = Report._select_logs(tmp_path)
    assert log_map
    assert log_map.stderr.is_file()
    assert log_map.stdout.is_file()
    assert "google_breakpad::ExceptionHandler::WriteMinidump" in log_map.aux.read_text()


def test_report_08(tmp_path):
    """test selecting worker logs with Report._select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    (tmp_path / "log_ffp_worker_1.txt").write_bytes(b"worker log")
    # we should only ever see one but if we see multiple we warn, so test that.
    (tmp_path / "log_ffp_worker_2.txt").write_bytes(b"worker log")
    log_map = Report._select_logs(tmp_path)
    assert log_map
    assert log_map.stderr.is_file()
    assert log_map.stdout.is_file()
    assert "worker log" in log_map.aux.read_text()


def test_report_09(tmp_path):
    """test prioritizing sanitizer logs with Report._find_sanitizer()"""
    # NOTE: ordered by selection priority in order to use previously added logs
    # test empty
    (tmp_path / "log_asan.txt.0").touch()
    assert Report._find_sanitizer(list(tmp_path.iterdir())) is None
    # test *San log with data
    (tmp_path / "log_asan.txt.1").write_text("test")
    selected = Report._find_sanitizer(list(tmp_path.iterdir()))
    assert selected is not None
    assert "test" in selected.read_text()
    # test UBSan log
    (tmp_path / "log_asan.txt.1").write_text(
        "test.cc:3:5: runtime error: signed integer overflow: ..."
    )
    selected = Report._find_sanitizer(list(tmp_path.iterdir()))
    assert selected is not None
    assert "runtime error: signed integer overflow" in selected.read_text()
    # test selecting ASan report
    with (tmp_path / "log_asan.txt.2").open("wb") as log_fp:
        # missing stack
        log_fp.write(b"==1184==ERROR: AddressSanitizer: BUS on ... blah\n")
    with (tmp_path / "log_asan.txt.3").open("wb") as log_fp:
        log_fp.write(b"==9482==ERROR: AddressSanitizer: stack-overflow on ...\n")
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % (l_no,))
    selected = Report._find_sanitizer(list(tmp_path.iterdir()))
    assert selected is not None
    assert "AddressSanitizer: stack-overflow" in selected.read_text()
    # test selecting prioritized
    with (tmp_path / "log_asan.txt.4").open("wb") as log_fp:
        log_fp.write(
            b"==1942==ERROR: AddressSanitizer: heap-use-after-free on ... blah\n"
        )
        for l_no in range(4):
            log_fp.write(b"    #%d blah...\n" % (l_no,))
    with (tmp_path / "log_asan.txt.5").open("wb") as log_fp:
        log_fp.write(b"==1984==ERROR: AddressSanitizer: SEGV on ... blah\n")
        log_fp.write(b"missing trace...\n")
    with (tmp_path / "log_asan.txt.6").open("wb") as log_fp:
        log_fp.write(b"ERROR: Failed to mmap\n")
    selected = Report._find_sanitizer(list(tmp_path.iterdir()))
    assert selected is not None
    assert "heap-use-after-free" in selected.read_text()
    # test selecting TSan reports
    tsan_path = tmp_path / "tsan"
    tsan_path.mkdir()
    (tsan_path / "log_asan_benign.txt").write_text(
        "==27531==WARNING: Symbolizer buffer too small\n"
        "==27531==WARNING: Symbolizer buffer too small"
    )
    tsan_report = tsan_path / "log_asan_report.txt"
    tsan_report.write_text(
        "WARNING: ThreadSanitizer: data race (pid=26919)\n"
        "  Write of size 8 at 0x7f0ca2fc3400 by thread T51:\n"
        "    #0 memcpy /sanitizer_common_interceptors.inc:810:5 (lib+0x6656e)\n"
    )
    selected = Report._find_sanitizer(list(tsan_path.iterdir()))
    assert selected is not None
    assert selected == tsan_report


def test_report_10(tmp_path):
    """test Report() size_limit"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log\n" * 200)
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log\n" * 200)
    (tmp_path / "unrelated.txt").write_bytes(b"nothing burger\n" * 200)
    (tmp_path / "rr-trace").mkdir()
    size_limit = len("STDERR log\n")
    report = Report(tmp_path, Path("bin"), size_limit=size_limit)
    assert report.path == tmp_path
    assert report._logs
    assert report._logs.aux is None
    assert report._logs.stderr.name == "log_stderr.txt"
    assert report._logs.stdout.name == "log_stdout.txt"
    assert report.preferred.name == "log_stderr.txt"
    assert report.stack is None
    size_limit += len("[LOG TAILED]\n")
    assert report._logs.stderr.stat().st_size == size_limit
    assert report._logs.stdout.stat().st_size == size_limit
    assert (tmp_path / "unrelated.txt").stat().st_size == size_limit
    report.cleanup()
    assert not tmp_path.is_dir()


def test_report_11(tmp_path):
    """test selecting Valgrind logs with Report._select_logs()"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    (tmp_path / "log_valgrind.txt").write_bytes(b"valgrind log")
    log_map = Report._select_logs(tmp_path)
    assert log_map
    assert log_map.stderr.is_file()
    assert log_map.stdout.is_file()
    assert "valgrind log" in log_map.aux.read_text()


def test_report_12(tmp_path):
    """test Report.crash_info"""
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    # no binary.fuzzmanagerconf
    report = Report(tmp_path, Path("bin"))
    assert report._crash_info is None
    assert report.crash_info is not None
    assert report._crash_info is not None
    assert report._crash_info.configuration.product == "bin"
    # with binary.fuzzmanagerconf
    with (tmp_path / "bin.fuzzmanagerconf").open("wb") as conf:
        conf.write(b"[Main]\n")
        conf.write(b"platform = x86-64\n")
        conf.write(b"product = grizzly-test\n")
        conf.write(b"os = linux\n")
    report = Report(tmp_path, Path("bin"))
    report._target_binary = tmp_path / "bin"
    assert report._crash_info is None
    assert report.crash_info is not None
    assert report._crash_info is not None
    assert report._crash_info.configuration.product == "grizzly-test"


def test_report_13(mocker, tmp_path):
    """test Report.crash_info with unparsable log"""
    crash_info = mocker.patch("grizzly.common.report.CrashInfo", autospec=True)
    crash_info.fromRawCrashData.side_effect = TraceParsingError(line_no=0)
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    with raises(TraceParsingError):
        # pylint: disable=expression-not-assigned
        Report(tmp_path, Path("bin")).crash_info


@mark.parametrize(
    "sig_cache, has_sig",
    [
        # signature exists in cache
        ('{"symptoms": [{"functionNames": ["a"],"type": "stackFrames"}]}', True),
        # no signature
        (None, True),
        # FM failed to generate signature
        (None, False),
    ],
)
def test_report_14(mocker, tmp_path, sig_cache, has_sig):
    """test Report.crash_signature and Report.crash_hash"""
    mocker.patch("grizzly.common.report.ProgramConfiguration", autospec=True)
    collector = mocker.patch("grizzly.common.report.Collector", autospec=True)
    if sig_cache:
        sig_file = tmp_path / "cache.sig"
        sig_file.write_text(sig_cache)
        collector.return_value.search.return_value = (str(sig_file), None)
        collector.return_value.sigCacheDir = str(tmp_path)
    else:
        collector.return_value.sigCacheDir = None
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    if has_sig:
        _create_crash_log(tmp_path / "log_asan_blah.txt")
    report = Report(tmp_path, Path("bin"))
    assert report._signature is None
    if has_sig:
        assert report.crash_signature
        assert report.crash_info.createShortSignature() == "[@ foo]"
    else:
        assert not report.crash_signature
    assert report.crash_hash


@mark.parametrize(
    "backtrace, lines",
    [
        # baseline
        ((), 5),
        # not ignored
        (("1",), 5),
        # ignore frame
        (("std::panicking::rust_panic",), 6),
        # ignore frame
        (("alloc::alloc",), 6),
        # ignore frame and other frames
        (("1", "std::panicking::rust_panic", "3"), 6),
        # ignored frames is last ignorable frame
        (("1", "2", "3", "4", "std::panicking::rust_panic", "6"), 6),
        # ignored frames is too deep
        (("1", "2", "3", "4", "5", "std::panicking::rust_panic"), 5),
    ],
)
def test_report_15(mocker, backtrace, lines):
    """test Report.crash_signature_max_frames()"""
    info = mocker.Mock(spec=CrashInfo, backtrace=backtrace)
    assert Report.crash_signature_max_frames(info, suggested_frames=5) == lines


@mark.parametrize(
    "data, lines",
    [
        # simple log
        ("test", 1),
        # simple log
        ("a\nb", 2),
        # empty log
        ("", 0),
        # log with bad chars
        ("a\n\0", 2),
    ],
)
def test_report_16(tmp_path, data, lines):
    """test Report._load_log()"""
    log = tmp_path / "test-log.txt"
    log.write_text(data)
    assert len(Report._load_log(log)) == lines


@mark.parametrize(
    "hang, has_log, expected",
    [
        # process log and create short signature
        (False, True, "[@ foo]"),
        # no log available to create short signature
        (False, False, "Signature creation failed"),
        # result is a hang
        (True, True, "Potential hang detected"),
    ],
)
def test_report_17(mocker, tmp_path, hang, has_log, expected):
    """test Report.short_signature"""
    mocker.patch("grizzly.common.report.ProgramConfiguration", autospec=True)
    collector = mocker.patch("grizzly.common.report.Collector", autospec=True)
    # prevent checking signature cache (if it exists)
    collector.return_value.sigCacheDir = None
    (tmp_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (tmp_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    if has_log:
        _create_crash_log(tmp_path / "log_asan_blah.txt")
    report = Report(tmp_path, Path("bin"), is_hang=hang)
    assert report.short_signature == expected
    if hang:
        assert report.crash_hash == "hang"
