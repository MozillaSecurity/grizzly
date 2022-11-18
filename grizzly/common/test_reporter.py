# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly Reporter"""
# pylint: disable=protected-access

from FTB.ProgramConfiguration import ProgramConfiguration
from pytest import mark, raises

from .report import Report
from .reporter import (
    FailedLaunchReporter,
    FilesystemReporter,
    FuzzManagerReporter,
    Reporter,
)
from .storage import TestCase


def _create_crash_log(log_path):
    with log_path.open("w") as log_fp:
        log_fp.write("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0")
        log_fp.write(" (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19")


@mark.parametrize(
    "display_logs, is_hang",
    [
        # do not display report
        (False, False),
        # display report
        (True, False),
        # display report (hang)
        (True, True),
    ],
)
def test_reporter_01(mocker, tmp_path, display_logs, is_hang):
    """test creating a simple Reporter"""

    class SimpleReporter(Reporter):
        def _pre_submit(self, report):
            pass

        def _post_submit(self):
            pass

        def _submit_report(self, report, test_cases):
            pass

    (tmp_path / "log_stderr.txt").write_bytes(b"log msg")
    report = mocker.Mock(
        spec_set=Report, is_hang=is_hang, preferred=tmp_path / "log_stderr.txt"
    )
    reporter = SimpleReporter()
    reporter.display_logs = display_logs
    reporter.submit([], report=report)
    assert report.cleanup.call_count == 1


def test_filesystem_reporter_01(tmp_path):
    """test FilesystemReporter without testcases"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    _create_crash_log(tmp_path / "log_asan_blah.txt")
    report_path = tmp_path / "reports"
    report_path.mkdir()
    reporter = FilesystemReporter(report_path)
    reporter.submit([], Report(log_path, "fake_bin"))
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
    tests = list(mocker.Mock(spec_set=TestCase) for _ in range(10))
    report_path = tmp_path / "reports"
    assert not report_path.exists()
    reporter = FilesystemReporter(report_path)
    reporter.submit(tests, Report(log_path, "fake_bin"))
    assert not log_path.exists()
    assert report_path.exists()
    assert len(tuple(report_path.iterdir())) == 1
    assert all(x.dump.call_count == 1 for x in tests)
    # call report a 2nd time
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    tests = list(mocker.Mock(spec_set=TestCase) for _ in range(2))
    reporter.submit(tests, Report(log_path, "fake_bin"))
    assert all(x.dump.call_count == 1 for x in tests)
    assert len(tuple(report_path.iterdir())) == 2
    assert len(tuple(report_path.glob("NO_STACK"))) == 1


def test_filesystem_reporter_03(tmp_path):
    """test FilesystemReporter disk space failsafe"""
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    reporter = FilesystemReporter(tmp_path / "reports")
    reporter.min_space = 2**50
    with raises(RuntimeError, match="Low disk space: "):
        reporter.submit([], Report(log_path, "fake_bin"))


def test_filesystem_reporter_04(mocker, tmp_path):
    """test FilesystemReporter w/o major bucket"""
    fake_report = tmp_path / "fake_report"
    fake_report.mkdir()
    report = mocker.Mock(spec_set=Report, path=fake_report, prefix="test_prefix")
    reporter = FilesystemReporter(tmp_path / "dst", major_bucket=False)
    reporter.submit([], report)
    assert not fake_report.is_dir()
    assert not report.major.call_count
    assert any((tmp_path / "dst").glob("test_prefix_logs"))


def test_fuzzmanager_reporter_01(mocker, tmp_path):
    """test FuzzManagerReporter.sanity_check()"""
    fake_reporter = mocker.patch("grizzly.common.reporter.ProgramConfiguration")
    fake_reporter.fromBinary.return_value = mocker.Mock(spec_set=ProgramConfiguration)
    # missing global FM config file
    FuzzManagerReporter.FM_CONFIG = tmp_path / "no_file"
    with raises(IOError, match="no_file"):
        FuzzManagerReporter.sanity_check("fake")
    # missing binary FM config file
    fake_fmc = tmp_path / ".fuzzmanagerconf"
    fake_fmc.touch()
    fake_bin = tmp_path / "bin"
    fake_bin.touch()
    FuzzManagerReporter.FM_CONFIG = fake_fmc
    with raises(IOError, match="bin.fuzzmanagerconf"):
        FuzzManagerReporter.sanity_check(str(fake_bin))
    # success
    (tmp_path / "bin.fuzzmanagerconf").touch()
    FuzzManagerReporter.sanity_check(str(fake_bin))
    assert fake_reporter.fromBinary.call_count == 1


@mark.parametrize(
    "tests, frequent, ignored, force, sig_cache",
    [
        # report - without test
        (False, False, False, False, True),
        # report - with test
        (True, False, False, False, True),
        # report - frequent
        (True, True, False, False, True),
        # report - forced frequent
        (True, True, False, True, True),
        # report - ignored
        (True, False, True, False, True),
        # report - missing sigCacheDir
        (False, False, False, False, False),
    ],
)
def test_fuzzmanager_reporter_02(
    mocker, tmp_path, tests, frequent, ignored, force, sig_cache
):
    """test FuzzManagerReporter.submit()"""
    mocker.patch(
        "grizzly.common.reporter.FuzzManagerReporter._ignored",
        new_callable=mocker.MagicMock,
        return_value=ignored,
    )
    mocker.patch("grizzly.common.reporter.Path.cwd", return_value=tmp_path)
    mocker.patch("grizzly.common.reporter.getenv", autospec=True, return_value="0")
    fake_collector = mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    fake_collector.return_value.search.return_value = (
        None,
        {"frequent": frequent, "shortDescription": "[@ test]"},
    )
    fake_collector.return_value.sigCacheDir = str(tmp_path) if sig_cache else None
    log_path = tmp_path / "log_path"
    log_path.mkdir()
    (log_path / "log_ffp_worker_blah.txt").touch()
    (log_path / "log_stderr.txt").touch()
    (log_path / "log_stdout.txt").touch()
    (log_path / "rr-traces").mkdir()
    (tmp_path / "screenlog.0").touch()
    fake_test = mocker.Mock(
        spec_set=TestCase,
        adapter_name="adapter",
        env_vars={"TEST": "1"},
        input_fname="input",
    )
    test_cases = []
    if tests:
        test_cases.append(fake_test)
    reporter = FuzzManagerReporter("fake_bin")
    reporter.force_report = force
    reporter.submit(test_cases, Report(log_path, "fake_bin", is_hang=True))
    assert not log_path.is_dir()
    if (frequent and not force) or ignored:
        assert fake_collector.return_value.submit.call_count == 0
        assert fake_test.dump.call_count == 0
    else:
        assert fake_collector.return_value.submit.call_count == 1
        if tests:
            assert fake_test.dump.call_count == 1


def test_fuzzmanager_reporter_03(mocker, tmp_path):
    """test FuzzManagerReporter._ignored()"""
    log_file = tmp_path / "test.log"
    log_file.touch()
    report = mocker.Mock(spec_set=Report, path=tmp_path, preferred=log_file, stack=None)
    # not ignored
    assert not FuzzManagerReporter._ignored(report)
    # ignored - sanitizer OOM missing stack
    log_file.write_bytes(b"ERROR: Failed to mmap")
    assert FuzzManagerReporter._ignored(report)
    # ignored - Valgrind OOM
    log_file.write_bytes(b"VEX temporary storage exhausted.")
    assert FuzzManagerReporter._ignored(report)


def test_failed_launch_reporter_01(mocker, tmp_path):
    """test FailedLaunchReporter()"""
    gtp = tmp_path / "grizzly"
    gtp.mkdir()
    mocker.patch("grizzly.common.reporter.grz_tmp", autospec=True, return_value=gtp)
    report_path = tmp_path / "report"
    report_path.mkdir()
    (report_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (report_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    FailedLaunchReporter().submit([], Report(report_path, "fake_bin"))
    assert any(gtp.glob("*_logs"))
