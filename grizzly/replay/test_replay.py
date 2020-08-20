# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.replay
"""
from os import walk
from os.path import isfile, join as pathjoin, relpath
from zipfile import ZIP_DEFLATED, ZipFile

from pytest import raises

from sapphire import Sapphire, SERVED_ALL, SERVED_REQUEST
from .replay import ReplayManager, TestCaseLoadFailure
from ..common import Report, Status, TestCase
from ..target import Target, TargetLaunchError


def _fake_save_logs_result(result_logs, meta=False):  # pylint: disable=unused-argument
    """write fake log data to disk"""
    with open(pathjoin(result_logs, "log_stderr.txt"), "w") as log_fp:
        log_fp.write("STDERR log\n")
    with open(pathjoin(result_logs, "log_stdout.txt"), "w") as log_fp:
        log_fp.write("STDOUT log\n")
    with open(pathjoin(result_logs, "log_asan_blah.txt"), "w") as log_fp:
        log_fp.write("==1==ERROR: AddressSanitizer: ")
        log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")

def test_replay_01(mocker):
    """test ReplayManager.cleanup()"""
    replay = ReplayManager([], mocker.Mock(spec=Sapphire), mocker.Mock(spec=Target), [mocker.Mock()])
    replay._reports_expected = {"A":  mocker.Mock(spec=Report)}
    replay._reports_other = {"B":  mocker.Mock(spec=Report)}
    replay.status = mocker.Mock(spec=Status)
    ereport = tuple(replay.reports)[0]
    oreport = tuple(replay.other_reports)[0]
    replay.cleanup()
    assert ereport.cleanup.call_count == 1
    assert oreport.cleanup.call_count == 1
    assert replay.status.cleanup.call_count == 1

def test_replay_02(mocker):
    """test ReplayManager.run() - no repro"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_NONE = Target.RESULT_NONE
    target.closed = True
    target.detect_failure.return_value = Target.RESULT_NONE
    target.forced_close = True
    target.rl_reset = 1
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, use_harness=True) as replay:
        assert not replay.run()
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 0
        assert not replay.reports

def test_replay_03(mocker):
    """test ReplayManager.run() - successful repro"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.binary = "C:\\fake_bin"
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.save_logs = _fake_save_logs_result
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, use_harness=False) as replay:
        assert replay.run()
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 1
        assert len(replay.reports) == 1
        assert not replay.other_reports

def test_replay_04(mocker):
    """test ReplayManager.run() - Error (landing page not requested/served)"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_REQUEST, ["x"])
    target = mocker.Mock(spec=Target)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, use_harness=False) as replay:
        assert not replay.run(repeat=2)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 0
        assert not replay.reports
        assert not replay.other_reports
    assert target.check_relaunch.call_count == 0

def test_replay_05(mocker):
    """test ReplayManager.run() - ignored"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.detect_failure.return_value = Target.RESULT_IGNORED
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, use_harness=False) as replay:
        assert not replay.run()
        assert replay.status.ignored == 1
        assert replay.status.iteration == 1
        assert replay.status.results == 0
        assert not replay.reports
        assert not replay.other_reports

def test_replay_06(mocker):
    """test ReplayManager.run() - early exit"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.RESULT_NONE = Target.RESULT_NONE
    target.binary = "path/fake_bin"
    target.save_logs = _fake_save_logs_result
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    # early failure
    target.detect_failure.side_effect = [Target.RESULT_FAILURE, Target.RESULT_IGNORED, Target.RESULT_NONE]
    with ReplayManager([], server, target, testcases, use_harness=False) as replay:
        assert not replay.run(repeat=4, min_results=3)
        assert replay.status.iteration == 3
        assert replay.status.results == 1
        assert replay.status.ignored == 1
        assert len(replay.reports) == 1
    # early success
    target.detect_failure.side_effect = [Target.RESULT_FAILURE, Target.RESULT_IGNORED, Target.RESULT_FAILURE]
    with ReplayManager([], server, target, testcases, use_harness=False) as replay:
        assert replay.run(repeat=4, min_results=2)
        assert replay.status.iteration == 3
        assert replay.status.results == 2
        assert replay.status.ignored == 1
        assert len(replay._reports_expected) == 1
        assert not replay._reports_other
        assert len(replay.reports) == 1

def test_replay_07(mocker, tmp_path):
    """test ReplayManager.run() - test signatures"""
    report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_0 = mocker.Mock(spec=Report)
    report_0.crash_info.return_value.createShortSignature.return_value = "No crash detected"
    report_1 = mocker.Mock(spec=Report)
    report_1.crash_info.return_value.createShortSignature.return_value = "[@ test1]"
    report_1.major = "0123abcd"
    report_1.minor = "01239999"
    report_2 = mocker.Mock(spec=Report)
    report_2.crash_info.return_value.createShortSignature.return_value = "[@ test2]"
    report_2.major = "0123abcd"
    report_2.minor = "abcd9876"
    report.from_path.side_effect = (report_0, report_1, report_2)
    server = mocker.Mock(spec=Sapphire)
    server.port = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    signature = mocker.Mock()
    signature.matches.side_effect = (True, False)
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.binary = "fake_bin"
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, signature=signature, use_harness=False) as replay:
        assert not replay.run(repeat=3, min_results=2)
        assert replay._signature == signature
        assert report.from_path.call_count == 3
        assert replay.status.iteration == 3
        assert replay.status.results == 1
        assert replay.status.ignored == 1
        assert len(replay.reports) == 1
        assert len(replay.other_reports) == 1
        assert report_0.cleanup.call_count == 1
        assert report_1.cleanup.call_count == 0
        assert report_2.cleanup.call_count == 0
    assert signature.matches.call_count == 2

def test_replay_08(mocker, tmp_path):
    """test ReplayManager.run() - any crash"""
    report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_0 = mocker.Mock(spec=Report)
    report_0.crash_info.return_value.createShortSignature.return_value = "No crash detected"
    report_1 = mocker.Mock(spec=Report)
    report_1.crash_info.return_value.createShortSignature.return_value = "[@ test1]"
    report_1.crash_hash.return_value = "hash1"
    report_1.major = "0123abcd"
    report_1.minor = "01239999"
    report_2 = mocker.Mock(spec=Report)
    report_2.crash_info.return_value.createShortSignature.return_value = "[@ test2]"
    report_2.crash_hash.return_value = "hash2"
    report_2.major = "0123abcd"
    report_2.minor = "abcd9876"
    report.from_path.side_effect = (report_0, report_1, report_2)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.binary = "fake_bin"
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, any_crash=True, use_harness=False) as replay:
        assert replay.run(repeat=3, min_results=2)
        assert replay._signature is None
        assert report.from_path.call_count == 3
        assert replay.status.iteration == 3
        assert replay.status.results == 2
        assert replay.status.ignored == 0
        assert report_1.crash_hash.call_count == 1
        assert report_2.crash_hash.call_count == 1
        assert len(replay.reports) == 2
        assert not replay.other_reports
        assert report_0.cleanup.call_count == 1
        assert report_1.cleanup.call_count == 0
        assert report_2.cleanup.call_count == 0

def test_replay_09(mocker, tmp_path):
    """test ReplayManager.report_to_filesystem()"""
    # no reports
    ReplayManager.report_to_filesystem(str(tmp_path), [])
    assert not any(tmp_path.glob("*"))
    # with reports
    reports_expected = list()
    reports_expected.append(mocker.Mock(spec=Report))
    reports_expected[-1].prefix = "expected"
    (tmp_path / "report_expected").mkdir()
    reports_expected[-1].path = str(tmp_path / "report_expected")
    reports_other = list()
    reports_other.append(mocker.Mock(spec=Report))
    reports_other[-1].prefix = "other1"
    (tmp_path / "report_other1").mkdir()
    reports_other[-1].path = str(tmp_path / "report_other1")
    reports_other.append(mocker.Mock(spec=Report))
    reports_other[-1].prefix = "other2"
    (tmp_path / "report_other2").mkdir()
    reports_other[-1].path = str(tmp_path / "report_other2")
    test = mocker.Mock(spec=TestCase)
    path = tmp_path / "dest"
    ReplayManager.report_to_filesystem(str(path), reports_expected, reports_other, tests=[test])
    assert test.dump.call_count == 3  # called once per report
    assert not (tmp_path / "report_expected").is_dir()
    assert not (tmp_path / "report_other1").is_dir()
    assert not (tmp_path / "report_other2").is_dir()
    assert path.is_dir()
    assert (path / "reports").is_dir()
    assert (path / "reports" / "expected_logs").is_dir()
    assert (path / "other_reports").is_dir()
    assert (path / "other_reports" / "other1_logs").is_dir()
    assert (path / "other_reports" / "other2_logs").is_dir()

def test_replay_10(mocker, tmp_path):
    """test ReplayManager.run() - TargetLaunchError"""
    report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report.from_path.side_effect = (mocker.Mock(spec=Report),)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target)
    target.launch.side_effect = TargetLaunchError
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, use_harness=False) as replay:
        with raises(TargetLaunchError):
            replay.run()
        assert not any(replay.reports)
        assert any(replay.other_reports)
        assert "STARTUP" in replay._reports_other

def test_replay_11(mocker):
    """test ReplayManager.run() - multiple TestCases - no repro"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_NONE = Target.RESULT_NONE
    target.closed = True
    target.detect_failure.return_value = Target.RESULT_NONE
    target.forced_close = True
    target.rl_reset = 1
    testcases = [
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html"),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html"),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, use_harness=True) as replay:
        assert not replay.run()
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 0
        assert not replay.reports

def test_replay_12(mocker):
    """test ReplayManager.run() - multiple TestCases - successful repro"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, binary="fake_bin", rl_reset=1)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.side_effect = (
        Target.RESULT_NONE,
        Target.RESULT_NONE,
        Target.RESULT_FAILURE)
    target.save_logs = _fake_save_logs_result
    testcases = [
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html"),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html"),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html")]
    with ReplayManager([], server, target, testcases, use_harness=True) as replay:
        assert replay.run()
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 1
        assert len(replay.reports) == 1
        assert not replay.other_reports

def test_replay_13(tmp_path):
    """test ReplayManager.load_testcases() - error cases"""
    # test missing
    with raises(TestCaseLoadFailure, match="Cannot find"):
        ReplayManager.load_testcases("missing", False)
    # test empty path
    with raises(TestCaseLoadFailure, match="Missing 'test_info.json'"):
        ReplayManager.load_testcases(str(tmp_path), False)
    # test broken archive
    archive = (tmp_path / "fake.zip")
    archive.write_bytes(b"x")
    with raises(TestCaseLoadFailure, match="Testcase archive is corrupted"):
        ReplayManager.load_testcases(str(archive), False)

def test_replay_14(tmp_path):
    """test ReplayManager.load_testcases() - single file"""
    tfile = (tmp_path / "testcase.html")
    tfile.touch()
    testcases, unpacked = ReplayManager.load_testcases(str(tfile), False)
    try:
        assert unpacked is None
        assert len(tuple(testcases)) == 1
    finally:
        map(lambda x: x.cleanup, testcases)

def test_replay_15(tmp_path):
    """test ReplayManager.load_testcases() - single directory"""
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_data("test", "target.bin")
        src.dump(str(tmp_path), include_details=True)
    testcases, unpacked = ReplayManager.load_testcases(str(tmp_path), False)
    try:
        assert unpacked is None
        assert len(tuple(testcases)) == 1
    finally:
        map(lambda x: x.cleanup, testcases)

def test_replay_16(tmp_path):
    """test ReplayManager.load_testcases() - archive"""
    # build archive containing multiple testcases
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_data("test", "target.bin")
        src.dump(str(tmp_path / "src-0"), include_details=True)
        src.dump(str(tmp_path / "src-1"), include_details=True)
        src.dump(str(tmp_path / "src-2"), include_details=True)
    (tmp_path / "src-1" / "prefs.js").write_bytes(b"fake_prefs")
    (tmp_path / "log_dummy.txt").touch()
    (tmp_path / "not_a_tc").mkdir()
    (tmp_path / "not_a_tc" / "file.txt").touch()
    archive = str(tmp_path / "testcase.zip")
    with ZipFile(archive, mode="w", compression=ZIP_DEFLATED) as zfp:
        for dir_name, _, dir_files in walk(str(tmp_path)):
            arc_path = relpath(dir_name, str(tmp_path))
            for file_name in dir_files:
                zfp.write(
                    pathjoin(dir_name, file_name),
                    arcname=pathjoin(arc_path, file_name))
    testcases, unpacked = ReplayManager.load_testcases(str(archive), True)
    try:
        assert unpacked is not None
        assert isfile(pathjoin(unpacked, "prefs.js"))
        assert len(tuple(testcases)) == 3
    finally:
        map(lambda x: x.cleanup, testcases)
    # empty archive
    with ZipFile(archive, mode="w", compression=ZIP_DEFLATED) as zfp:
        zfp.write(str(tmp_path / "not_a_tc"), arcname="not_a_tc")
    with raises(TestCaseLoadFailure, match="Failed to load TestCases"):
        ReplayManager.load_testcases(str(archive), True)
