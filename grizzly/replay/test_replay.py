# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.ReplayManager
"""
import os

from sapphire import Sapphire, SERVED_ALL
from .replay import ReplayManager
from ..common import Report, TestCase
from ..target import Target


def _fake_save_logs_result(result_logs, meta=False):  # pylint: disable=unused-argument
    """write fake log data to disk"""
    with open(os.path.join(result_logs, "log_stderr.txt"), "w") as log_fp:
        log_fp.write("STDERR log\n")
    with open(os.path.join(result_logs, "log_stdout.txt"), "w") as log_fp:
        log_fp.write("STDOUT log\n")
    with open(os.path.join(result_logs, "log_asan_blah.txt"), "w") as log_fp:
        log_fp.write("==1==ERROR: AddressSanitizer: ")
        log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")

def test_replay_01(mocker):
    """test ReplayManager.cleanup()"""
    replay = ReplayManager([], mocker.Mock(spec=Sapphire), mocker.Mock(spec=Target), mocker.Mock())
    replay._reports_expected = {"A":  mocker.Mock(spec=Report)}
    replay._reports_other = {"B":  mocker.Mock(spec=Report)}
    ereport = tuple(replay.reports)[0]
    oreport = tuple(replay.other_reports)[0]
    replay.cleanup()
    assert ereport.cleanup.call_count == 1
    assert oreport.cleanup.call_count == 1

def test_replay_02(mocker):
    """test ReplayManager.run() - no repro"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.port = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_NONE = Target.RESULT_NONE
    target.closed = True
    target.detect_failure.return_value = Target.RESULT_NONE
    target.forced_close = True
    target.rl_reset = 1
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"
    replay = ReplayManager(ignore, server, target, testcase, use_harness=True)
    assert not replay.run()
    assert replay.status.ignored == 0
    assert replay.status.iteration == 1
    assert replay.status.results == 0
    assert not replay.reports

def test_replay_03(mocker):
    """test ReplayManager.run() - successful repro"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.port = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.save_logs = _fake_save_logs_result
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"
    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    assert replay.run()
    assert replay.status.ignored == 0
    assert replay.status.iteration == 1
    assert replay.status.results == 1
    assert len(replay.reports) == 1
    assert not replay.other_reports
    replay.cleanup()

def test_replay_04(mocker):
    """test ReplayManager.run() - ignored"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.port = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.detect_failure.return_value = Target.RESULT_IGNORED
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"
    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    assert not replay.run()
    assert replay.status.ignored == 1
    assert replay.status.iteration == 1
    assert replay.status.results == 0
    assert not replay.reports
    assert not replay.other_reports

def test_replay_05(mocker):
    """test ReplayManager.run() - early exit"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.port = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.RESULT_NONE = Target.RESULT_NONE
    target.save_logs = _fake_save_logs_result
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"
    # early failure
    target.detect_failure.side_effect = [Target.RESULT_FAILURE, Target.RESULT_IGNORED, Target.RESULT_NONE]
    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    assert not replay.run(repeat=4, min_results=3)
    assert replay.status.iteration == 3
    assert replay.status.results == 1
    assert replay.status.ignored == 1
    assert len(replay.reports) == 1
    replay.cleanup()
    # early success
    target.detect_failure.side_effect = [Target.RESULT_FAILURE, Target.RESULT_IGNORED, Target.RESULT_FAILURE]
    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    assert replay.run(repeat=4, min_results=2)
    assert replay.status.iteration == 3
    assert replay.status.results == 2
    assert replay.status.ignored == 1
    assert len(replay._reports_expected) == 1
    assert not replay._reports_other
    assert len(replay.reports) == 1
    replay.cleanup()

def test_replay_06(mocker, tmp_path):
    """test ReplayManager.run() - test signatures"""
    report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    mkdtemp = mocker.patch("grizzly.replay.replay.tempfile.mkdtemp", autospec=True)
    mkdtemp.return_value = str(tmp_path)
    report_0 = mocker.Mock(spec=Report)
    report_0.crash_info.return_value.createShortSignature.return_value = "No crash detected"
    report_1 = mocker.Mock(spec=Report)
    report_1.crash_info.return_value.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(spec=Report)
    report_2.crash_info.return_value.createShortSignature.return_value = "[@ test2]"
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
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"
    replay = ReplayManager([], server, target, testcase, signature=signature, use_harness=False)
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

def test_replay_07(mocker, tmp_path):
    """test ReplayManager.run() - any crash"""
    report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    mkdtemp = mocker.patch("grizzly.replay.replay.tempfile.mkdtemp", autospec=True)
    mkdtemp.return_value = str(tmp_path)
    report_0 = mocker.Mock(spec=Report)
    report_0.crash_info.return_value.createShortSignature.return_value = "No crash detected"
    report_1 = mocker.Mock(spec=Report)
    report_1.crash_info.return_value.createShortSignature.return_value = "[@ test1]"
    report_1.crash_hash.return_value = "hash1"
    report_2 = mocker.Mock(spec=Report)
    report_2.crash_info.return_value.createShortSignature.return_value = "[@ test2]"
    report_2.crash_hash.return_value = "hash2"
    report.from_path.side_effect = (report_0, report_1, report_2)
    server = mocker.Mock(spec=Sapphire)
    server.port = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.binary = "fake_bin"
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"
    replay = ReplayManager([], server, target, testcase, any_crash=True, use_harness=False)
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

def test_replay_08(mocker, tmp_path):
    """test ReplayManager.dump_reports()"""
    server = mocker.Mock(spec=Sapphire)
    server.port = 34567
    target = mocker.Mock(spec=Target)
    target.rl_reset = 10
    replay = ReplayManager(None, server, target, None, use_harness=False)
    # no reports
    replay.dump_reports(str(tmp_path))
    assert not any(tmp_path.glob("*"))
    # with reports
    path = tmp_path / "dest"
    replay._reports_expected["testhash"] = mocker.Mock(spec=Report)
    replay._reports_expected["testhash"].prefix = "expected"
    (tmp_path / "report_expected").mkdir()
    replay._reports_expected["testhash"].path = str(tmp_path / "report_expected")
    replay._reports_other["other1"] = mocker.Mock(spec=Report)
    replay._reports_other["other1"].prefix = "other1"
    (tmp_path / "report_other1").mkdir()
    replay._reports_other["other1"].path = str(tmp_path / "report_other1")
    replay._reports_other["other2"] = mocker.Mock(spec=Report)
    replay._reports_other["other2"].prefix = "other2"
    (tmp_path / "report_other2").mkdir()
    replay._reports_other["other2"].path = str(tmp_path / "report_other2")
    replay.dump_reports(str(path))
    assert not (tmp_path / "report_expected").is_dir()
    assert not (tmp_path / "report_other1").is_dir()
    assert not (tmp_path / "report_other2").is_dir()
    assert path.is_dir()
    assert (path / "reports").is_dir()
    assert (path / "reports" / "expected_logs").is_dir()
    assert (path / "other_reports").is_dir()
    assert (path / "other_reports" / "other1_logs").is_dir()
    assert (path / "other_reports" / "other2_logs").is_dir()
