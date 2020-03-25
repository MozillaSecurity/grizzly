# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.ReplayManager
"""

import pytest

from sapphire import Sapphire, SERVED_ALL
from .replay import ReplayManager
from ..common import Report, TestCase
from ..target import Target, TargetLaunchError, TargetLaunchTimeout


def test_replay_01(mocker):
    """test ReplayManager.run() - no repro"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 0x1337
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
    assert not any(replay.reports)

def test_replay_02(mocker):
    """test ReplayManager.run() - successful repro"""
    mocker.patch("grizzly.replay.replay.Report", autospec=True)
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"
    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    assert replay.run()
    assert replay.status.ignored == 0
    assert replay.status.iteration == 1
    assert replay.status.results == 1
    assert len([replay.reports]) == 1

def test_replay_03(mocker):
    """test ReplayManager.run() - ignored"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 0x1337
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
    assert not any(replay.reports)

def test_replay_04(mocker):
    """test ReplayManager.run() - early exit"""
    mocker.patch("grizzly.replay.replay.Report", autospec=True)
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 0x1337
    server.serve_testcase.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.RESULT_NONE = Target.RESULT_NONE
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
    assert len([replay.reports]) == 1
    # early success
    target.detect_failure.side_effect = [Target.RESULT_FAILURE, Target.RESULT_IGNORED, Target.RESULT_FAILURE]
    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    assert replay.run(repeat=4, min_results=2)
    assert replay.status.iteration == 3
    assert replay.status.results == 2
    assert replay.status.ignored == 1
    assert len(replay._reports_expected) == 1
    assert not replay._reports_other
    assert len([replay.reports]) == 1

def test_replay_05(mocker):
    """test ReplayManager.run() - test signatures"""
    report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    crash_info = mocker.Mock()
    crash_info.createShortSignature.side_effect = ("No crash detected", "[@ test]", "[@ test]")
    report.from_path.return_value.crash_info.return_value = crash_info
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 0x1337
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
    replay = ReplayManager(ignore, server, target, testcase, signature=signature, use_harness=False)
    assert not replay.run(repeat=3, min_results=2)
    assert replay.status.iteration == 3
    assert replay.status.results == 1
    assert replay.status.ignored == 1
    assert len(replay._reports_expected) == 1
    assert len(replay._reports_other) == 1
    assert len([replay.reports]) == 1
    assert signature.matches.call_count == 2

def test_replay_06(mocker):
    """test ReplayManager._launch()"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 0x1337
    target = mocker.Mock(spec=Target)
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"

    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    replay._launch()
    assert target.launch.call_count == 1
    target.reset_mock()

    target.launch.side_effect = TargetLaunchError
    with pytest.raises(TargetLaunchError):
        replay._launch()
    assert target.launch.call_count == 1
    target.reset_mock()

    target.launch.side_effect = TargetLaunchTimeout
    with pytest.raises(TargetLaunchTimeout):
        replay._launch(max_timeouts=3)
    assert target.launch.call_count == 3

def test_replay_07(mocker):
    """test ReplayManager._location()"""
    ignore = mocker.Mock(spec=list)
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 34567
    target = mocker.Mock(spec=Target)
    target.rl_reset = 10
    testcase = mocker.Mock(spec=TestCase)
    testcase.env_vars = dict()
    testcase.landing_page = "index.html"

    replay = ReplayManager(ignore, server, target, testcase, use_harness=False)
    assert replay._location() == "http://127.0.0.1:34567/index.html"

    target.forced_close = True
    replay = ReplayManager(ignore, server, target, testcase, use_harness=True)
    assert replay._location() == "http://127.0.0.1:34567/harness.html?close_after=10"

    target.forced_close = False
    replay = ReplayManager(ignore, server, target, testcase, use_harness=True)
    assert replay._location() == "http://127.0.0.1:34567/harness.html?close_after=10&forced_close=0"

    target.forced_close = True
    replay = ReplayManager(ignore, server, target, testcase, use_harness=True)
    assert replay._location(timeout=60) == "http://127.0.0.1:34567/harness.html?timeout=60000&close_after=10"

def test_replay_08(mocker, tmp_path):
    """test ReplayManager.dump_reports()"""
    server = mocker.Mock(spec=Sapphire)
    server.get_port.return_value = 34567
    target = mocker.Mock(spec=Target)
    target.rl_reset = 10

    replay = ReplayManager(None, server, target, None, use_harness=False)

    # no reports
    replay.dump_reports(str(tmp_path))
    assert not list(tmp_path.glob("*"))

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
