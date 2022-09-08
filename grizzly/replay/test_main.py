# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
unit tests for grizzly.replay.main
"""
from pytest import mark

from sapphire import Served

from ..common.reporter import Report
from ..common.storage import TestCase, TestCaseLoadFailure
from ..common.utils import Exit
from ..target import (
    AssetManager,
    Result,
    Target,
    TargetLaunchError,
    TargetLaunchTimeout,
)
from .replay import ReplayManager
from .test_replay import _fake_save_logs

pytestmark = mark.usefixtures(
    "patch_collector", "tmp_path_grz_tmp", "tmp_path_replay_status_db"
)


def test_main_01(mocker, tmp_path):
    """test ReplayManager.main()"""
    # This is a typical scenario - a test that reproduces results ~50% of the time.
    # Of the four attempts only the first and third will 'reproduce' the result
    # and the forth attempt should be skipped.
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    # mock Sapphire.serve_path only
    serve_path = mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path",
        autospec=True,
        return_value=(Served.ALL, ["test.html"]),  # passed to Target.check_result
    )
    # setup Target
    load_target = mocker.patch("grizzly.replay.replay.load_plugin", autospec=True)
    target = mocker.Mock(spec_set=Target, binary="bin", environ={}, launch_timeout=30)
    target.assets = mocker.Mock(spec_set=AssetManager)
    target.check_result.side_effect = (Result.FOUND, Result.NONE, Result.FOUND)
    target.filtered_environ.return_value = {"ENV": "123"}
    target.save_logs = _fake_save_logs
    load_target.return_value.return_value = target
    with TestCase("test.html", None, "adpt") as src:
        src.env_vars["TEST_VAR"] = "100"
        src.add_from_bytes(b"test", "test.html")
        src.dump(str(tmp_path / "testcase"), include_details=True)
    # setup args
    log_path = tmp_path / "logs"
    (tmp_path / "sig.json").write_bytes(
        b'{"symptoms": [{"type": "crashAddress", "address": "0"}]}'
    )
    args = mocker.Mock(
        any_crash=False,
        asset=list(),
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["fake", "timeout"],
        input=str(tmp_path / "testcase"),
        launch_attempts=3,
        logs=log_path,
        min_crashes=2,
        no_harness=False,
        pernosco=False,
        post_launch_delay=None,
        relaunch=1,
        repeat=4,
        rr=False,
        sig=str(tmp_path / "sig.json"),
        test_index=None,
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    assert ReplayManager.main(args) == Exit.SUCCESS
    assert target.reverse.call_count == 1
    assert target.launch.call_count == 3
    assert target.check_result.call_count == 3
    assert "TEST_VAR" in target.environ
    assert serve_path.call_count == 3
    assert load_target.call_count == 1
    assert target.close.call_count == 4
    assert target.filtered_environ.call_count == 2
    assert target.cleanup.call_count == 1
    assert target.assets.add.call_count == 0
    assert target.assets.is_empty.call_count == 1
    assert log_path.is_dir()
    assert any(log_path.glob("reports/*/log_asan_blah.txt"))
    assert any(log_path.glob("reports/*/log_stderr.txt"))
    assert any(log_path.glob("reports/*/log_stdout.txt"))


def test_main_02(mocker, tmp_path):
    """test ReplayManager.main() - no repro"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    # mock Sapphire.serve_path only
    mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path",
        autospec=True,
        return_value=(Served.ALL, ["test.html"]),  # passed to Target.check_result
    )
    # setup Target
    load_target = mocker.patch("grizzly.replay.replay.load_plugin")
    target = mocker.Mock(spec_set=Target, binary="bin", environ={}, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    load_target.return_value.return_value = target
    # setup args
    (tmp_path / "test.html").touch()
    args = mocker.Mock(
        asset=list(),
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["fake", "timeout"],
        input=str(tmp_path / "test.html"),
        launch_attempts=3,
        min_crashes=2,
        no_harness=True,
        pernosco=False,
        post_launch_delay=None,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=None,
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    assert ReplayManager.main(args) == Exit.FAILURE
    assert target.check_result.call_count == 1
    assert not target.environ
    assert target.close.call_count == 2
    assert target.cleanup.call_count == 1


def test_main_03(mocker):
    """test ReplayManager.main() error cases"""
    fake_sig = mocker.patch("grizzly.replay.replay.CrashSignature", autospec=True)
    mocker.patch("grizzly.replay.replay.FuzzManagerReporter", autospec=True)
    fake_load_target = mocker.patch("grizzly.replay.replay.load_plugin", autospec=True)
    mocker.patch("grizzly.replay.replay.Sapphire", autospec=True)
    fake_tc = mocker.patch("grizzly.replay.replay.TestCase", autospec=True)
    # setup args
    args = mocker.Mock(
        asset=list(),
        ignore=list(),
        input="test",
        min_crashes=1,
        no_harness=True,
        pernosco=False,
        post_launch_delay=None,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=None,
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    # user abort
    fake_load_target.side_effect = KeyboardInterrupt
    assert ReplayManager.main(args) == Exit.ABORT
    fake_load_target.reset_mock()
    # invalid test case
    fake_tc.load.side_effect = TestCaseLoadFailure
    assert ReplayManager.main(args) == Exit.ERROR
    assert fake_load_target.call_count == 0
    # no test cases
    fake_tc.load.side_effect = None
    fake_tc.load.return_value = list()
    assert ReplayManager.main(args) == Exit.ERROR
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()
    # multiple test cases with --no-harness
    fake_tc.load.return_value = [
        mocker.Mock(spec_set=TestCase, env_vars={}, hang=False) for _ in range(2)
    ]
    assert ReplayManager.main(args) == Exit.ARGS
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()
    # signature required replaying hang
    fake_tc.load.return_value = [mocker.Mock(spec_set=TestCase, env_vars={}, hang=True)]
    assert ReplayManager.main(args) == Exit.ERROR
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()
    # can't ignore timeout replaying hang
    args.ignore = ["timeout"]
    args.sig = "sig"
    fake_tc.load.return_value = [mocker.Mock(spec_set=TestCase, env_vars={}, hang=True)]
    assert ReplayManager.main(args) == Exit.ERROR
    assert fake_sig.fromFile.call_count == 1
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()


def test_main_04(mocker, tmp_path):
    """test ReplayManager.main() target exceptions"""
    mocker.patch("grizzly.replay.replay.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.replay.replay.Sapphire", autospec=True)
    mocker.patch("grizzly.replay.replay.TestCase", autospec=True)
    target = mocker.NonCallableMock(spec_set=Target, launch_timeout=30)
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(spec_set=Target, return_value=target),
    )
    fake_tmp = tmp_path / "grz_tmp"
    fake_tmp.mkdir()
    mocker.patch(
        "grizzly.replay.replay.grz_tmp", autospec=True, return_value=str(fake_tmp)
    )
    # setup args
    args = mocker.Mock(
        asset=list(),
        ignore=list(),
        input="test",
        min_crashes=1,
        no_harness=True,
        post_launch_delay=None,
        pernosco=False,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=None,
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    # target launch error
    fake_logs = tmp_path / "fake_report"
    fake_logs.mkdir()
    report = mocker.Mock(spec_set=Report, prefix="fake_report", path=str(fake_logs))
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.run",
        side_effect=TargetLaunchError("", report),
    )
    assert ReplayManager.main(args) == Exit.LAUNCH_FAILURE
    assert not fake_logs.is_dir()
    assert "fake_report_logs" in (x.name for x in fake_tmp.iterdir())
    # target launch timeout
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.run", side_effect=TargetLaunchTimeout
    )
    assert ReplayManager.main(args) == Exit.LAUNCH_FAILURE


def test_main_05(mocker, tmp_path):
    """test ReplayManager.main() loading specified assets"""
    serve_path = mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path",
        autospec=True,
        return_value=(None, ["test.html"]),  # passed to Target.check_result
    )
    # setup Target
    target = mocker.NonCallableMock(spec_set=Target, binary="bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.filtered_environ.return_value = dict()
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(spec_set=Target, return_value=target),
    )
    asset = tmp_path / "sample_asset"
    asset.touch()
    # setup args
    args = mocker.Mock(
        asset=[["from_cmdline", str(asset)]],
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=list(),
        launch_attempts=3,
        min_crashes=1,
        no_harness=True,
        pernosco=False,
        post_launch_delay=None,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=None,
        time_limit=1,
        timeout=None,
        valgrind=False,
    )
    log_path = tmp_path / "logs"
    args.logs = log_path
    input_path = tmp_path / "input"
    input_path.mkdir()
    # build a test case
    entry_point = input_path / "test.html"
    entry_point.touch()
    with TestCase("test.html", None, "test-adapter") as src:
        src.add_from_file(str(entry_point))
        src.dump(str(input_path), include_details=True)
    args.input = str(input_path)
    with AssetManager(base_path=str(tmp_path)) as assets:
        target.assets = assets
        assert ReplayManager.main(args) == Exit.SUCCESS
        assert "from_cmdline" in target.assets.assets
    assert target.launch.call_count == 1
    assert target.check_result.call_count == 1
    assert target.filtered_environ.call_count == 1
    assert serve_path.call_count == 1
    assert log_path.is_dir()
    assert any(log_path.glob("**/sample_asset"))


@mark.parametrize(
    "arg_timelimit, arg_timeout, test_timelimit, result",
    [
        # use default test time limit and timeout values (test missing time limit)
        (None, None, None, Exit.FAILURE),
        # use min test time limit and default timeout values
        (None, None, 1, Exit.FAILURE),
        # set test time limit
        (10, None, None, Exit.FAILURE),
        # set both test time limit and timeout to the same value
        (10, 10, None, Exit.FAILURE),
        # set timeout greater than test time limit
        (10, 11, None, Exit.FAILURE),
        # set test time limit greater than timeout
        (11, 10, None, Exit.ARGS),
    ],
)
def test_main_06(mocker, tmp_path, arg_timelimit, arg_timeout, test_timelimit, result):
    """test ReplayManager.main() - test time limit and timeout"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    # mock Sapphire.serve_path only
    mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path",
        autospec=True,
        return_value=(Served.ALL, ["test.html"]),  # passed to Target.check_result
    )
    # setup Target
    target = mocker.NonCallableMock(spec_set=Target, binary="bin", launch_timeout=30)
    target.check_result.return_value = Result.NONE
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(spec_set=Target, return_value=target),
    )
    # create test to load
    with TestCase("test.html", None, None) as test:
        test_file = tmp_path / "test.html"
        test_file.write_text("test")
        test.add_from_file(str(test_file))
        replay_path = tmp_path / "test"
        replay_path.mkdir()
        test.time_limit = test_timelimit
        test.dump(str(replay_path), include_details=True)
    # setup args
    args = mocker.Mock(
        asset=list(),
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["timeout"],
        input=str(replay_path),
        launch_attempts=3,
        min_crashes=2,
        no_harness=True,
        pernosco=False,
        post_launch_delay=None,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=None,
        time_limit=arg_timelimit,
        timeout=arg_timeout,
        valgrind=False,
    )
    assert ReplayManager.main(args) == result


@mark.parametrize(
    "pernosco, rr, valgrind, no_harness",
    [
        # No debugger enabled and no harness
        (False, False, False, False),
        # No debugger enabled and with harness
        (False, False, False, True),
        # Pernosco enabled
        (True, False, False, False),
        # rr enabled
        (False, True, False, False),
        # Valgrind enabled
        (False, False, True, False),
    ],  # pylint: disable=invalid-name
)
def test_main_07(mocker, tmp_path, pernosco, rr, valgrind, no_harness):
    """test ReplayManager.main() enable debuggers"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    # mock Sapphire.serve_path only
    mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path",
        autospec=True,
        return_value=(Served.ALL, ["test.html"]),  # passed to Target.check_result
    )
    # setup Target
    target = mocker.NonCallableMock(spec_set=Target, binary="bin", launch_timeout=30)
    target.check_result.return_value = Result.NONE
    load_target = mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(spec_set=Target, return_value=target),
    )
    # setup args
    (tmp_path / "test.html").touch()
    args = mocker.Mock(
        asset=list(),
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["fake", "timeout"],
        input=str(tmp_path / "test.html"),
        launch_attempts=3,
        min_crashes=2,
        no_harness=no_harness,
        pernosco=pernosco,
        post_launch_delay=None,
        relaunch=1,
        repeat=1,
        rr=rr,
        sig=None,
        test_index=None,
        time_limit=10,
        timeout=None,
        valgrind=valgrind,
    )
    # maximum one debugger allowed at a time
    assert sum((pernosco, rr, valgrind)) < 2, "test broken!"
    assert ReplayManager.main(args) == Exit.FAILURE
    assert target.check_result.call_count == 1
    assert target.close.call_count == 2
    assert target.cleanup.call_count == 1
    assert load_target.return_value.call_args[-1]["pernosco"] == pernosco
    assert load_target.return_value.call_args[-1]["rr"] == rr
    assert load_target.return_value.call_args[-1]["valgrind"] == valgrind
