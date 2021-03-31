# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.replay.main
"""
from shutil import rmtree

from pytest import mark

from sapphire import SERVED_ALL

from ..common import Report, TestCase, TestCaseLoadFailure
from ..session import Session
from ..target import Target, TargetLaunchError, TargetLaunchTimeout
from .replay import ReplayManager
from .test_replay import _fake_save_logs


def test_main_01(mocker, tmp_path):
    """test ReplayManager.main()"""
    # This is a typical scenario - a test that reproduces results ~50% of the time.
    # Of the four attempts only the first and third will 'reproduce' the result
    # and the forth attempt should be skipped.
    # mock Sapphire.serve_path only
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    serve_path = mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path", autospec=True
    )
    serve_path.return_value = (
        SERVED_ALL,
        ["test.html"],
    )  # passed to mocked Target.detect_failure
    # setup Target
    load_target = mocker.patch("grizzly.replay.replay.load_plugin")
    target = mocker.Mock(spec=Target, binary="bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.side_effect = (
        Target.RESULT_FAILURE,
        Target.RESULT_NONE,
        Target.RESULT_FAILURE,
    )
    target.save_logs = _fake_save_logs
    load_target.return_value.return_value = target
    # setup args
    log_path = tmp_path / "logs"
    (tmp_path / "test.html").touch()
    (tmp_path / "prefs.js").touch()
    (tmp_path / "sig.json").write_bytes(
        b'{"symptoms": [{"type": "crashAddress", "address": "0"}]}'
    )
    args = mocker.Mock(
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["fake", "timeout"],
        input=str(tmp_path / "test.html"),
        logs=str(log_path),
        min_crashes=2,
        no_harness=True,
        prefs=str(tmp_path / "prefs.js"),
        relaunch=1,
        repeat=4,
        rr=False,
        sig=str(tmp_path / "sig.json"),
        test_index=None,
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    assert ReplayManager.main(args) == Session.EXIT_SUCCESS
    assert target.reverse.call_count == 1
    assert target.launch.call_count == 3
    assert target.detect_failure.call_count == 3
    assert serve_path.call_count == 3
    assert load_target.call_count == 1
    assert target.close.call_count == 4
    assert target.cleanup.call_count == 1
    assert log_path.is_dir()
    assert any(log_path.glob("reports/*/log_asan_blah.txt"))
    assert any(log_path.glob("reports/*/log_stderr.txt"))
    assert any(log_path.glob("reports/*/log_stdout.txt"))


def test_main_02(mocker, tmp_path):
    """test ReplayManager.main() - no repro"""
    # mock Sapphire.serve_path only
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    serve_path = mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path", autospec=True
    )
    serve_path.return_value = (
        SERVED_ALL,
        ["test.html"],
    )  # passed to mocked Target.detect_failure
    # setup Target
    load_target = mocker.patch("grizzly.replay.replay.load_plugin")
    target = mocker.Mock(spec=Target, binary="bin", launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    load_target.return_value.return_value = target
    # setup args
    (tmp_path / "test.html").touch()
    (tmp_path / "prefs.js").touch()
    args = mocker.Mock(
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["fake", "timeout"],
        input=str(tmp_path / "test.html"),
        min_crashes=2,
        no_harness=True,
        prefs=None,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=None,
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    assert ReplayManager.main(args) == Session.EXIT_FAILURE
    assert target.detect_failure.call_count == 1
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
        ignore=list(),
        input="test",
        min_crashes=1,
        no_harenss=True,
        prefs=None,
        relaunch=1,
        repeat=1,
        sig=None,
        test_index=None,
        time_limit=10,
        timeout=None,
    )
    # user abort
    fake_load_target.side_effect = KeyboardInterrupt
    # coverage
    args.rr = True
    args.valgrind = False
    assert ReplayManager.main(args) == Session.EXIT_ABORT
    fake_load_target.reset_mock()
    # invalid test case
    fake_tc.load.side_effect = TestCaseLoadFailure
    # coverage
    args.rr = False
    args.valgrind = True
    assert ReplayManager.main(args) == Session.EXIT_ERROR
    assert fake_load_target.call_count == 0
    # no test cases
    args.valgrind = False
    fake_tc.load.side_effect = None
    fake_tc.load.return_value = list()
    assert ReplayManager.main(args) == Session.EXIT_ERROR
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()
    # multiple test cases with --no-harness
    fake_tc.load.return_value = [mocker.Mock(hang=False), mocker.Mock(hang=False)]
    assert ReplayManager.main(args) == Session.EXIT_ARGS
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()
    # signature required replaying hang
    fake_tc.load.return_value = [mocker.Mock(hang=True)]
    assert ReplayManager.main(args) == Session.EXIT_ERROR
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()
    # can't ignore timeout replaying hang
    args.ignore = ["timeout"]
    args.sig = "sig"
    fake_tc.load.return_value = [mocker.Mock(hang=True)]
    assert ReplayManager.main(args) == Session.EXIT_ERROR
    assert fake_sig.fromFile.call_count == 1
    assert fake_load_target.call_count == 0
    fake_load_target.reset_mock()


def test_main_04(mocker, tmp_path):
    """test ReplayManager.main() target exceptions"""
    mocker.patch("grizzly.replay.replay.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.replay.replay.Sapphire", autospec=True)
    mocker.patch("grizzly.replay.replay.TestCase", autospec=True)
    target = mocker.Mock(spec=Target, launch_timeout=30)
    load_target = mocker.patch("grizzly.replay.replay.load_plugin", autospec=True)
    load_target.return_value.return_value = target
    fake_tmp = tmp_path / "grz_tmp"
    fake_tmp.mkdir()
    mocker.patch(
        "grizzly.replay.replay.grz_tmp", autospec=True, return_value=str(fake_tmp)
    )
    # setup args
    args = mocker.Mock(
        ignore=list(),
        input="test",
        min_crashes=1,
        no_harenss=True,
        prefs=None,
        relaunch=1,
        repeat=1,
        sig=None,
        test_index=None,
        time_limit=10,
        timeout=None,
    )
    # target launch error
    fake_logs = tmp_path / "fake_report"
    fake_logs.mkdir()
    report = mocker.Mock(spec=Report, prefix="fake_report", path=str(fake_logs))
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.run",
        side_effect=TargetLaunchError("", report),
    )
    assert ReplayManager.main(args) == Session.EXIT_LAUNCH_FAILURE
    assert not fake_logs.is_dir()
    assert "fake_report_logs" in (x.name for x in fake_tmp.iterdir())
    # target launch timeout
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.run", side_effect=TargetLaunchTimeout
    )
    assert ReplayManager.main(args) == Session.EXIT_LAUNCH_FAILURE


def test_main_05(mocker, tmp_path):
    """test ReplayManager.main() loading/generating prefs.js"""
    serve_path = mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path", autospec=True
    )
    serve_path.return_value = (
        None,
        ["test.html"],
    )  # passed to mocked Target.detect_failure
    # setup Target
    target = mocker.Mock(spec=Target, binary="bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    load_target = mocker.patch("grizzly.replay.replay.load_plugin")
    load_target.return_value.return_value = target
    # setup args
    args = mocker.Mock(
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=list(),
        min_crashes=1,
        no_harness=True,
        relaunch=1,
        repeat=1,
        sig=None,
        test_index=None,
        time_limit=1,
        timeout=None,
    )
    log_path = tmp_path / "logs"
    args.logs = str(log_path)
    input_path = tmp_path / "input"
    input_path.mkdir()
    # build a test case
    entry_point = input_path / "test.html"
    entry_point.touch()
    with TestCase("test.html", None, "test-adapter") as src:
        src.add_from_file(str(entry_point))
        src.dump(str(input_path), include_details=True)
    args.input = str(input_path)

    # test no specified prefs.js
    args.prefs = None
    assert ReplayManager.main(args) == Session.EXIT_SUCCESS
    assert target.launch.call_count == 1
    assert target.detect_failure.call_count == 1
    assert serve_path.call_count == 1
    assert log_path.is_dir()
    assert not any(log_path.glob("**/prefs.js"))

    target.reset_mock()
    serve_path.reset_mock()
    rmtree(str(log_path), ignore_errors=True)

    # test included prefs.js
    (input_path / "prefs.js").write_bytes(b"included")
    assert ReplayManager.main(args) == Session.EXIT_SUCCESS
    assert target.launch.call_count == 1
    assert target.detect_failure.call_count == 1
    assert serve_path.call_count == 1
    assert log_path.is_dir()
    prefs = next(log_path.glob("**/prefs.js"))
    assert prefs.read_bytes() == b"included"

    target.reset_mock()
    serve_path.reset_mock()
    rmtree(str(log_path), ignore_errors=True)

    # test specified prefs.js
    (tmp_path / "prefs.js").write_bytes(b"specified")
    args.prefs = str(tmp_path / "prefs.js")
    assert ReplayManager.main(args) == Session.EXIT_SUCCESS
    assert target.launch.call_count == 1
    assert target.detect_failure.call_count == 1
    assert serve_path.call_count == 1
    assert log_path.is_dir()
    prefs = next(log_path.glob("**/prefs.js"))
    assert prefs.read_bytes() == b"specified"


@mark.parametrize(
    "arg_timelimit, arg_timeout, test_timelimit, result",
    [
        # use default test time limit and timeout values (test missing time limit)
        (None, None, None, Session.EXIT_FAILURE),
        # use min test time limit and default timeout values
        (None, None, 1, Session.EXIT_FAILURE),
        # set test time limit
        (10, None, None, Session.EXIT_FAILURE),
        # set both test time limit and timeout to the same value
        (10, 10, None, Session.EXIT_FAILURE),
        # set timeout greater than test time limit
        (10, 11, None, Session.EXIT_FAILURE),
        # set test time limit greater than timeout
        (11, 10, None, Session.EXIT_ARGS),
    ],
)
def test_main_06(mocker, tmp_path, arg_timelimit, arg_timeout, test_timelimit, result):
    """test ReplayManager.main() - test time limit and timeout"""
    # mock Sapphire.serve_path only
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    serve_path = mocker.patch(
        "grizzly.replay.replay.Sapphire.serve_path", autospec=True
    )
    serve_path.return_value = (
        SERVED_ALL,
        ["test.html"],
    )  # passed to mocked Target.detect_failure
    # setup Target
    target = mocker.Mock(spec=Target, binary="bin", launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    load_target = mocker.patch("grizzly.replay.replay.load_plugin")
    load_target.return_value.return_value = target
    # create test to load
    test = TestCase("test.html", None, None)
    test_file = tmp_path / "test.html"
    test_file.write_text("test")
    test.add_from_file(str(test_file))
    replay_path = tmp_path / "test"
    replay_path.mkdir()
    test.time_limit = test_timelimit
    test.dump(str(replay_path), include_details=True)
    # setup args
    (tmp_path / "prefs.js").touch()
    args = mocker.Mock(
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["timeout"],
        input=str(replay_path),
        min_crashes=2,
        no_harness=True,
        prefs=None,
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
