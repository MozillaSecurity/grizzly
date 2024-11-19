# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
unit tests for grizzly.replay.main
"""
from pathlib import Path
from unittest.mock import Mock

from pytest import mark

from sapphire import Served

from ..common.report import Report
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
    "patch_collector",
    "tmp_path_grz_tmp",
)


def test_main_01(mocker, server, tmp_path):
    """test ReplayManager.main()"""
    # This is a typical scenario - a test that reproduces results ~50% of the time.
    # Of the four attempts only the first and third will 'reproduce' the result
    # and the forth attempt should be skipped.
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server.serve_path.return_value = (Served.ALL, {"test.html": "/fake/path"})
    # setup Target
    load_target = mocker.patch("grizzly.replay.replay.load_plugin", autospec=True)
    target = mocker.Mock(
        spec_set=Target, binary=Path("bin"), environ={}, launch_timeout=30
    )
    target.asset_mgr = mocker.Mock(spec_set=AssetManager)
    target.check_result.side_effect = (Result.FOUND, Result.NONE, Result.FOUND)
    target.filtered_environ.return_value = {"ENV": "123"}
    target.save_logs = _fake_save_logs
    load_target.return_value.return_value = target
    with TestCase("test.html", "adpt") as src:
        src.env_vars["TEST_VAR"] = "100"
        src.add_from_bytes(b"test", src.entry_point)
        src.dump(tmp_path / "testcase", include_details=True)
    # setup args
    log_path = tmp_path / "logs"
    (tmp_path / "sig.json").write_bytes(
        b'{"symptoms": [{"type": "crashAddress", "address": "0"}]}'
    )
    args = mocker.Mock(
        any_crash=False,
        asset=[],
        entry_point=None,
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["fake", "timeout"],
        input=[tmp_path / "testcase"],
        launch_attempts=3,
        min_crashes=2,
        no_harness=False,
        output=log_path,
        pernosco=False,
        post_launch_delay=0,
        relaunch=1,
        repeat=4,
        rr=False,
        sig=tmp_path / "sig.json",
        test_index=[],
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    assert ReplayManager.main(args) == Exit.SUCCESS
    assert target.reverse.call_count == 1
    assert target.launch.call_count == 3
    assert target.check_result.call_count == 3
    assert target.merge_environment.call_count == 1
    assert server.serve_path.call_count == 6
    assert load_target.call_count == 1
    assert target.close.call_count == 4
    assert target.filtered_environ.call_count == 2
    assert target.cleanup.call_count == 1
    assert target.asset_mgr.add.call_count == 0
    assert target.asset_mgr.is_empty.call_count == 1
    assert log_path.is_dir()
    assert any(log_path.glob("reports/*/log_asan_blah.txt"))
    assert any(log_path.glob("reports/*/log_stderr.txt"))
    assert any(log_path.glob("reports/*/log_stdout.txt"))


@mark.parametrize(
    "repro_results,",
    [
        # no results
        (Result.NONE, Result.NONE),
        # results do not match signature
        (Result.FOUND, Result.FOUND),
        # no result and failed signature match
        (Result.FOUND, Result.NONE),
    ],
)
def test_main_02(mocker, server, tmp_path, repro_results):
    """test ReplayManager.main() - no repro"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server.serve_path.return_value = (Served.ALL, {"test.html": "/fake/path"})
    # setup Target
    target = mocker.Mock(
        spec_set=Target, binary=Path("bin"), environ={}, launch_timeout=30
    )
    target.check_result.side_effect = repro_results
    target.filtered_environ.return_value = {}
    target.save_logs = _fake_save_logs
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(spec=Target, return_value=target),
    )
    (tmp_path / "sig.json").write_bytes(
        b'{"symptoms": [{"type": "stackFrames", "functionNames": ["no-match"]}]}'
    )
    # setup args
    (tmp_path / "test.html").touch()
    args = mocker.Mock(
        any_crash=False,
        asset=[],
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=[],
        input=[tmp_path / "test.html"],
        launch_attempts=3,
        min_crashes=2,
        no_harness=True,
        output=tmp_path / "logs",
        pernosco=False,
        post_launch_delay=-1,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=tmp_path / "sig.json",
        test_index=[],
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    assert ReplayManager.main(args) == Exit.FAILURE
    assert target.check_result.call_count == 1
    assert not target.environ
    assert target.close.call_count == 2
    assert target.cleanup.call_count == 1


@mark.parametrize(
    "load_plugin, load_testcases, signature, result",
    [
        # failed to load test cases
        (None, TestCaseLoadFailure("test"), None, Exit.ERROR),
        # user abort
        (
            KeyboardInterrupt,
            ([Mock(spec_set=TestCase, hang=False)], None, None),
            None,
            Exit.ABORT,
        ),
        # signature required replaying hang
        (None, ([Mock(spec_set=TestCase)], None, None), None, Exit.ERROR),
        # can't ignore timeout replaying hang
        (None, ([Mock(spec_set=TestCase)], None, None), "sig", Exit.ERROR),
        # cleanup assets loaded from test case
        (
            KeyboardInterrupt,
            ([Mock(spec_set=TestCase, hang=False)], Mock(spec_set=AssetManager), None),
            None,
            Exit.ABORT,
        ),
    ],
)
def test_main_03(mocker, load_plugin, load_testcases, signature, result):
    """test ReplayManager.main() error cases"""
    mocker.patch("grizzly.replay.replay.Sapphire", autospec=True)
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        side_effect=load_plugin,
    )
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.load_testcases",
        autospec=True,
        side_effect=(load_testcases,),
    )
    fake_sig = mocker.patch("grizzly.replay.replay.CrashSignature", autospec=True)
    # setup args
    args = mocker.Mock(
        asset=[],
        fuzzmanager=False,
        ignore=["timeout"] if signature else [],
        input=["test"],
        min_crashes=1,
        pernosco=False,
        post_launch_delay=-1,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=signature,
        test_index=[],
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    asset_mgr = load_testcases[1] if isinstance(load_testcases, tuple) else None
    assert ReplayManager.main(args) == result
    if asset_mgr is not None:
        assert asset_mgr.cleanup.call_count == 1
    if signature:
        assert fake_sig.fromFile.call_count == 1


def test_main_04(mocker, tmp_path):
    """test ReplayManager.main() target exceptions"""
    mocker.patch("grizzly.replay.replay.FuzzManagerReporter", autospec=True)
    reporter = mocker.patch("grizzly.replay.replay.FailedLaunchReporter", autospec=True)
    mocker.patch("grizzly.replay.replay.Sapphire", autospec=True)
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(
            spec_set=Target,
            return_value=mocker.NonCallableMock(spec_set=Target, launch_timeout=30),
        ),
    )
    with TestCase("test.html", "adpt") as test:
        test.add_from_bytes(b"", test.entry_point)
        test.dump(tmp_path / "test", include_details=True)
    # setup args
    args = mocker.MagicMock(
        entry_point=None,
        input=[tmp_path / "test"],
        min_crashes=1,
        no_harness=True,
        post_launch_delay=-1,
        pernosco=False,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=[],
        time_limit=10,
        timeout=None,
        valgrind=False,
    )
    # target launch error
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.run",
        side_effect=TargetLaunchError("", mocker.Mock(spec_set=Report)),
    )
    assert ReplayManager.main(args) == Exit.LAUNCH_FAILURE
    assert reporter.return_value.submit.call_count == 1
    reporter.reset_mock()
    # target launch timeout
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.run", side_effect=TargetLaunchTimeout
    )
    assert ReplayManager.main(args) == Exit.LAUNCH_FAILURE
    assert reporter.return_value.submit.call_count == 0


def test_main_05(mocker, server, tmp_path):
    """test ReplayManager.main() loading specified assets"""
    server.serve_path.return_value = (None, {"test.html": "/fake/path"})
    # setup Target
    target = mocker.NonCallableMock(
        spec_set=Target, binary=Path("bin"), launch_timeout=30
    )
    target.check_result.return_value = Result.FOUND
    target.filtered_environ.return_value = {}
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(spec_set=Target, return_value=target),
    )
    asset = tmp_path / "sample_asset"
    asset.touch()
    input_path = tmp_path / "input"
    input_path.mkdir()
    log_path = tmp_path / "logs"
    # setup args
    args = mocker.Mock(
        asset=[["from_cmdline", str(asset)]],
        entry_point=None,
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=[],
        input=[input_path],
        launch_attempts=3,
        min_crashes=1,
        no_harness=True,
        output=log_path,
        pernosco=False,
        post_launch_delay=-1,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=[],
        time_limit=1,
        timeout=None,
        valgrind=False,
    )
    # build a test case
    with TestCase("test.html", "test-adapter") as src:
        src.add_from_bytes(b"test", src.entry_point)
        src.dump(input_path, include_details=True)
    with AssetManager(base_path=tmp_path) as asset_mgr:
        target.asset_mgr = asset_mgr
        assert ReplayManager.main(args) == Exit.SUCCESS
        assert "from_cmdline" in target.asset_mgr.assets
    assert target.launch.call_count == 1
    assert target.check_result.call_count == 1
    assert target.filtered_environ.call_count == 1
    assert server.serve_path.call_count == 1
    assert log_path.is_dir()
    assert any(log_path.glob("**/sample_asset"))


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
def test_main_06(
    mocker, server, tmp_path, pernosco, rr, valgrind, no_harness
):  # pylint: disable=invalid-name
    """test ReplayManager.main() enable debuggers"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server.serve_path.return_value = (Served.ALL, {"test.html": "/fake/path"})
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
        asset=[],
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        ignore=["fake", "timeout"],
        input=[tmp_path / "test.html"],
        launch_attempts=3,
        min_crashes=2,
        no_harness=no_harness,
        pernosco=pernosco,
        post_launch_delay=-1,
        relaunch=1,
        repeat=1,
        rr=rr,
        sig=None,
        test_index=[],
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


def test_main_07(mocker, server, tmp_path):
    """test ReplayManager.main() - report to FuzzManager"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server.serve_path.return_value = (Served.ALL, {"test.html": "/fake/path"})
    reporter = mocker.patch("grizzly.replay.replay.FuzzManagerReporter", autospec=True)
    # setup Target
    load_target = mocker.patch("grizzly.replay.replay.load_plugin", autospec=True)
    target = mocker.MagicMock(
        spec_set=Target, binary=Path("bin"), environ={}, launch_timeout=30
    )
    target.check_result.side_effect = (Result.FOUND,)
    target.save_logs = _fake_save_logs
    load_target.return_value.return_value = target
    with TestCase("test.html", "adpt") as src:
        src.add_from_bytes(b"test", src.entry_point)
        src.dump(tmp_path / "testcase", include_details=True)
    # setup args
    args = mocker.Mock(
        any_crash=False,
        asset=[],
        entry_point=None,
        fuzzmanager=True,
        idle_delay=0,
        idle_threshold=0,
        ignore=[],
        input=[tmp_path / "testcase"],
        launch_attempts=1,
        min_crashes=1,
        no_harness=False,
        output=None,
        pernosco=False,
        post_launch_delay=-1,
        relaunch=1,
        repeat=1,
        rr=False,
        sig=None,
        test_index=[],
        time_limit=10,
        timeout=None,
        tool=None,
        valgrind=False,
    )
    assert ReplayManager.main(args) == Exit.SUCCESS
    assert target.reverse.call_count == 1
    assert target.launch.call_count == 1
    assert target.check_result.call_count == 1
    assert server.serve_path.call_count == 1
    assert load_target.call_count == 1
    assert target.close.call_count == 2
    assert target.cleanup.call_count == 1
    assert reporter.return_value.submit.call_count == 1


@mark.parametrize("https_supported", [True, False])
def test_main_08(mocker, tmp_path, https_supported):
    """test ReplayManager.main() - Target HTTPS support"""
    (tmp_path / "test.html").touch()
    args = mocker.MagicMock(
        adapter="fake",
        binary=Path("bin"),
        input=[tmp_path / "test.html"],
        fuzzmanager=False,
        launch_attempts=1,
        min_crashes=1,
        relaunch=1,
        repeat=1,
        sig=None,
        use_http=False,
        time_limit=1,
        timeout=1,
    )

    target_cls = mocker.MagicMock(spec_set=Target)
    target = target_cls.return_value
    target.https.return_value = https_supported
    mocker.patch("grizzly.replay.replay.load_plugin", return_value=target_cls)
    mocker.patch("grizzly.replay.replay.ReplayManager.run", return_value=[])
    assert ReplayManager.main(args) == Exit.FAILURE
    assert target.https.call_count == 1


def test_main_09(mocker, server, tmp_path):
    """test ReplayManager.main() - load test case assets"""
    server.serve_path.return_value = (None, {"test.html": "/fake/path"})
    # setup Target
    target = mocker.NonCallableMock(
        spec_set=Target, binary=Path("bin"), launch_timeout=30
    )
    target.check_result.return_value = Result.NONE
    target.monitor.is_healthy.return_value = False
    mocker.patch(
        "grizzly.replay.replay.load_plugin",
        autospec=True,
        return_value=mocker.Mock(spec_set=Target, return_value=target),
    )
    # setup args
    input_path = tmp_path / "input"
    input_path.mkdir()
    args = mocker.MagicMock(
        adapter="fake",
        binary=Path("bin"),
        entry_point=None,
        fuzzmanager=False,
        idle_delay=0,
        idle_threshold=0,
        input=[input_path],
        launch_attempts=1,
        min_crashes=1,
        output=None,
        post_launch_delay=-1,
        relaunch=1,
        repeat=1,
        sig=None,
        use_http=False,
        test_index=[],
        time_limit=1,
        timeout=1,
    )
    # build test case and asset
    asset = tmp_path / "sample_asset"
    asset.touch()
    with AssetManager(base_path=tmp_path) as asset_mgr:
        asset_mgr.add("sample", asset)
        with TestCase("test.html", "test-adapter") as src:
            src.assets = asset_mgr.assets
            src.assets_path = asset_mgr.path
            src.add_from_bytes(b"", src.entry_point)
            src.dump(input_path, include_details=True)
    # this will load the previously created test case and asset from the filesystem
    try:
        assert ReplayManager.main(args) == Exit.FAILURE
        assert target.launch.call_count == 1
        assert "sample" in target.asset_mgr.assets
        assert target.asset_mgr.path is not None
    finally:
        if target.asset_mgr:
            target.asset_mgr.cleanup()
