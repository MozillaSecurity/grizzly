# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Unit tests for `grizzly.reduce.main`."""
from pytest import mark, raises

from ..common.storage import TestCase, TestCaseLoadFailure
from ..common.utils import ConfigError, Exit
from ..target import AssetManager, Target, TargetLaunchError, TargetLaunchTimeout
from . import ReduceManager
from .args import ReduceArgs, ReduceFuzzManagerIDArgs, ReduceFuzzManagerIDQualityArgs
from .exceptions import GrizzlyReduceBaseException

pytestmark = mark.usefixtures("tmp_path_status_db_reduce")


def test_args_01(capsys, tmp_path, mocker):
    """test args in common with grizzly.replay"""
    # pylint: disable=import-outside-toplevel
    from ..replay.test_args import test_replay_args_01 as real_test

    mocker.patch("grizzly.replay.test_args.ReplayArgs", new=ReduceArgs)
    real_test(capsys, mocker, tmp_path)


def test_args_02(capsys, tmp_path):
    """test parsing args specific to grizzly.reduce"""
    exe = tmp_path / "binary"
    exe.touch()
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "somefile").touch()

    # test valid strategy
    ReduceArgs().parse_args([str(exe), str(inp), "--strategy", "lines"])
    # test invalid strategy
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--strategy", "cosmic_radiation"])
    assert (
        "error: argument --strategy: invalid choice: 'cosmic_radiation'"
        in capsys.readouterr()[-1]
    )
    # test no-analysis
    ReduceArgs().parse_args(
        [str(exe), str(inp), "--no-analysis", "--repeat", "99", "--min-crashes", "99"]
    )
    # test multiple inputs
    ReduceArgs().parse_args([str(exe), str(inp), str(inp)])
    # test no-harness
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), str(inp), "--no-harness"])
    assert (
        "error: '--no-harness' cannot be used with multiple testcases"
        in capsys.readouterr()[-1]
    )
    # these should both log a warning that the args will be ignored due to analysis
    ReduceArgs().parse_args([str(exe), str(inp), "--repeat", "99"])
    ReduceArgs().parse_args([str(exe), str(inp), "--min-crashes", "99"])
    ReduceArgs().parse_args([str(exe), str(inp), "--report-period", "99"])
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--report-period", "0"])
    assert "error: Invalid --report-period" in capsys.readouterr()[-1]
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--report-period", "15"])
    assert "error: Very short --report-period" in capsys.readouterr()[-1]


def test_args_03(tmp_path, capsys):
    """test ReduceFuzzManagerIDArgs"""
    exe = tmp_path / "binary"
    exe.touch()
    ReduceFuzzManagerIDArgs().parse_args([str(exe), "123"])
    # error cases
    with raises(SystemExit):
        ReduceFuzzManagerIDArgs().parse_args(
            [str(exe), "123", "--no-harness", "--test-index", "0", "1"]
        )
    assert (
        "error: '--test-index' only supports a single value with '--no-harness'"
        in capsys.readouterr()[-1]
    )


def test_args_04(tmp_path):
    """test ReduceFuzzManagerIDQualityArgs"""
    exe = tmp_path / "binary"
    exe.touch()
    ReduceFuzzManagerIDQualityArgs().parse_args([str(exe), "123"])


@mark.parametrize(
    "patch_func, side_effect, return_value, kwargs, exit_code, use_sig",
    [
        (
            "grizzly.reduce.core.ReduceManager.run",
            TargetLaunchError("error", None),
            None,
            {},
            Exit.LAUNCH_FAILURE,
            False,
        ),
        (
            "grizzly.reduce.core.ReduceManager.run",
            TargetLaunchTimeout,
            None,
            {},
            Exit.LAUNCH_FAILURE,
            False,
        ),
        (
            "grizzly.reduce.core.load_plugin",
            KeyboardInterrupt,
            None,
            {},
            Exit.ABORT,
            True,
        ),
        (
            "grizzly.reduce.core.load_plugin",
            GrizzlyReduceBaseException("", 999),
            None,
            {},
            999,
            False,
        ),
        (
            "grizzly.reduce.core.ReplayManager.load_testcases",
            TestCaseLoadFailure,
            None,
            {},
            Exit.ERROR,
            False,
        ),
        (
            "grizzly.reduce.core.ReplayManager.load_testcases",
            ConfigError("", 999),
            None,
            {"no_harness": False},
            999,
            False,
        ),
        (
            "grizzly.reduce.core.ReplayManager.load_testcases",
            RuntimeError,
            None,
            {},
            Exit.ERROR,
            False,
        ),
    ],
)
def test_main_exit(
    mocker, tmp_path, patch_func, side_effect, return_value, kwargs, exit_code, use_sig
):
    """test ReduceManager.main() failure cases"""
    mocker.patch("grizzly.reduce.core.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.reduce.core.load_plugin", autospec=True)
    mocker.patch("grizzly.reduce.core.ReductionStatus", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)

    if use_sig:
        sig = tmp_path / "fake.sig"
        sig.write_text('{"symptoms": [{"address": "0", "type": "crashAddress"}]}')
        sig.with_suffix(".metadata").write_text('{"shortDescription": "foo"}')
    else:
        sig = None

    (tmp_path / "test.html").touch()
    # setup args
    args = mocker.Mock(
        ignore=["fake"],
        input=[tmp_path / "test.html"],
        min_crashes=1,
        relaunch=1,
        repeat=1,
        sig=sig,
        test_index=[],
        timeout=10,
        **kwargs
    )

    mocker.patch(patch_func, side_effect=side_effect, return_value=return_value)
    assert ReduceManager.main(args) == exit_code


@mark.parametrize(
    "exc_type",
    [
        TargetLaunchError,
        TargetLaunchTimeout,
    ],
)
def test_main_launch_error(mocker, exc_type):
    mocker.patch("grizzly.reduce.core.ReductionStatus", autospec=True)
    mocker.patch("grizzly.reduce.core.FuzzManagerReporter", autospec=True)
    reporter = mocker.patch("grizzly.reduce.core.FailedLaunchReporter", autospec=True)
    mocker.patch("grizzly.reduce.core.load_plugin", autospec=True)
    mocker.patch(
        "grizzly.reduce.core.ReplayManager.load_testcases",
        return_value=(
            [mocker.Mock(spec_set=TestCase, hang=False, adapter_name="fake")],
            None,
            {},
        ),
    )
    mocker.patch("grizzly.reduce.core.time_limits", return_value=(None, 10))
    run = mocker.patch("grizzly.reduce.core.ReduceManager.run", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    # setup args
    args = mocker.Mock(
        ignore=["fake"],
        input=["test"],
        min_crashes=1,
        no_harness=False,
        relaunch=1,
        repeat=1,
        sig=None,
        tool=None,
    )

    exc_obj = exc_type(
        "error", mocker.Mock() if exc_type is TargetLaunchError else None
    )
    run.side_effect = exc_obj
    assert ReduceManager.main(args) == 4
    if exc_type is TargetLaunchError:
        assert reporter.return_value.submit.call_count == 1
        reported_testcases, report = reporter.return_value.submit.call_args[0]
        assert reported_testcases == []
        assert report is exc_obj.report
    else:
        assert reporter.return_value.submit.call_count == 0


@mark.parametrize("https_supported", [True, False])
def test_main_https_support(mocker, tmp_path, https_supported):
    """test ReduceManager.main() - Target HTTPS support"""
    mocker.patch("grizzly.reduce.core.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.reduce.core.ReduceManager.run", autospec=True, return_value=0)
    mocker.patch("grizzly.reduce.core.ReductionStatus", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    (tmp_path / "test.html").touch()
    # setup args
    args = mocker.Mock(
        ignore=["fake"],
        input=[tmp_path / "test.html"],
        min_crashes=1,
        relaunch=1,
        repeat=1,
        sig=None,
        test_index=[],
        use_http=False,
        time_limit=1,
        timeout=1,
    )

    target_cls = mocker.MagicMock(spec_set=Target)
    target = target_cls.return_value
    target.https.return_value = https_supported
    mocker.patch("grizzly.reduce.core.load_plugin", return_value=target_cls)
    assert ReduceManager.main(args) == 0
    assert target.https.call_count == 1


def test_main_load_assets_and_env(mocker, tmp_path):
    """test ReduceManager.main() - Use assets and env vars from loaded TestCase"""
    asset_mgr = mocker.Mock(spec_set=AssetManager)
    mocker.patch(
        "grizzly.reduce.core.ReplayManager.load_testcases",
        autospec=True,
        return_value=([], asset_mgr, {"FOO_ENV": "123"}),
    )
    mocker.patch("grizzly.reduce.core.ReduceManager.run", autospec=True, return_value=0)
    mocker.patch("grizzly.reduce.core.ReductionStatus", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    (tmp_path / "test.html").touch()
    # setup args
    args = mocker.Mock(
        ignore=["fake"],
        input=[tmp_path / "test.html"],
        min_crashes=1,
        relaunch=1,
        repeat=1,
        sig=None,
        test_index=[],
        time_limit=1,
        timeout=1,
    )

    target = mocker.Mock(spec_set=Target)
    target_cls = mocker.MagicMock(spec_set=Target, return_value=target)
    mocker.patch("grizzly.reduce.core.load_plugin", return_value=target_cls)
    assert ReduceManager.main(args) == 0
    assert target.merge_environment.call_count == 1
    assert target.merge_environment.call_args.args == ({"FOO_ENV": "123"},)
    assert asset_mgr.add_batch.call_count == 1
    # this should not be called since the AssetManager was given to the target
    # and the target is a mock
    assert asset_mgr.cleanup.call_count == 0
