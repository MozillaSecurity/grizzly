# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Unit tests for `grizzly.reduce.main`."""
from unittest.mock import Mock

from pytest import mark, raises

from ..common.storage import TestCase, TestCaseLoadFailure
from ..common.utils import Exit
from ..target import AssetManager, TargetLaunchError, TargetLaunchTimeout
from . import ReduceManager
from .args import ReduceArgs, ReduceFuzzManagerIDArgs, ReduceFuzzManagerIDQualityArgs
from .exceptions import GrizzlyReduceBaseException

pytestmark = mark.usefixtures(
    "tmp_path_fm_config",
    "tmp_path_replay_status_db",
    "tmp_path_reduce_status_db",
)


def test_args_01(capsys, tmp_path, mocker):
    """test args in common with grizzly.replay"""
    # pylint: disable=import-outside-toplevel
    from ..replay.test_args import test_replay_args_01 as real_test

    mocker.patch("grizzly.replay.test_args.ReplayArgs", new=ReduceArgs)
    real_test(capsys, mocker, tmp_path)


def test_args_02(tmp_path):
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
    # test no-analysis
    ReduceArgs().parse_args(
        [str(exe), str(inp), "--no-analysis", "--repeat", "99", "--min-crashes", "99"]
    )
    # these should both log a warning that the args will be ignored due to analysis
    ReduceArgs().parse_args([str(exe), str(inp), "--repeat", "99"])
    ReduceArgs().parse_args([str(exe), str(inp), "--min-crashes", "99"])
    ReduceArgs().parse_args([str(exe), str(inp), "--report-period", "99"])
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--report-period", "0"])
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--report-period", "15"])


def test_args_03(tmp_path):
    """test ReduceFuzzManagerIDArgs"""
    exe = tmp_path / "binary"
    exe.touch()
    ReduceFuzzManagerIDArgs().parse_args([str(exe), "123"])


def test_args_04(tmp_path):
    """test ReduceFuzzManagerIDQualityArgs"""
    exe = tmp_path / "binary"
    exe.touch()
    ReduceFuzzManagerIDQualityArgs().parse_args([str(exe), "123"])


@mark.parametrize(
    "patch_func, side_effect, return_value, kwargs, exit_code",
    [
        (
            "grizzly.reduce.core.ReduceManager.run",
            TargetLaunchError("error", None),
            None,
            {},
            Exit.ERROR,
        ),
        (
            "grizzly.reduce.core.ReduceManager.run",
            TargetLaunchTimeout,
            None,
            {},
            Exit.ERROR,
        ),
        ("grizzly.reduce.core.load_plugin", KeyboardInterrupt, None, {}, Exit.ERROR),
        (
            "grizzly.reduce.core.load_plugin",
            GrizzlyReduceBaseException(""),
            None,
            {},
            Exit.ERROR,
        ),
        (
            "grizzly.reduce.core.ReplayManager.load_testcases",
            TestCaseLoadFailure,
            None,
            {},
            Exit.ERROR,
        ),
        ("grizzly.reduce.core.ReplayManager.load_testcases", None, [], {}, Exit.ERROR),
        (
            "grizzly.reduce.core.ReplayManager.load_testcases",
            None,
            ([Mock(hang=False), Mock(hang=False)], Mock(spec_set=AssetManager), dict()),
            {"no_harness": True},
            Exit.ARGS,
        ),
    ],
)
def test_main_exit(mocker, patch_func, side_effect, return_value, kwargs, exit_code):
    """test ReduceManager.main() failure cases"""
    mocker.patch("grizzly.reduce.core.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.reduce.core.load_plugin", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    # setup args
    args = mocker.Mock(
        ignore=["fake"],
        input="test",
        min_crashes=1,
        relaunch=1,
        repeat=1,
        sig=None,
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
    reporter = mocker.patch("grizzly.reduce.core.FilesystemReporter", autospec=True)
    mocker.patch("grizzly.reduce.core.load_plugin", autospec=True)
    mocker.patch(
        "grizzly.reduce.core.ReplayManager.load_testcases",
        return_value=(
            [mocker.Mock(spec_set=TestCase, hang=False, adapter_name="fake")],
            None,
            dict(),
        ),
    )
    mocker.patch(
        "grizzly.reduce.core.ReplayManager.time_limits", return_value=(None, 10)
    )
    run = mocker.patch("grizzly.reduce.core.ReduceManager.run", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    # setup args
    args = mocker.Mock(
        ignore=["fake"],
        input="test",
        min_crashes=1,
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
