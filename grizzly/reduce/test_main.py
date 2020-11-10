# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.main`.
"""
import json
from logging import getLogger
from pathlib import Path
from shutil import rmtree

import pytest
from pytest import raises

from ..common import TestCaseLoadFailure
from ..target import TargetLaunchError, TargetLaunchTimeout
from .args import ReduceArgs
from . import ReduceManager


LOG = getLogger(__name__)
pytestmark = pytest.mark.usefixtures("tmp_path_fm_config")


def test_args_01(capsys, tmp_path, mocker):
    """test args in common with grizzly.replay"""
    # pylint: disable=import-outside-toplevel
    from ..replay.test_main import test_args_01 as real_test
    mocker.patch("grizzly.replay.test_main.ReplayArgs", new=ReduceArgs)
    real_test(capsys, tmp_path)


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
    # test --logs must be dir
    logs_file = tmp_path / "logs1"
    logs_file.touch()
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--logs", str(logs_file)])
    logs_dir = tmp_path / "logs2"
    logs_dir.mkdir()
    ReduceArgs().parse_args([str(exe), str(inp), "--logs", str(logs_dir)])
    # test no-analysis
    ReduceArgs().parse_args([str(exe), str(inp), "--no-analysis", "--repeat", "99",
                             "--min-crashes", "99"])
    # these should both log a warning that the args will be ignored due to analysis
    ReduceArgs().parse_args([str(exe), str(inp), "--repeat", "99"])
    ReduceArgs().parse_args([str(exe), str(inp), "--min-crashes", "99"])


@pytest.mark.parametrize(
    "patch_func, side_effect, return_value, result",
    [
        (
            "grizzly.reduce.core.ReduceManager.run",
            TargetLaunchError("error", None), None, 9
        ),
        ("grizzly.reduce.core.ReduceManager.run", TargetLaunchTimeout, None, 9),
        ("grizzly.reduce.core.load_target", KeyboardInterrupt, None, 1),
        ("grizzly.reduce.core.TestCase.load", TestCaseLoadFailure, None, 1),
        ("grizzly.reduce.core.TestCase.load", None, [], 1),
    ]
)
def test_main_01(mocker, patch_func, side_effect, return_value, result):
    """test ReduceManager.main() failure cases"""
    mocker.patch(
        "grizzly.reduce.core.FuzzManagerReporter", autospec=True,
        QUAL_REDUCER_ERROR=9)
    mocker.patch("grizzly.reduce.core.load_target", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    mocker.patch("grizzly.reduce.core.TestCase", autospec=True)
    # setup args
    args = mocker.Mock(
        ignore=["fake"],
        input="test",
        min_crashes=1,
        prefs=None,
        relaunch=1,
        repeat=1,
        sig=None)

    mocker.patch(patch_func, side_effect=side_effect, return_value=return_value)
    assert ReduceManager.main(args) == result


def test_force_closed(mocker, tmp_path):
    """test that `forced_close` in testcase metadata is respected"""
    load_target = mocker.patch("grizzly.reduce.core.load_target")
    mocker.patch("grizzly.reduce.core.ReduceManager.run", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    (tmp_path / "test.html").touch()
    (tmp_path / "test_info.json").write_text(
        json.dumps({
            "timestamp": 1,
            "target": "test.html",
            "env": {"GRZ_FORCED_CLOSE": "0"}
        })
    )
    args = mocker.Mock(
        fuzzmanager=False,
        ignore=[],
        input=str(tmp_path),
        min_crashes=1,
        prefs=None,
        repeat=1,
        sig=None,
    )
    ReduceManager.main(args)
    assert load_target.return_value.return_value.forced_close is False


@pytest.mark.parametrize("result", ["testprefs", "argprefs"])
def test_testcase_prefs(mocker, tmp_path, result):
    """test that prefs from testcase are used if --prefs not specified and --prefs
    overrides"""
    load_target = mocker.patch("grizzly.reduce.core.load_target")
    mocker.patch("grizzly.reduce.core.ReduceManager.run", autospec=True)
    mocker.patch("grizzly.reduce.core.Sapphire", autospec=True)
    rmtree_mock = mocker.patch("grizzly.reduce.core.rmtree", autospec=True)
    (tmp_path / "test.html").touch()
    (tmp_path / "prefs.js").write_text("testprefs")
    args = mocker.Mock(
        fuzzmanager=False,
        ignore=[],
        input=str(tmp_path / "test.html"),
        min_crashes=1,
        prefs=None,
        repeat=1,
        sig=None,
    )
    if result == "argprefs":
        (tmp_path / "args.js").write_text("argprefs")
        args.prefs = str(tmp_path / "args.js")

    try:
        ReduceManager.main(args)
        assert Path(load_target.return_value.return_value.prefs).read_text() == result
    finally:
        for rm_args, rm_kwds in rmtree_mock.call_args_list:
            rmtree(*rm_args, **rm_kwds)
