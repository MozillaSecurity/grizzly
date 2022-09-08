# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
unit tests for grizzly.replay.args
"""
from platform import system

from pytest import mark, param, raises

from .args import ReplayArgs, ReplayFuzzManagerIDArgs, ReplayFuzzManagerIDQualityArgs


def test_replay_args_01(capsys, mocker, tmp_path):
    """test parsing args"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=["targ1"])
    # missing args tests
    with raises(SystemExit):
        ReplayArgs().parse_args([])
    # specified prefs.js missing
    exe = tmp_path / "binary"
    exe.touch()
    # test success
    ReplayArgs().parse_args([str(exe), str(exe), "--platform", "targ1"])
    # test missing input
    with raises(SystemExit):
        ReplayArgs().parse_args(argv=[str(exe), "missing", "--platform", "targ1"])
    assert "error: 'missing' does not exist" in capsys.readouterr()[-1]


@mark.parametrize(
    "args, msg",
    [
        # test any-crash with signature
        (
            ["--any-crash", "--sig", "x"],
            "error: signature is ignored when running with --any-crash",
        ),
        # test in valid idle_delay
        (
            ["--idle-threshold", "1", "--idle-delay", "-1"],
            "error: --idle-delay value must be positive",
        ),
        # test invalid min-crashes value
        (["--min-crashes", "0"], "error: --min-crashes value must be positive"),
        # test invalid post-launch-delay value
        (
            ["--post-launch-delay", "-1"],
            "error: --post-launch-delay value must be positive",
        ),
        # test invalid repeat value
        (["--repeat", "-1"], "error: --repeat value must be positive"),
        # test running with rr without --logs set
        param(
            ["--rr"],
            "error: --logs must be set when using rr",
            marks=[mark.skipif(system() != "Linux", reason="Linux only")],
        ),
        # test missing signature file
        (["--sig", "missing"], "error: signature file not found"),
    ],
)
def test_replay_args_02(capsys, mocker, tmp_path, args, msg):
    """test ReplayArgs.parse_args() - sanity checks"""
    mocker.patch("grizzly.args.Path.read_text", autospec=True, return_value="0")
    target = "target1"
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=[target])
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    with raises(SystemExit):
        ReplayArgs().parse_args(
            argv=[str(fake_bin), str(fake_bin), "--platform", target] + args
        )
    assert msg in capsys.readouterr()[-1]


def test_replay_args_03(tmp_path):
    """test ReplayFuzzManagerIDArgs"""
    exe = tmp_path / "binary"
    exe.touch()
    ReplayFuzzManagerIDArgs().parse_args([str(exe), "123"])


def test_replay_args_04(capsys, tmp_path):
    """test ReplayFuzzManagerIDQualityArgs"""
    exe = tmp_path / "binary"
    exe.touch()
    with raises(SystemExit):
        ReplayFuzzManagerIDQualityArgs().parse_args(
            [str(exe), "123", "--quality", "-1"]
        )
    assert "error: '--quality' value cannot be negative" in capsys.readouterr()[-1]
