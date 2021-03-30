# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from pytest import raises

from .args import GrizzlyArgs


def test_grizzly_args_01(capsys, mocker, tmp_path):
    """test GrizzlyArgs.parse_args()"""
    # test help
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=["-h"])
    out, _ = capsys.readouterr()
    assert "For addition help check out the wiki" in out
    # test success
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    mocker.patch(
        "grizzly.args.scan_plugins",
        autospec=True,
        side_effect=(["targ1"], ["adpt1"], ["targ1"], ["adpt1"]),
    )
    assert GrizzlyArgs().parse_args(
        argv=[str(fake_bin), "adpt1", "--platform", "targ1"]
    )


def test_grizzly_args_02(capsys, mocker):
    """test GrizzlyArgs.parse_args() handling binary"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=["blah"])
    # test missing required args
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=[])
    _, err = capsys.readouterr()
    assert "the following arguments are required: binary, adapter" in err
    # test missing binary
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=["missing_bin", "adapter"])
    _, err = capsys.readouterr()
    assert "error: file not found: 'missing_bin'" in err


def test_grizzly_args_03(capsys, mocker, tmp_path):
    """test GrizzlyArgs.parse_args() handling Adapter"""
    scan_plugins = mocker.patch("grizzly.args.scan_plugins", autospec=True)
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    # no adapters installed
    scan_plugins.side_effect = (["targ1"], [], ["targ1"], [])
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=[str(fake_bin), "adpt", "--platform", "targ1"])
    _, err = capsys.readouterr()
    assert "error: No Adapters are installed" in err
    # invalid adapter name
    scan_plugins.side_effect = (["targ1"], ["a1", "a2"], ["targ1"], ["a1", "a2"])
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=[str(fake_bin), "missing", "--platform", "targ1"])
    _, err = capsys.readouterr()
    assert "error: Adapter 'missing' is not installed" in err


# TODO: Add CommonArgs tests
