# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from pytest import raises

from .args import GrizzlyArgs

def test_grizzly_args_01(capsys, tmp_path):
    """test GrizzlyArgs.parse_args()"""
    # test help
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=["-h"])
    out, _ = capsys.readouterr()
    assert "For addition help check out the wiki" in out
    # test success
    fake_bin = (tmp_path / "fake.bin")
    fake_bin.touch()
    argp = GrizzlyArgs()
    argp._adapters = ["test_adapter"]
    assert argp.parse_args(argv=[str(fake_bin), "test_adapter"])

def test_grizzly_args_03(capsys):
    """test GrizzlyArgs.parse_args() handling binary"""
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

def test_grizzly_args_04(capsys, tmp_path):
    """test GrizzlyArgs.parse_args() handling adapter"""
    fake_bin = (tmp_path / "fake.bin")
    fake_bin.touch()
    # no adapters
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=[str(fake_bin), "missing"])
    _, err = capsys.readouterr()
    assert "error: Adapter 'missing' does not exist. No adapters available." in err
    # invalid adapter name
    argp = GrizzlyArgs()
    argp._adapters = ["a1", "b2"]
    with raises(SystemExit):
        argp.parse_args(argv=[str(fake_bin), "missing"])
    _, err = capsys.readouterr()
    assert "error: Adapter 'missing' does not exist. Available adapters: a1, b2" in err

# TODO: Add CommonArgs tests
