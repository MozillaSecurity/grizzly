# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.replay.main
"""

import pytest

from grizzly.replay.args import ReplayArgs


def test_args_01(capsys, tmp_path):
    """test parsing args"""
    # missing args tests
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([])

    # test case directory missing test_info.json
    exe = tmp_path / "binary"
    exe.touch()
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "somefile").touch()
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp)])
    assert "error: Test case folder must contain 'test_info.json'" in capsys.readouterr()[-1]

    # test case directory with test_info.json missing prefs.js
    (inp / "test_info.json").touch()
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp)])
    assert "error: 'prefs.js' not found" in capsys.readouterr()[-1]

    # test case directory
    (inp / "prefs.js").touch()
    ReplayArgs().parse_args([str(exe), str(inp)])

    # test case file not specified prefs.js
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp / "somefile")])
    assert "error: 'prefs.js' not specified" in capsys.readouterr()[-1]

    # test case file
    ReplayArgs().parse_args([str(exe), str(inp / "somefile"), "--prefs", str(inp / "prefs.js")])

    # test logs directory that is not empty
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp), "--logs", str(tmp_path)])
    assert "must be empty" in capsys.readouterr()[-1]

    # test negative min-crashes value
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp), "--min-crashes", "-1"])
    assert "error: '--min-crashes' value must be positive" in capsys.readouterr()[-1]

    # test negative repeat value
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp), "--repeat", "-1"])
    assert "error: '--repeat' value must be positive" in capsys.readouterr()[-1]

    # test missing signature file
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp), "--sig", "missing"])
    assert "error: signature file not found" in capsys.readouterr()[-1]

#TODO: main() tests
