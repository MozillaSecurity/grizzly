# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.replay.main
"""
import os

import pytest

from ..common import TestCaseLoadFailure
from ..target import Target, TargetLaunchError, TargetLaunchTimeout
from ..replay import ReplayManager
from ..replay.args import ReplayArgs


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

    # test any crash and signature
    with pytest.raises(SystemExit):
        ReplayArgs().parse_args([str(exe), str(inp), "--any-crash", "--sig", "x"])
    assert "error: signature is ignored when running with '--any-crash'" in capsys.readouterr()[-1]

def test_main_01(mocker, tmp_path):
    """test ReplayManager.main()"""
    # This is a typical scenario - a test that reproduces results ~50% of the time.
    # Of the four attempts only the first and third will 'reproduce' the result
    # and the forth attempt should be skipped.
    # mock Sapphire.serve_testcase only
    serve_testcase = mocker.patch("grizzly.replay.replay.Sapphire.serve_testcase", autospec=True)
    serve_testcase.return_value = (None, ["test.html"])  # passed to mocked Target.detect_failure
    # setup Target
    load_target = mocker.patch("grizzly.replay.replay.load_target")
    target = mocker.Mock(spec=Target)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.RESULT_NONE = Target.RESULT_NONE
    target.binary = "bin"
    target.detect_failure.side_effect = (Target.RESULT_FAILURE, Target.RESULT_NONE, Target.RESULT_FAILURE)
    def _fake_save_logs(result_logs, meta=False):  # pylint: disable=unused-argument
        """write fake log data to disk"""
        with open(os.path.join(result_logs, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log\n")
        with open(os.path.join(result_logs, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log\n")
        with open(os.path.join(result_logs, "log_asan_blah.txt"), "w") as log_fp:
            log_fp.write("==1==ERROR: AddressSanitizer: ")
            log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")
    target.save_logs = _fake_save_logs
    load_target.return_value.return_value = target
    # setup args
    args = mocker.Mock()
    args.fuzzmanager = False
    args.ignore = ["fake", "timeout"]
    log_path = (tmp_path / "logs")
    args.logs = str(log_path)
    (tmp_path / "test.html").touch()
    args.input = str(tmp_path / "test.html")
    args.min_crashes = 2
    (tmp_path / "prefs.js").touch()
    args.prefs = str(tmp_path / "prefs.js")
    args.relaunch = 1
    args.repeat = 4
    (tmp_path / "sig.json").write_bytes(b"{\"symptoms\": [{\"type\": \"crashAddress\", \"address\": \"0\"}]}")
    args.sig = str(tmp_path / "sig.json")
    args.timeout = 10
    assert ReplayManager.main(args) == 0
    assert target.reverse.call_count == 1
    assert target.launch.call_count == 3
    assert target.step.call_count == 3
    assert target.detect_failure.call_count == 3
    assert serve_testcase.call_count == 3
    assert load_target.call_count == 1
    assert target.close.call_count == 1
    assert target.cleanup.call_count == 1
    assert target.check_relaunch.call_count == 2
    assert log_path.is_dir()
    assert any(log_path.glob('**/log_asan_blah.txt'))
    assert any(log_path.glob('**/log_stderr.txt'))
    assert any(log_path.glob('**/log_stdout.txt'))

def test_main_02(mocker):
    """test ReplayManager.main() failure cases"""
    mocker.patch("grizzly.replay.replay.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.replay.replay.load_target", autospec=True)
    mocker.patch("grizzly.replay.replay.Sapphire", autospec=True)
    mocker.patch("grizzly.replay.replay.TestCase", autospec=True)
    # setup args
    args = mocker.Mock()
    args.ignore = None
    args.input = "test"
    args.min_crashes = 1
    args.relaunch = 1
    args.repeat = 1
    args.sig = None

    mocker.patch("grizzly.replay.replay.ReplayManager.run", side_effect=TargetLaunchError)
    assert ReplayManager.main(args) == 1

    mocker.patch("grizzly.replay.replay.ReplayManager.run", side_effect=TargetLaunchTimeout)
    assert ReplayManager.main(args) == 1

    mocker.patch("grizzly.replay.replay.load_target", side_effect=KeyboardInterrupt)
    assert ReplayManager.main(args) == 1

    mocker.patch("grizzly.replay.replay.TestCase.load_path", side_effect=TestCaseLoadFailure)
    assert ReplayManager.main(args) == 1
