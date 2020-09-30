# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.reduce.main
"""
import functools
from logging import getLogger
from pathlib import Path

import pytest
from pytest import raises

from sapphire import SERVED_ALL
from ..common import TestCaseLoadFailure
from ..target import Target, TargetLaunchError, TargetLaunchTimeout
from ..reduce import ReduceManager
from ..reduce.args import ReduceArgs


LOG = getLogger(__name__)
pytestmark = pytest.mark.usefixtures("tmp_path_fm_config")  # pylint: disable=invalid-name


def _fake_save_logs_foo(result_logs, meta=False):  # pylint: disable=unused-argument
    """write fake log data to disk"""
    (Path(result_logs) / "log_stderr.txt").write_text("STDERR log\n")
    (Path(result_logs) / "log_stdout.txt").write_text("STDOUT log\n")
    (Path(result_logs) / "log_asan_blah.txt").write_text(
        "==1==ERROR: AddressSanitizer: "
        "SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n"
        "    #0 0xbad000 in foo /file1.c:123:234\n"
        "    #1 0x1337dd in bar /file2.c:1806:19\n"
    )


def _fake_save_logs_bar(result_logs, meta=False):  # pylint: disable=unused-argument
    """write fake log data to disk"""
    (Path(result_logs) / "log_stderr.txt").write_text("STDERR log\n")
    (Path(result_logs) / "log_stdout.txt").write_text("STDOUT log\n")
    (Path(result_logs) / "log_asan_blah.txt").write_text(
        "==1==ERROR: AddressSanitizer: "
        "SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n"
        "    #0 0xbad000 in bar /file1.c:123:234\n"
        "    #1 0x1337dd in foo /file2.c:1806:19\n"
    )


def test_args_01(capsys, tmp_path):
    """test parsing args"""
    # missing args tests
    with raises(SystemExit):
        ReduceArgs().parse_args([])
    # specified prefs.js missing
    exe = tmp_path / "binary"
    exe.touch()
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "somefile").touch()
    (inp / "test_info.json").touch()
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp / "somefile"), "--prefs", "missing"])
    assert "error: -p/--prefs not found 'missing'" in capsys.readouterr()[-1]
    # test case directory
    (inp / "prefs.js").touch()
    ReduceArgs().parse_args([str(exe), str(inp)])
    # test case file
    ReduceArgs().parse_args([str(exe), str(inp / "somefile"), "--prefs", str(inp / "prefs.js")])
    # test negative min-crashes value
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--min-crashes", "-1"])
    assert "error: '--min-crashes' value must be positive" in capsys.readouterr()[-1]
    # test negative repeat value
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--repeat", "-1"])
    assert "error: '--repeat' value must be positive" in capsys.readouterr()[-1]
    # test missing signature file
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--sig", "missing"])
    assert "error: signature file not found" in capsys.readouterr()[-1]
    # test any crash and signature
    with raises(SystemExit):
        ReduceArgs().parse_args([str(exe), str(inp), "--any-crash", "--sig", "x"])
    assert "error: signature is ignored when running with '--any-crash'" in capsys.readouterr()[-1]

    # above this line is copied from replay/test_main.py#test_args_01
    # TODO: is there a way to make the test generic?

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
    ReduceArgs().parse_args([str(exe), str(inp), "--no-analysis", "--repeat", "99", "--min-crashes", "99"])


def test_main_01(mocker):
    """test ReduceManager.main() failure cases"""
    mocker.patch("grizzly.reduce.reduce.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.reduce.reduce.load_target", autospec=True)
    mocker.patch("grizzly.reduce.reduce.Sapphire", autospec=True)
    mocker.patch("grizzly.reduce.reduce.TestCase", autospec=True)
    # setup args
    args = mocker.Mock(
        ignore=None,
        input="test",
        min_crashes=1,
        prefs=None,
        relaunch=1,
        repeat=1,
        sig=None)

    mocker.patch("grizzly.reduce.reduce.ReduceManager.run", side_effect=TargetLaunchError("error", None))
    assert ReduceManager.main(args) == 1

    mocker.patch("grizzly.reduce.reduce.ReduceManager.run", side_effect=TargetLaunchTimeout)
    assert ReduceManager.main(args) == 1

    mocker.patch("grizzly.reduce.reduce.load_target", side_effect=KeyboardInterrupt)
    assert ReduceManager.main(args) == 1

    mocker.patch("grizzly.reduce.reduce.TestCase.load", side_effect=TestCaseLoadFailure)
    assert ReduceManager.main(args) == 1

    mocker.patch("grizzly.reduce.reduce.TestCase.load", return_value=list())
    assert ReduceManager.main(args) == 1


def ignore_arg(func):
    """Function wrapper that simply ignores 1 argument"""
    @functools.wraps(func)
    def wrapped(_):
        return func()
    return wrapped


@pytest.mark.parametrize(
    "original, strategies, detect_failure, interesting_str, save_logs, launch_count, n_reports, reports, "
    "n_other, other_reports",
    [
        # no repro
        (
            "123456\n",
            ["check"],
            lambda _: False,
            "%r",
            None,
            1,
            0,
            None,
            0,
            None,
        ),
        # reproduces, one strategy, no reduction works
        (
            "1\n2\n3\n",
            ["check", "lines"],
            lambda contents: contents == "1\n2\n3\n",
            "%r == '1\n2\n3\n'",
            lambda _: _fake_save_logs_foo,
            6,
            1,
            {"1\n2\n3\n"},
            0,
            None,
        ),
        # reproduces, one strategy, some reduction works
        (
            "odd\neven\n" * 3,
            ["check", "lines"],
            lambda contents: sum(1 for line in contents.splitlines() if line == "odd") == 3,
            "%r contains 3x 'odd'",
            lambda _: _fake_save_logs_foo,
            8,
            2,
            {"odd\neven\n" * 3, "odd\n" * 3},
            0,
            None,
        ),
        # reproduces, one strategy, reduction only finds other
        (
            "1\n2\n3\n",
            ["check", "lines"],
            bool,
            "%r != ''",
            lambda contents: _fake_save_logs_foo if contents == "1\n2\n3\n" else \
            (_fake_save_logs_bar if contents else None),
            6,
            1,
            {"1\n2\n3\n"},
            5,
            {"1\n", "3\n", "1\n2\n", "1\n3\n", "2\n3\n"},
        ),
        # reproduces, 50% iterations work, 1 iteration produces other sig
        (
            "1\n2\n3\n4\n5\n6\n",
            ["check", "lines"],
            lambda contents: set(contents.splitlines()) >= set("135"),
            "%r contains {'1', '3', '5'}",
            lambda contents: _fake_save_logs_foo if contents == "1\n3\n5\n" else \
            (_fake_save_logs_bar if contents else None),
            13,
            2,
            {"1\n2\n3\n4\n5\n6\n", "1\n2\n3\n5\n"},
            1,
            {"1\n3\n5\n"},
        ),
        # reproduces, two strategies, 1st no reduction, 2nd 50% reduction
        (
            "A1\nA2\nA3\nA4\nA5\nA6\n",
            ["check", "lines", "chars"],
            lambda contents: len(contents.splitlines()) == 6 and set(contents.splitlines()) >= \
            {"A1", "A3", "A5"},
            "%r contains {'A1', 'A3', 'A5'} and len() == 6",
            lambda _: _fake_save_logs_foo,
            43,
            # lines found nothing, only check and chars should report
            2,
            {"A1\nA2\nA3\nA4\nA5\nA6\n", "A1\n\nA3\n\nA5\nA"},
            0,
            None,
        ),
        # reproduces, two strategies, 1st 50% reduction, 2nd no reduction
        (
            "A1\nA2\nA3\nA4\nA5\nA6\n",
            ["check", "lines", "chars"],
            lambda contents: set(contents.splitlines(keepends=True)) >= {"A1\n", "A3\n", "A5\n"},
            "%r contains {'A1\\n', 'A3\\n', 'A5\\n'}",
            lambda _: _fake_save_logs_foo,
            34,
            # lines found nothing, only check and chars should report
            2,
            {"A1\nA2\nA3\nA4\nA5\nA6\n", "A1\nA3\nA5\n"},
            0,
            None,
        ),
        # reproduces, two strategies, reduce only produces other sig
        (
            "1\n2\n3\n",
            ["check", "lines", "chars"],
            bool,
            "%r != ''",
            lambda contents: _fake_save_logs_foo if contents == "1\n2\n3\n" else \
            (_fake_save_logs_bar if contents else None),
            16,
            1,
            {"1\n2\n3\n"},
            15,
            {"\n2\n3\n", "1\n", "1\n\n3\n", "1\n2\n", "1\n2\n\n", "1\n2\n3", "1\n23\n", "1\n3\n", "12\n3\n",
             "2\n3\n", "3\n"}
        ),
        # reproduces, one strategy, testcase reduces to 0
        (
            "1\n2\n3\n",
            ["check", "lines"],
            lambda _: True,
            "%r is anything, incl. empty",
            lambda _: _fake_save_logs_foo,
            3,
            2,
            {"1\n2\n3\n", ""},
            0,
            None,
        ),
        # reproduces, two strategies, 1st no reduce, 2nd testcase reduces to 0
        (
            "1\n2\n3\n",
            ["check", "lines", "lines"],
            ignore_arg(functools.partial([True, False, False, False, False, False, True, True].pop, 0)),
            "%r is anything, only in second strategy",
            lambda _: _fake_save_logs_foo,
            8,
            2,
            {"1\n2\n3\n", ""},
            0,
            None,
        ),
    ]
)
def test_repro(mocker, tmp_path, original, strategies, detect_failure, interesting_str, save_logs,
               launch_count, n_reports, reports, n_other, other_reports):
    """test ReduceManager, difference scenarios produce correct expected/other results"""
    last_path = [None]

    def serve(path, **_kw):
        LOG.debug("serving %r", path)
        last_path[0] = path
        return (SERVED_ALL, ["test.html"])
    serve_path = mocker.patch("grizzly.reduce.reduce.Sapphire.serve_path", side_effect=serve)
    # setup Target
    load_target = mocker.patch("grizzly.reduce.reduce.load_target")
    target = mocker.Mock(spec=Target, binary="bin", forced_close=True)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.RESULT_NONE = Target.RESULT_NONE

    def _fake_save_logs(result_path, meta=False):
        contents = (Path(last_path[0]) / "test.html").read_text()
        return save_logs(contents)(result_path, meta)
    target.save_logs = _fake_save_logs
    target.relaunch = 1

    def interesting(*_, **_kw):
        contents = (Path(last_path[0]) / "test.html").read_text()
        LOG.debug("interesting if " + interesting_str, contents)  # pylint: disable=logging-not-lazy
        if detect_failure(contents):
            return Target.RESULT_FAILURE
        return Target.RESULT_NONE
    target.detect_failure.side_effect = interesting
    load_target.return_value.return_value = target

    prefix = mocker.patch("grizzly.common.reporter.strftime")

    def report_prefix(_):
        return "%04d" % (prefix.call_count,)
    prefix.side_effect = report_prefix

    # setup args
    args = mocker.Mock()
    args.fuzzmanager = False
    args.ignore = ["fake", "timeout"]
    log_path = (tmp_path / "logs")
    args.logs = str(log_path)
    (tmp_path / "test.html").write_text(original)
    args.input = str(tmp_path / "test.html")
    args.min_crashes = 1
    (tmp_path / "prefs.js").touch()
    args.prefs = str(tmp_path / "prefs.js")
    args.relaunch = 1
    args.repeat = 1
    args.any_crash = False
    args.sig = None
    args.timeout = 10
    args.no_analysis = True
    args.strategies = strategies
    assert ReduceManager.main(args) == (0 if (n_reports or n_other) else 1)
    assert target.forced_close
    assert target.reverse.call_count == 1
    assert target.launch.call_count == launch_count
    assert target.step.call_count == launch_count
    assert target.detect_failure.call_count == launch_count
    assert serve_path.call_count == launch_count
    assert load_target.call_count == 1
    assert target.close.call_count == launch_count
    assert target.cleanup.call_count == 1
    assert target.check_relaunch.call_count == 0
    expected_dirs = set()
    if n_reports:
        expected_dirs.add(log_path / "reports")
    if n_other:
        expected_dirs.add(log_path / "other_reports")
    if expected_dirs:
        assert set(log_path.iterdir()) == expected_dirs
    if n_reports:
        tests = {test.read_text() for test in log_path.glob("reports/*-0/test.html")}
        assert tests == reports
        assert len(list((log_path / "reports").iterdir())) \
            == n_reports * 2, list((log_path / "reports").iterdir())
    if n_other:
        other_tests = {test.read_text() for test in log_path.glob("other_reports/*-0/test.html")}
        assert other_tests == other_reports
        assert len(list((log_path / "other_reports").iterdir())) \
            == n_other * 2, list((log_path / "other_reports").iterdir())
