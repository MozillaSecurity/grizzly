# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.reduce`."""

from collections import namedtuple
from functools import partial, wraps
from itertools import count
from logging import getLogger
from pathlib import Path

from pytest import mark, param, raises

from sapphire import Sapphire

from ..common.reporter import Quality, Report
from ..common.storage import TestCase
from ..replay import ReplayResult
from ..target import AssetManager, Target
from . import ReduceManager
from .exceptions import NotReproducible
from .strategies import Strategy

LOG = getLogger(__name__)
pytestmark = mark.usefixtures(
    "reporter_sequential_strftime",
    "tmp_path_status_db_reduce",
)


def _fake_save_logs_foo(result_logs):
    """write fake log data to disk"""
    (result_logs / "log_stderr.txt").write_text("STDERR log\n")
    (result_logs / "log_stdout.txt").write_text("STDOUT log\n")
    (result_logs / "log_asan_blah.txt").write_text(
        "==1==ERROR: AddressSanitizer: "
        "SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n"
        "    #0 0xbad000 in foo /file1.c:123:234\n"
        "    #1 0x1337dd in bar /file2.c:1806:19\n"
    )


def _fake_save_logs_bar(result_logs):
    """write fake log data to disk"""
    (result_logs / "log_stderr.txt").write_text("STDERR log\n")
    (result_logs / "log_stdout.txt").write_text("STDOUT log\n")
    (result_logs / "log_asan_blah.txt").write_text(
        "==1==ERROR: AddressSanitizer: "
        "SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n"
        "    #0 0xbad000 in bar /file1.c:123:234\n"
        "    #1 0x1337dd in foo /file2.c:1806:19\n"
    )


@mark.parametrize(
    "harness_last_crashes,harness_crashes,no_harness_crashes,expected_repeat,"
    "expected_min_crashes,use_harness,result_harness",
    [
        param(
            11,
            None,
            None,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            True,
            id="perfect with harness",
        ),
        param(
            None,
            None,
            11,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            False,
            False,
            id="perfect, use_harness=False",
        ),
        param(
            1,
            11,
            None,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            True,
            id="1/11 with harness last test, perfect all tests",
        ),
        param(0, 10, None, 2, 1, True, True, id="10/11 with harness"),
        param(0, 9, None, 2, 1, True, True, id="9/11 with harness"),
        param(0, 8, None, 3, 1, True, True, id="8/11 with harness"),
        param(0, 7, None, 3, 1, True, True, id="7/11 with harness"),
        param(0, 6, None, 4, 1, True, True, id="6/11 with harness"),
        param(0, 5, 0, 5, 1, True, True, id="5/11 with harness"),
        param(0, 5, 1, 5, 1, True, True, id="5/11 with harness, 1/11 without"),
        param(0, 5, 2, 5, 1, True, True, id="5/11 with harness, 2/11 without"),
        param(0, 5, 3, 5, 1, True, True, id="5/11 with harness, 3/11 without"),
        param(0, 5, 4, 5, 1, True, True, id="5/11 with harness, 4/11 without"),
        param(0, 5, 5, 5, 1, True, True, id="5/11 with harness, 5/11 without"),
        param(0, 5, 6, 5, 1, True, True, id="5/11 with harness, 6/11 without"),
        param(0, 5, 7, 5, 1, True, True, id="5/11 with harness, 7/11 without"),
        param(0, 5, 8, 3, 1, True, False, id="5/11 with harness, 8/11 without"),
        param(0, 5, 9, 2, 1, True, False, id="5/11 with harness, 9/11 without"),
        param(0, 5, 10, 2, 1, True, False, id="5/11 with harness, 10/11 without"),
        param(
            0,
            5,
            11,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            False,
            id="5/11 with harness, perfect without",
        ),
        param(0, 4, 0, 7, 1, True, True, id="4/11 with harness"),
        param(0, 4, 1, 7, 1, True, True, id="4/11 with harness, 1/11 without"),
        param(0, 4, 2, 7, 1, True, True, id="4/11 with harness, 2/11 without"),
        param(0, 4, 3, 7, 1, True, True, id="4/11 with harness, 3/11 without"),
        param(0, 4, 4, 7, 1, True, True, id="4/11 with harness, 4/11 without"),
        param(0, 4, 5, 7, 1, True, True, id="4/11 with harness, 5/11 without"),
        param(0, 4, 6, 4, 1, True, False, id="4/11 with harness, 6/11 without"),
        param(0, 4, 7, 3, 1, True, False, id="4/11 with harness, 7/11 without"),
        param(0, 4, 8, 3, 1, True, False, id="4/11 with harness, 8/11 without"),
        param(0, 4, 9, 2, 1, True, False, id="4/11 with harness, 9/11 without"),
        param(0, 4, 10, 2, 1, True, False, id="4/11 with harness, 10/11 without"),
        param(
            0,
            4,
            11,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            False,
            id="4/11 with harness, perfect without",
        ),
        param(0, 3, 0, 10, 1, True, True, id="3/11 with harness"),
        param(0, 3, 1, 10, 1, True, True, id="3/11 with harness, 1/11 without"),
        param(0, 3, 2, 10, 1, True, True, id="3/11 with harness, 2/11 without"),
        param(0, 3, 3, 10, 1, True, True, id="3/11 with harness, 3/11 without"),
        param(0, 3, 4, 10, 1, True, True, id="3/11 with harness, 4/11 without"),
        param(0, 3, 5, 5, 1, True, False, id="3/11 with harness, 5/11 without"),
        param(0, 3, 6, 4, 1, True, False, id="3/11 with harness, 6/11 without"),
        param(0, 3, 7, 3, 1, True, False, id="3/11 with harness, 7/11 without"),
        param(0, 3, 8, 3, 1, True, False, id="3/11 with harness, 8/11 without"),
        param(0, 3, 9, 2, 1, True, False, id="3/11 with harness, 9/11 without"),
        param(0, 3, 10, 2, 1, True, False, id="3/11 with harness, 10/11 without"),
        param(
            0,
            3,
            11,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            False,
            id="3/11 with harness, perfect without",
        ),
        param(0, 2, 0, 15, 1, True, True, id="2/11 with harness"),
        param(0, 2, 1, 15, 1, True, True, id="2/11 with harness, 1/11 without"),
        param(0, 2, 2, 15, 1, True, True, id="2/11 with harness, 2/11 without"),
        param(0, 2, 3, 10, 1, True, False, id="2/11 with harness, 3/11 without"),
        param(0, 2, 4, 7, 1, True, False, id="2/11 with harness, 4/11 without"),
        param(0, 2, 5, 5, 1, True, False, id="2/11 with harness, 5/11 without"),
        param(0, 2, 6, 4, 1, True, False, id="2/11 with harness, 6/11 without"),
        param(0, 2, 7, 3, 1, True, False, id="2/11 with harness, 7/11 without"),
        param(0, 2, 8, 3, 1, True, False, id="2/11 with harness, 8/11 without"),
        param(0, 2, 9, 2, 1, True, False, id="2/11 with harness, 9/11 without"),
        param(0, 2, 10, 2, 1, True, False, id="2/11 with harness, 10/11 without"),
        param(
            0,
            2,
            11,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            False,
            id="2/11 with harness, perfect without",
        ),
        param(0, 1, 0, 32, 1, True, True, id="1/11 with harness"),
        param(0, 1, 1, 32, 1, True, True, id="1/11 with harness, 1/11 without"),
        param(0, 1, 2, 15, 1, True, False, id="1/11 with harness, 2/11 without"),
        param(0, 1, 3, 10, 1, True, False, id="1/11 with harness, 3/11 without"),
        param(0, 1, 4, 7, 1, True, False, id="1/11 with harness, 4/11 without"),
        param(0, 1, 5, 5, 1, True, False, id="1/11 with harness, 5/11 without"),
        param(0, 1, 6, 4, 1, True, False, id="1/11 with harness, 6/11 without"),
        param(0, 1, 7, 3, 1, True, False, id="1/11 with harness, 7/11 without"),
        param(0, 1, 8, 3, 1, True, False, id="1/11 with harness, 8/11 without"),
        param(0, 1, 9, 2, 1, True, False, id="1/11 with harness, 9/11 without"),
        param(0, 1, 10, 2, 1, True, False, id="1/11 with harness, 10/11 without"),
        param(
            0,
            1,
            11,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            False,
            id="1/11 with harness, perfect without",
        ),
        param(
            0,
            0,
            11,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            False,
            id="perfect without harness",
        ),
        param(0, 0, 10, 2, 1, True, False, id="10/11 without harness"),
        param(0, 0, 9, 2, 1, True, False, id="9/11 without harness"),
        param(0, 0, 8, 3, 1, True, False, id="8/11 without harness"),
        param(0, 0, 7, 3, 1, True, False, id="7/11 without harness"),
        param(0, 0, 6, 4, 1, True, False, id="6/11 without harness"),
        param(0, 0, 5, 5, 1, True, False, id="5/11 without harness"),
        param(0, 0, 4, 7, 1, True, False, id="4/11 without harness"),
        param(0, 0, 3, 10, 1, True, False, id="3/11 without harness"),
        param(0, 0, 2, 15, 1, True, False, id="2/11 without harness"),
        param(0, 0, 1, 32, 1, True, False, id="1/11 without harness"),
        param(
            1,
            0,
            0,
            32,
            1,
            True,
            True,
            id="last test repros (1/11), all tests are tried, without_harness is tried",
        ),
        param(
            11,
            None,
            None,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            True,
            id="last test repros (11/11), no other rounds are tried",
        ),
        param(
            0,
            1,
            0,
            32,
            1,
            True,
            True,
            id="last test doesn't repro, harness+all tests is (1/11), "
            "without harness is tried",
        ),
        param(
            0,
            11,
            None,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            ReduceManager.ANALYSIS_PERFECT_MIN_CRASHES,
            True,
            True,
            id="last test doesn't repro, harness+all tests is (11/11), "
            "skip without harness",
        ),
    ],
)
def test_analysis(
    mocker,
    tmp_path,
    harness_last_crashes,
    harness_crashes,
    no_harness_crashes,
    expected_repeat,
    expected_min_crashes,
    use_harness,
    result_harness,
):
    """test that analysis sets reasonable params"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value.__enter__.return_value
    crashes = []
    expected_iters = 0
    if harness_last_crashes is not None:
        crashes += [False] * (11 - harness_last_crashes) + [True] * harness_last_crashes
        expected_iters += 1
    if harness_crashes is not None:
        crashes += [True] * harness_crashes + [False] * (11 - harness_crashes)
        expected_iters += 1
    if no_harness_crashes is not None:
        crashes += [False] * (11 - no_harness_crashes) + [True] * no_harness_crashes
        expected_iters += 1

    def replay_run(_tests, _time_limit, **kw):
        results = []
        repeat = kw["repeat"]
        assert repeat <= len(crashes)
        assert not kw["exit_early"]
        for _ in range(repeat):
            kw["on_iteration_cb"]()
            LOG.debug("interesting: %r", crashes[0])
            if crashes.pop(0):
                log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
                log_path.mkdir(exist_ok=True)
                _fake_save_logs_foo(log_path)
                report = Report(log_path, Path("bin"))
                results.append(ReplayResult(report, [], True))
        return results

    replayer.run.side_effect = replay_run

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"1", test.entry_point)
        test.dump(tmp_path / "src1", include_details=True)
    tests = [test.load(tmp_path / "src1")]
    if harness_last_crashes is not None:
        with TestCase("test.html", "test-adapter") as test:
            test.add_from_bytes(b"2", test.entry_point)
            test.dump(tmp_path / "src2", include_details=True)
        tests.append(test.load(tmp_path / "src2"))
    log_path = tmp_path / "logs"

    with ReduceManager(
        set(),
        mocker.Mock(spec_set=Sapphire, timeout=30),
        mocker.Mock(spec_set=Target),
        tests,
        [],
        log_path,
        use_harness=use_harness,
    ) as mgr:
        repeat, min_crashes = mgr.run_reliability_analysis()

        observed = {
            "replay_iters": replayer.run.call_count,
            "repeat": repeat,
            "min_crashes": min_crashes,
            "use_harness": mgr._use_harness,
            "launch_iters": mgr._status.iterations,
        }
        expected = {
            "replay_iters": expected_iters,
            "repeat": expected_repeat,
            "min_crashes": expected_min_crashes,
            "use_harness": result_harness,
            "launch_iters": expected_iters * 11,
        }
    assert observed == expected


def _ignore_arg(func):
    """Function wrapper that simply ignores 1 argument"""

    @wraps(func)
    def wrapped(_):
        return func()

    return wrapped


ReproTestParams = namedtuple(
    "ReproTestParams",
    "original, strategies, detect_failure, interesting_str, is_expected,"
    "expected_run_calls, n_reports, reports, n_other, other_reports, result",
)


@mark.parametrize(
    ReproTestParams._fields,
    [
        # no repro
        ReproTestParams(
            original=b"123456\n",
            strategies=["check"],
            detect_failure=lambda _: False,
            interesting_str="%r",
            is_expected=None,
            expected_run_calls=1,
            n_reports=0,
            reports=None,
            n_other=0,
            other_reports=None,
            result=NotReproducible,
        ),
        # reproduces, one strategy, no reduction works
        ReproTestParams(
            original=b"1\n2\n3\n",
            strategies=["check", "lines"],
            detect_failure=lambda contents: contents == "1\n2\n3\n",
            interesting_str="%r == '1\n2\n3\n'",
            is_expected=lambda _: True,
            expected_run_calls=6,
            n_reports=1,
            reports={"1\n2\n3\n"},
            n_other=0,
            other_reports=None,
            result=0,
        ),
        # reproduces, one strategy, some reduction works
        ReproTestParams(
            original=b"odd\neven\n" * 3,
            strategies=["check", "lines"],
            detect_failure=lambda contents: sum(
                1 for line in contents.splitlines() if line == "odd"
            )
            == 3,
            interesting_str="%r contains 3x 'odd'",
            is_expected=lambda _: True,
            expected_run_calls=8,
            n_reports=2,
            reports={"odd\neven\n" * 3, "odd\n" * 3},
            n_other=0,
            other_reports=None,
            result=0,
        ),
        # reproduces, one strategy, reduction only finds other
        ReproTestParams(
            original=b"1\n2\n3\n",
            strategies=["check", "lines"],
            detect_failure=bool,
            interesting_str="%r != ''",
            is_expected=lambda contents: contents == "1\n2\n3\n",
            expected_run_calls=6,
            n_reports=1,
            reports={"1\n2\n3\n"},
            n_other=1,
            other_reports={"1\n"},
            result=0,
        ),
        # reproduces, 50% iterations work, 1 iteration produces other sig
        ReproTestParams(
            original=b"1\n2\n3\n4\n5\n6\n",
            strategies=["check", "lines"],
            detect_failure=lambda contents: set(contents.splitlines()) >= set("135"),
            interesting_str="%r contains {'1', '3', '5'}",
            is_expected=lambda contents: contents != "1\n3\n5\n",
            expected_run_calls=13,
            n_reports=2,
            reports={"1\n2\n3\n4\n5\n6\n", "1\n2\n3\n5\n"},
            n_other=1,
            other_reports={"1\n3\n5\n"},
            result=0,
        ),
        # reproduces, two strategies, 1st no reduction, 2nd 50% reduction
        ReproTestParams(
            original=b"A1\nA2\nA3\nA4\nA5\nA6\n",
            strategies=["check", "lines", "chars"],
            detect_failure=(
                lambda contents: (
                    len(contents.splitlines()) == 6
                    and set(contents.splitlines()) >= {"A1", "A3", "A5"}
                )
            ),
            interesting_str="%r contains {'A1', 'A3', 'A5'} and len() == 6",
            is_expected=lambda _: True,
            expected_run_calls=43,
            # lines found nothing, only check and chars should report
            n_reports=2,
            reports={"A1\nA2\nA3\nA4\nA5\nA6\n", "A1\n\nA3\n\nA5\nA"},
            n_other=0,
            other_reports=None,
            result=0,
        ),
        # reproduces, two strategies, 1st 50% reduction, 2nd no reduction
        ReproTestParams(
            original=b"A1\nA2\nA3\nA4\nA5\nA6\n",
            strategies=["check", "lines", "chars"],
            detect_failure=(
                lambda contents: (
                    set(contents.splitlines(keepends=True)) >= {"A1\n", "A3\n", "A5\n"}
                )
            ),
            interesting_str="%r contains {'A1\\n', 'A3\\n', 'A5\\n'}",
            is_expected=lambda _: True,
            expected_run_calls=34,
            # lines found nothing, only check and chars should report
            n_reports=2,
            reports={"A1\nA2\nA3\nA4\nA5\nA6\n", "A1\nA3\nA5\n"},
            n_other=0,
            other_reports=None,
            result=0,
        ),
        # reproduces, two strategies, reduce only produces other sig
        ReproTestParams(
            original=b"1\n2\n3\n",
            strategies=["check", "lines", "chars"],
            detect_failure=bool,
            interesting_str="%r != ''",
            is_expected=lambda contents: contents == "1\n2\n3\n",
            expected_run_calls=12,
            n_reports=1,
            reports={"1\n2\n3\n"},
            n_other=2,
            other_reports={
                "1\n",
                "1\n2\n3",
            },
            result=0,
        ),
        # reproduces, one strategy, testcase reduces to 0
        ReproTestParams(
            original=b"1\n2\n3\n",
            strategies=["check", "lines"],
            detect_failure=lambda _: True,
            interesting_str="%r is anything, incl. empty",
            is_expected=lambda _: True,
            expected_run_calls=3,
            n_reports=2,
            reports={"1\n2\n3\n", ""},
            n_other=0,
            other_reports=None,
            result=0,
        ),
        # reproduces, two strategies, 1st no reduce, 2nd testcase reduces to 0
        ReproTestParams(
            original=b"1\n2\n3\n",
            strategies=["check", "lines", "lines"],
            detect_failure=_ignore_arg(
                partial([True, False, False, False, False, True, True, True].pop, 0)
            ),
            interesting_str="%r is anything, only in second strategy",
            is_expected=lambda _: True,
            expected_run_calls=8,
            n_reports=2,
            reports={"1\n2\n3\n", ""},
            n_other=0,
            other_reports=None,
            result=0,
        ),
    ],
)
@mark.usefixtures("reporter_sequential_strftime")
def test_repro(
    mocker,
    tmp_path,
    original,
    strategies,
    detect_failure,
    interesting_str,
    is_expected,
    expected_run_calls,
    n_reports,
    reports,
    n_other,
    other_reports,
    result,
):
    """test ReduceManager, difference scenarios produce correct expected/other
    results"""
    mocker.patch("grizzly.reduce.strategies.lithium._contains_dd", return_value=True)
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(testcases, _time_limit, **kw):
        kw["on_iteration_cb"]()
        for test in testcases:
            contents = test["test.html"].read_text()
            # pylint: disable=logging-not-lazy
            LOG.debug("interesting if " + interesting_str, contents)
            if detect_failure(contents):
                log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
                log_path.mkdir()
                expected = is_expected(contents)
                if expected:
                    _fake_save_logs_foo(log_path)
                else:
                    _fake_save_logs_bar(log_path)
                report = Report(log_path, Path("bin"))
                return [ReplayResult(report, [], expected)]
        return []

    replayer.run.side_effect = replay_run

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(original, test.entry_point)
        test.dump(tmp_path / "src")
    tests = [TestCase.load(tmp_path / "src")]

    log_path = tmp_path / "logs"

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = {}
    target.asset_mgr = mocker.Mock(spec_set=AssetManager)
    with ReduceManager(
        set(),
        mocker.Mock(spec_set=Sapphire, timeout=30),
        target,
        tests,
        strategies,
        log_path,
        use_analysis=False,
    ) as mgr:
        if isinstance(result, type) and issubclass(result, BaseException):
            with raises(result):
                mgr.run()
        else:
            assert mgr.run() == result

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
        assert sum(1 for _ in (log_path / "reports").iterdir()) == n_reports * 2, list(
            (log_path / "reports").iterdir()
        )
    if n_other:
        other_tests = {
            test.read_text() for test in log_path.glob("other_reports/*-0/test.html")
        }
        assert other_tests == other_reports
        assert sum(1 for _ in (log_path / "other_reports").iterdir()) == n_other * 2, (
            list((log_path / "other_reports").iterdir())
        )
    assert replayer.run.call_count == expected_run_calls


def test_report_01(mocker, tmp_path):
    """test that report is called with --report-period is set"""
    mocker.patch("grizzly.reduce.core.time", side_effect=count())

    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(_tests, _time_limit, **kw):
        kw["on_iteration_cb"]()
        if replayer.run.call_count in {20, 40}:
            log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
            log_path.mkdir()
            _fake_save_logs_foo(log_path)
            report = Report(log_path, Path("bin"))
            return [ReplayResult(report, [], True)]
        return []

    replayer.run.side_effect = replay_run

    (tmp_path / "test.html").touch()
    testcase = TestCase.load(tmp_path / "test.html")
    assert testcase
    log_path = tmp_path / "logs"

    fake_strat = mocker.MagicMock(spec_set=Strategy)
    fake_strat.return_value.name = "fake"

    def fake_iter():
        for count_ in range(1, 61):
            LOG.debug("fake_iter() %d", count_)
            (tmp_path / "test.html").write_text(str(count_))
            testcases = [TestCase.load(tmp_path / "test.html")]
            assert testcases
            yield testcases

    fake_strat.return_value.__iter__.side_effect = fake_iter
    mocker.patch("grizzly.reduce.core.STRATEGIES", new={"fake": fake_strat})

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = {}
    target.asset_mgr = mocker.Mock(spec_set=AssetManager)
    with ReduceManager(
        set(),
        mocker.Mock(spec_set=Sapphire, timeout=30),
        target,
        [testcase],
        ["fake"],
        log_path,
        use_analysis=False,
        report_period=30,
    ) as mgr:
        assert mgr.run() == 0

    # should be 2 reports: one made at time=30 (for crash on 20th iter),
    # and one at time=60 (for crash on 40th iter)
    n_reports = 2
    reports = {"20", "40"}
    assert replayer.run.call_count == 60
    expected_dirs = {log_path / "reports"}
    assert set(log_path.iterdir()) == expected_dirs
    tests = {test.read_text() for test in log_path.glob("reports/*-0/test.html")}
    assert tests == reports
    assert sum(1 for _ in (log_path / "reports").iterdir()) == n_reports * 2, list(
        (log_path / "reports").iterdir()
    )


def test_report_02(mocker, tmp_path):
    """test that report is called when KeyboardInterrupt occurs"""
    mocker.patch("grizzly.reduce.core.time", side_effect=count())

    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(_tests, _time_limit, **kw):
        kw["on_iteration_cb"]()
        if replayer.run.call_count in {10, 20}:
            log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
            log_path.mkdir()
            _fake_save_logs_foo(log_path)
            report = Report(log_path, Path("bin"))
            return [ReplayResult(report, [], True)]
        return []

    replayer.run.side_effect = replay_run

    (tmp_path / "test.html").touch()
    testcase = TestCase.load(tmp_path / "test.html")
    assert testcase
    log_path = tmp_path / "logs"

    fake_strat = mocker.MagicMock(spec_set=Strategy)
    fake_strat.return_value.name = "fake"

    def fake_iter():
        for count_ in range(1, 31):
            LOG.debug("fake_iter() %d", count_)
            (tmp_path / "test.html").write_text(str(count_))
            testcases = [TestCase.load(tmp_path / "test.html")]
            assert testcases
            yield testcases
        raise KeyboardInterrupt()

    fake_strat.return_value.__iter__.side_effect = fake_iter
    mocker.patch("grizzly.reduce.core.STRATEGIES", new={"fake": fake_strat})

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = {}
    target.asset_mgr = mocker.Mock(spec_set=AssetManager)

    with (
        ReduceManager(
            set(),
            mocker.Mock(spec_set=Sapphire, timeout=30),
            target,
            [testcase],
            ["fake"],
            log_path,
            use_analysis=False,
        ) as mgr,
        raises(KeyboardInterrupt),
    ):
        mgr.run()

    n_reports = 1
    reports = {"20"}
    assert replayer.run.call_count == 30
    expected_dirs = {log_path / "reports"}
    assert set(log_path.iterdir()) == expected_dirs
    tests = {test.read_text() for test in log_path.glob("reports/*-0/test.html")}
    assert tests == reports
    assert sum(1 for _ in (log_path / "reports").iterdir()) == n_reports * 2, list(
        (log_path / "reports").iterdir()
    )


def test_quality_update(mocker, tmp_path):
    """test that the final result gets changed to REDUCED with --fuzzmanager"""
    mocker.patch("grizzly.reduce.strategies.lithium._contains_dd", return_value=True)
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(testcases, _time_limit, **kw):
        kw["on_iteration_cb"]()
        for test in testcases:
            contents = test["test.html"].read_text()
            if not contents.strip():
                continue
            log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
            log_path.mkdir()
            _fake_save_logs_foo(log_path)
            report = Report(log_path, Path("bin"))
            return [ReplayResult(report, [], True)]
        return []

    replayer.run.side_effect = replay_run

    (tmp_path / "test.html").write_text("123\n")
    testcase = TestCase.load(tmp_path / "test.html")
    assert testcase
    log_path = tmp_path / "logs"

    mocker.patch("grizzly.common.reporter.Collector", autospec=True)
    reporter = mocker.patch("grizzly.reduce.core.FuzzManagerReporter", autospec=True)
    reporter.return_value.submit.return_value = 1234
    update_coll = mocker.patch("grizzly.common.fuzzmanager.Collector")
    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = {}
    target.asset_mgr = mocker.Mock(spec_set=AssetManager)
    with ReduceManager(
        set(),
        mocker.Mock(spec_set=Sapphire, timeout=30),
        target,
        [testcase],
        ["check", "lines"],
        log_path,
        use_analysis=False,
        report_to_fuzzmanager=True,
    ) as mgr:
        assert mgr.run() == 0

    assert reporter.return_value.submit.call_count == 1
    report_args, _ = reporter.return_value.submit.call_args
    assert len(report_args) == 2
    assert isinstance(report_args[0], list)
    assert len(report_args[0]) == 1
    assert isinstance(report_args[0][0], TestCase)
    assert isinstance(report_args[1], Report)
    assert update_coll.call_count == 1
    assert update_coll.return_value.patch.call_count == 1
    assert update_coll.return_value.patch.call_args[1] == {
        "data": {"testcase_quality": Quality.REDUCED},
    }


def test_include_assets_and_environ(mocker, tmp_path):
    """test report with assets and environment variables"""
    mocker.patch("grizzly.reduce.strategies.lithium._contains_dd", return_value=True)
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(testcases, _time_limit, **kw):
        kw["on_iteration_cb"]()
        for test in testcases:
            contents = test["test.html"].read_text()
            if not contents.strip():
                continue
            log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
            log_path.mkdir()
            _fake_save_logs_foo(log_path)
            report = Report(log_path, Path("bin"))
            return [ReplayResult(report, [], True)]
        return []

    replayer.run.side_effect = replay_run

    (tmp_path / "test.html").write_text("123\n")
    testcase = TestCase.load(tmp_path / "test.html")
    assert testcase
    log_path = tmp_path / "logs"

    reporter = mocker.patch("grizzly.reduce.core.FilesystemReporter", autospec=True)

    # pylint: disable=unused-argument
    def submit(test_cases, report, force=False):
        assert test_cases
        assert isinstance(report, Report)
        for test in test_cases:
            assert test.assets.get("example")
            assert test.env_vars == {"test": "abc"}

    reporter.return_value.submit.side_effect = submit

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = {"test": "abc"}
    with AssetManager(base_path=tmp_path) as asset_mgr:
        (tmp_path / "example_asset").touch()
        asset_mgr.add("example", tmp_path / "example_asset", copy=False)
        target.asset_mgr = asset_mgr
        with ReduceManager(
            set(),
            mocker.Mock(spec_set=Sapphire, timeout=30),
            target,
            [testcase],
            ["check", "lines"],
            log_path,
            use_analysis=False,
        ) as mgr:
            assert mgr.run() == 0

    assert reporter.return_value.submit.call_count == 1


TimeoutTestParams = namedtuple(
    "TimeoutTestParams",
    "durations, interesting, static_timeout, idle_input, idle_output, iter_input,"
    "iter_output, result",
)


@mark.parametrize(
    TimeoutTestParams._fields,
    [
        # 0 duration test sets both timeouts to minimum
        TimeoutTestParams(
            durations=[0],
            interesting=True,
            static_timeout=False,
            idle_input=30,
            idle_output=10,
            iter_input=60,
            iter_output=10,
            result=0,
        ),
        # max duration is used
        TimeoutTestParams(
            durations=[0, 30],
            interesting=True,
            static_timeout=False,
            idle_input=30,
            idle_output=30,
            iter_input=60,
            iter_output=60,
            result=0,
        ),
        # static timeout doesn't affect timeouts
        TimeoutTestParams(
            durations=[0],
            interesting=True,
            static_timeout=True,
            idle_input=30,
            idle_output=30,
            iter_input=60,
            iter_output=60,
            result=0,
        ),
        # uninteresting result doesn't affect timeouts
        TimeoutTestParams(
            durations=[0],
            interesting=False,
            static_timeout=True,
            idle_input=30,
            idle_output=30,
            iter_input=60,
            iter_output=60,
            result=NotReproducible,
        ),
        # test duration affects timeouts
        TimeoutTestParams(
            durations=[10],
            interesting=True,
            static_timeout=False,
            idle_input=30,
            idle_output=15,
            iter_input=60,
            iter_output=20,
            result=0,
        ),
    ],
)
def test_timeout_update(
    mocker,
    tmp_path,
    durations,
    interesting,
    static_timeout,
    idle_input,
    idle_output,
    iter_input,
    iter_output,
    result,
):
    "timeout will be updated based on time to crash"
    mocker.patch("grizzly.reduce.strategies.lithium._contains_dd", return_value=True)
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(_testcases, _time_limit, **kw):
        kw["on_iteration_cb"]()
        LOG.debug("interesting true")
        log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
        log_path.mkdir()
        _fake_save_logs_foo(log_path)
        report = Report(log_path, Path("bin"))
        return [ReplayResult(report, durations, interesting)]

    replayer.run.side_effect = replay_run

    (tmp_path / "test.html").touch()
    test = TestCase.load(tmp_path / "test.html")
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = {}
    target.asset_mgr = mocker.Mock(spec_set=AssetManager)
    server = mocker.Mock(spec_set=Sapphire, timeout=iter_input)
    with ReduceManager(
        set(),
        server,
        target,
        [test],
        ["check"],
        log_path,
        use_analysis=False,
        idle_delay=idle_input,
        static_timeout=static_timeout,
    ) as mgr:
        if isinstance(result, type) and issubclass(result, BaseException):
            with raises(result):
                mgr.run()
        else:
            assert mgr.run() == result

    assert server.timeout == iter_output
    assert mgr._idle_delay == idle_output
