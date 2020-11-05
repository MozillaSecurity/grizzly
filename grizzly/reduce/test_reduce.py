# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.reduce`.
"""
from collections import namedtuple
import functools
from logging import getLogger

import pytest
from pytest import raises

from sapphire import Sapphire
from ..common import TestCase, Report
from ..replay import ReplayResult
from ..target import Target, TargetLaunchError, TargetLaunchTimeout
from . import ReduceManager
from .exceptions import NotReproducible


LOG = getLogger(__name__)
pytestmark = pytest.mark.usefixtures("tmp_path_fm_config")


def _fake_save_logs_foo(result_logs, meta=False):  # pylint: disable=unused-argument
    """write fake log data to disk"""
    (result_logs / "log_stderr.txt").write_text("STDERR log\n")
    (result_logs / "log_stdout.txt").write_text("STDOUT log\n")
    (result_logs / "log_asan_blah.txt").write_text(
        "==1==ERROR: AddressSanitizer: "
        "SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n"
        "    #0 0xbad000 in foo /file1.c:123:234\n"
        "    #1 0x1337dd in bar /file2.c:1806:19\n"
    )


def _fake_save_logs_bar(result_logs, meta=False):  # pylint: disable=unused-argument
    """write fake log data to disk"""
    (result_logs / "log_stderr.txt").write_text("STDERR log\n")
    (result_logs / "log_stdout.txt").write_text("STDOUT log\n")
    (result_logs / "log_asan_blah.txt").write_text(
        "==1==ERROR: AddressSanitizer: "
        "SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n"
        "    #0 0xbad000 in bar /file1.c:123:234\n"
        "    #1 0x1337dd in foo /file2.c:1806:19\n"
    )


AnalysisTestParams = namedtuple(
    "AnalysisTestParams",
    "crashes, expected_repeat, expected_min_crashes, use_harness, result_harness"
)


@pytest.mark.parametrize(
    AnalysisTestParams._fields,
    [
        # perfect with harness
        AnalysisTestParams([True] * 11, 2, 2, True, True),
        # perfect without harness
        AnalysisTestParams([False] * 11 + [True] * 11, 2, 2, True, False),
        # perfect, use_harness=False
        AnalysisTestParams([True] * 11, 2, 2, False, False),
        # better without harness
        AnalysisTestParams([True] + [False] * 19 + [True] * 2, 30, 2, True, False),
        # better with harness
        AnalysisTestParams([True] * 2 + [False] * 19 + [True], 30, 2, True, True),
        # same with both, prefer harness
        AnalysisTestParams([True] * 2 + [False] * 18 + [True] * 2, 30, 2, True, True),
    ]
)
def test_analysis(mocker, tmp_path, crashes, expected_repeat, expected_min_crashes,
                  use_harness, result_harness):
    """test that analysis sets reasonable params"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value.__enter__.return_value
    replayer.status.iteration = 11
    expected_iters = len(crashes) / 11

    def replay_run(_, **kw):
        results = []
        repeat = kw["repeat"]
        assert repeat <= len(crashes)
        assert not kw["exit_early"]
        for _ in range(repeat):
            LOG.debug("interesting: %r", crashes[0])
            if crashes.pop(0):
                log_path = tmp_path / (
                    "crash%d_logs" % (replayer.run.call_count,)
                )
                log_path.mkdir(exist_ok=True)
                _fake_save_logs_foo(log_path)
                report = Report(str(log_path), "bin")
                results.append(ReplayResult(report, [["test.html"]], [], True))
        return results
    replayer.run.side_effect = replay_run

    test = TestCase("test.html", None, "test-adapter")
    test.add_from_data("", "test.html")
    tests = [test]
    log_path = tmp_path / "logs"

    class _ReduceStats:
        def __init__(self):
            self._iters = 0

        def add_iterations(self, iters):
            self._iters += iters

        @staticmethod
        def _stop_early(_):
            pass

    stats = _ReduceStats()
    try:
        mgr = ReduceManager(None, mocker.Mock(spec=Sapphire), mocker.Mock(spec=Target),
                            tests, None, log_path, use_harness=use_harness)
        repeat, min_crashes, _ = mgr.run_reliability_analysis(stats)
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.run.call_count == expected_iters
    assert repeat == expected_repeat
    assert min_crashes == expected_min_crashes
    assert mgr._use_harness == result_harness
    assert stats._iters == expected_iters * 11


def _ignore_arg(func):
    """Function wrapper that simply ignores 1 argument"""
    @functools.wraps(func)
    def wrapped(_):
        return func()
    return wrapped


ReproTestParams = namedtuple(
    "ReproTestParams",
    "original, strategies, detect_failure, interesting_str, is_expected,"
    "expected_run_calls, n_reports, reports, n_other, other_reports, result"
)


@pytest.mark.parametrize(
    ReproTestParams._fields,
    [
        # no repro
        ReproTestParams(
            original="123456\n",
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
            original="1\n2\n3\n",
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
            original="odd\neven\n" * 3,
            strategies=["check", "lines"],
            detect_failure=lambda contents: sum(1 for line in contents.splitlines()
                                                if line == "odd") == 3,
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
            original="1\n2\n3\n",
            strategies=["check", "lines"],
            detect_failure=bool,
            interesting_str="%r != ''",
            is_expected=lambda contents: contents == "1\n2\n3\n",
            expected_run_calls=6,
            n_reports=1,
            reports={"1\n2\n3\n"},
            n_other=5,
            other_reports={"1\n", "3\n", "1\n2\n", "1\n3\n", "2\n3\n"},
            result=0,
        ),
        # reproduces, 50% iterations work, 1 iteration produces other sig
        ReproTestParams(
            original="1\n2\n3\n4\n5\n6\n",
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
            original="A1\nA2\nA3\nA4\nA5\nA6\n",
            strategies=["check", "lines", "chars"],
            detect_failure=(
                lambda contents: (
                    len(contents.splitlines()) == 6
                    and set(contents.splitlines()) >= {"A1", "A3", "A5"})),
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
            original="A1\nA2\nA3\nA4\nA5\nA6\n",
            strategies=["check", "lines", "chars"],
            detect_failure=(
                lambda contents: (set(contents.splitlines(keepends=True))
                                  >= {"A1\n", "A3\n", "A5\n"})),
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
            original="1\n2\n3\n",
            strategies=["check", "lines", "chars"],
            detect_failure=bool,
            interesting_str="%r != ''",
            is_expected=lambda contents: contents == "1\n2\n3\n",
            expected_run_calls=16,
            n_reports=1,
            reports={"1\n2\n3\n"},
            n_other=15,
            other_reports={"\n2\n3\n", "1\n", "1\n\n3\n", "1\n2\n", "1\n2\n\n",
                           "1\n2\n3", "1\n23\n", "1\n3\n", "12\n3\n", "2\n3\n", "3\n"},
            result=0,
        ),
        # reproduces, one strategy, testcase reduces to 0
        ReproTestParams(
            original="1\n2\n3\n",
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
            original="1\n2\n3\n",
            strategies=["check", "lines", "lines"],
            detect_failure=_ignore_arg(
                functools.partial(
                    [True, False, False, False, False, False, True, True].pop, 0)),
            interesting_str="%r is anything, only in second strategy",
            is_expected=lambda _: True,
            expected_run_calls=8,
            n_reports=2,
            reports={"1\n2\n3\n", ""},
            n_other=0,
            other_reports=None,
            result=0,
        ),
    ]
)
@pytest.mark.usefixtures("reporter_sequential_strftime")
def test_repro(mocker, tmp_path, original, strategies, detect_failure, interesting_str,
               is_expected, expected_run_calls, n_reports, reports, n_other,
               other_reports, result):
    """test ReduceManager, difference scenarios produce correct expected/other
    results"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value
    replayer.status.iteration = 1

    def replay_run(testcases, **_):
        for test in testcases:
            contents = test.get_file("test.html").data.decode("ascii")
            # pylint: disable=logging-not-lazy
            LOG.debug("interesting if " + interesting_str, contents)
            if detect_failure(contents):
                log_path = tmp_path / (
                    "crash%d_logs" % (replayer.run.call_count,)
                )
                log_path.mkdir()
                expected = is_expected(contents)
                if expected:
                    _fake_save_logs_foo(log_path)
                else:
                    _fake_save_logs_bar(log_path)
                report = Report(str(log_path), "bin")
                return [ReplayResult(report, [["test.html"]], [], expected)]
        return []
    replayer.run.side_effect = replay_run

    test = TestCase("test.html", None, "test-adapter")
    test.add_from_data(original, "test.html")
    tests = [test]
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec=Target)
    target.relaunch = 1
    try:
        mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target, tests, strategies,
                            log_path, use_analysis=False)
        if isinstance(result, type) and issubclass(result, BaseException):
            with raises(result):
                mgr.run()
        else:
            assert mgr.run() == result
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.run.call_count == expected_run_calls
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
        other_tests = {test.read_text()
                       for test in log_path.glob("other_reports/*-0/test.html")}
        assert other_tests == other_reports
        assert len(list((log_path / "other_reports").iterdir())) \
            == n_other * 2, list((log_path / "other_reports").iterdir())


def test_quality_update(mocker, tmp_path):
    """test that the final result gets changed to Q0 with --fuzzmanager"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value
    replayer.status.iteration = 1

    def replay_run(_, **_kw):
        log_path = tmp_path / ("crash%d_logs" % (replayer.run.call_count,))
        log_path.mkdir()
        _fake_save_logs_foo(log_path)
        report = Report(str(log_path), "bin")
        return [ReplayResult(report, [["test.html"]], [], True)]
    replayer.run.side_effect = replay_run

    (tmp_path / "test.html").touch()
    testcases = TestCase.load(str(tmp_path / "test.html"), False)
    assert testcases
    log_path = tmp_path / "logs"

    mocker.patch("grizzly.common.reporter.Collector")
    reporter = mocker.patch("grizzly.reduce.core.FuzzManagerReporter")
    update_coll = mocker.patch("grizzly.reduce.core.Collector")
    target = mocker.Mock(spec=Target)
    target.relaunch = 1
    try:
        mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target, testcases,
                            ["check"], log_path, use_analysis=False,
                            report_to_fuzzmanager=True)
        assert mgr.run()
    finally:
        for test in testcases:
            test.cleanup()

    assert reporter.return_value.submit.call_count == 1
    report_args, report_kwds = reporter.return_value.submit.call_args
    assert len(report_args) == 1
    assert isinstance(report_args[0], list)
    assert len(report_args[0]) == 1
    assert isinstance(report_args[0][0], TestCase)
    assert report_kwds.keys() == {"report"}
    assert update_coll.call_count == 1
    assert update_coll.return_value.patch.call_count == 1
    assert update_coll.return_value.patch.call_args[1] == {
        "data": {"testcase_quality": reporter.QUAL_REDUCED_RESULT},
    }


@pytest.mark.parametrize("use_analysis", [True, False])
@pytest.mark.parametrize("exc_type", [TargetLaunchError, TargetLaunchTimeout])
def test_launch_error(mocker, tmp_path, use_analysis, exc_type):
    """test that launch errors are reported"""
    report_fcn = mocker.patch("grizzly.reduce.core.ReduceManager.report", autospec=True)
    replay_mock = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    if exc_type is TargetLaunchError:
        report_obj = mocker.Mock(spec=Report)
        replay_mock.return_value.__enter__.return_value.run.side_effect = \
            TargetLaunchError("msg", report_obj)
        replay_mock.return_value.run.side_effect = TargetLaunchError("msg", report_obj)
    else:
        replay_mock.return_value.__enter__.return_value.run.side_effect = \
            TargetLaunchTimeout("msg")
        replay_mock.return_value.run.side_effect = TargetLaunchTimeout("msg")

    (tmp_path / "test.html").touch()
    testcases = TestCase.load(str(tmp_path / "test.html"), False)
    assert testcases

    target_obj = mocker.Mock(spec=Target)
    target_obj.relaunch = 1
    mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target_obj, testcases,
                        ["check"], None, use_analysis=use_analysis)
    with raises(exc_type):
        mgr.run()
    if exc_type is TargetLaunchError:
        assert report_fcn.call_count == 1
        _mgr, reports, reported_testcases, _stats = report_fcn.call_args[0]
        if use_analysis:
            assert reported_testcases == testcases
        else:
            # should be testcases reported, but from the strategy, not the original
            assert reported_testcases
            assert reported_testcases != testcases
        assert len(reports) == 1
        assert reports[0].report == report_obj
        assert report_obj.cleanup.call_count == 1
    else:
        assert report_fcn.call_count == 0


TimeoutTestParams = namedtuple(
    "TimeoutTestParams",
    "durations, interesting, static_timeout, idle_input, idle_output, iter_input,"
    "iter_output, result"
)


@pytest.mark.parametrize(
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
    ]
)
def test_timeout_update(mocker, tmp_path, durations, interesting, static_timeout,
                        idle_input, idle_output, iter_input, iter_output, result):
    "timeout will be updated based on time to crash"
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value
    replayer.status.iteration = 1

    def replay_run(_testcases, **_):
        LOG.debug("interesting true")
        log_path = tmp_path / ("crash%d_logs" % (replayer.run.call_count,))
        log_path.mkdir()
        _fake_save_logs_foo(log_path)
        report = Report(str(log_path), "bin")
        return [ReplayResult(report, [["test.html"]], durations, interesting)]
    replayer.run.side_effect = replay_run

    test = TestCase("test.html", None, "test-adapter")
    test.add_from_data("123\n", "test.html")
    tests = [test]
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec=Target)
    target.relaunch = 1
    server = mocker.Mock(spec=Sapphire)
    server.timeout = iter_input
    try:
        mgr = ReduceManager([], server, target, tests, ["check"], log_path,
                            use_analysis=False, idle_delay=idle_input,
                            static_timeout=static_timeout)
        mgr.IDLE_DELAY_MIN = 10
        mgr.IDLE_DELAY_DURATION_MULTIPLIER = 1.5
        mgr.ITER_TIMEOUT_MIN = 10
        mgr.ITER_TIMEOUT_DURATION_MULTIPLIER = 2
        if isinstance(result, type) and issubclass(result, BaseException):
            with raises(result):
                mgr.run()
        else:
            assert mgr.run() == result
    finally:
        for test in tests:
            test.cleanup()

    assert server.timeout == iter_output
    assert mgr._idle_delay == idle_output
