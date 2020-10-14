# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.reduce.strategies
"""
from collections import namedtuple
from logging import getLogger
from pathlib import Path

import pytest
from pytest import raises

from sapphire import Sapphire
from ..common import TestCase, Report
from ..replay import ReplayResult
from ..target import Target
from .strategies import _load_strategies, HAVE_CSSBEAUTIFIER, HAVE_JSBEAUTIFIER
from . import ReduceManager


LOG = getLogger(__name__)
pytestmark = pytest.mark.usefixtures("tmp_path_fm_config")  # pylint: disable=invalid-name


def _fake_save_logs_foo(result_logs):
    """write fake log data to disk"""
    (Path(result_logs) / "log_stderr.txt").write_text("STDERR log\n")
    (Path(result_logs) / "log_stdout.txt").write_text("STDOUT log\n")
    (Path(result_logs) / "log_asan_blah.txt").write_text(
        "==1==ERROR: AddressSanitizer: "
        "SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n"
        "    #0 0xbad000 in foo /file1.c:123:234\n"
        "    #1 0x1337dd in bar /file2.c:1806:19\n"
    )


def test_strategy_load_fail(mocker):
    """test that a broken strategy doesn't block other strategies"""
    class _GoodStrategy(object):
        name = "good"
        @classmethod
        def load(cls):
            return cls

    class _BadStrategy(object):
        name = "bad"
        @classmethod
        def load(cls):
            raise RuntimeError("oops")

    def entries(_):
        yield _BadStrategy
        yield _GoodStrategy

    mocker.patch("grizzly.reduce.strategies.iter_entry_points", side_effect=entries)
    mocker.patch("grizzly.reduce.strategies.DEFAULT_STRATEGIES", new=("good",))
    result = _load_strategies()
    assert result == {"good": _GoodStrategy}

    # missing strategy in defaults should raise
    mocker.patch("grizzly.reduce.strategies.DEFAULT_STRATEGIES", new=("good", "bad"))
    with raises(AssertionError):
        _load_strategies()


ListStrategyParams = namedtuple(
    "ListStrategyParams",
    "test_data, strategies, required_first, expected_run_calls, expected_results, expected_num_reports"
)


@pytest.mark.parametrize(
    ListStrategyParams._fields,
    [
        # "list" is a no-op with a single testcase
        ListStrategyParams(
            test_data=["123"],
            strategies=["check", "list"],
            required_first=False,
            expected_run_calls=1,
            expected_results={"123"},
            expected_num_reports=2,
        ),
        # "list" reduces a list of testcases down to one required
        ListStrategyParams(
            test_data=["", "", "123", ""],
            strategies=["list"],
            required_first=False,
            expected_run_calls=4,
            expected_results={"123"},
            expected_num_reports=2,
        ),
        # "list" reduces a list of testcases down to two required
        ListStrategyParams(
            test_data=["", "required", "123", ""],
            strategies=["list"],
            required_first=True,
            expected_run_calls=4,
            expected_results={"required", "123"},
            expected_num_reports=3,
        ),
    ]
)
def test_list(mocker, tmp_path, test_data, strategies, required_first, expected_run_calls, expected_results,
              expected_num_reports):
    """tests for the "list" strategy"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)

    def replay_run(testcases, **_):
        required_seen = False
        for test in testcases:
            contents = test.get_file("test.html").data.decode("ascii")
            LOG.debug("interesting if %r == '123'", contents)
            if contents == "required" and required_first:
                required_seen = True
            elif contents == "123" and (required_seen or not required_first):
                log_path = tmp_path / ("crash%d_logs" % (replayer.return_value.run.call_count,))
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(str(log_path), "bin")
                return [ReplayResult(report, ["test.html"], [], True)]
        return []
    replayer.return_value.run.side_effect = replay_run

    tests = []
    for data in test_data:
        test = TestCase("test.html", None, "test-adapter")
        test.add_from_data(data, "test.html")
        tests.append(test)
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec=Target)
    target.relaunch = 1
    try:
        mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target, tests, strategies, log_path,
                            use_analysis=False)
        assert mgr.run()
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.return_value.run.call_count == expected_run_calls
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text() for test in log_path.glob("reports/*-*/test.html")}
    assert tests == expected_results
    assert len(list((log_path / "reports").iterdir())) == expected_num_reports, \
        list((log_path / "reports").iterdir())


BeautifyStrategyParams = namedtuple(
    "BeautifyStrategyParams",
    "test_data, test_name, expected_run_calls, expected_results, expected_num_reports, strategies"
)


@pytest.mark.parametrize(
    BeautifyStrategyParams._fields,
    [
        # test beautify a .js file
        pytest.param(
            *BeautifyStrategyParams(
                test_data="try{'fluff';'required'}catch(e){}\n",
                test_name="test.js",
                expected_run_calls=6,
                expected_results={"'required'"},
                expected_num_reports=2,
                strategies=["jsbeautify", "lines"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER, reason="jsbeautifier required"),
        ),
        # test beautify js embedded in html
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<script>try{'fluff';'required'}catch(e){}</script>\n",
                test_name="test.html",
                expected_run_calls=7,
                expected_results={"'required'"},
                expected_num_reports=2,
                strategies=["jsbeautify", "lines"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER, reason="jsbeautifier required"),
        ),
        # test beautify a .css file
        pytest.param(
            *BeautifyStrategyParams(
                test_data="*,#a{fluff:0;required:1}\n",
                test_name="test.css",
                expected_run_calls=8,
                expected_results={"required: 1"},
                expected_num_reports=2,
                strategies=["cssbeautify", "lines"],
            ),
            marks=pytest.mark.skipif(not HAVE_CSSBEAUTIFIER, reason="cssbeautifier required"),
        ),
        # test beautify css embedded in html
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<style>*,#a{fluff:0;required:1}</style>\n",
                test_name="test.html",
                expected_run_calls=6,
                expected_results={"required: 1"},
                expected_num_reports=2,
                strategies=["cssbeautify", "lines"],
            ),
            marks=pytest.mark.skipif(not HAVE_CSSBEAUTIFIER, reason="cssbeautifier required"),
        ),
    ]
)
def test_beautifier(mocker, tmp_path, test_data, test_name, expected_run_calls, expected_results,
                    expected_num_reports, strategies):
    """test for the "beautify" strategies"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)

    def replay_run(testcases, **_):
        for test in testcases:
            contents = test.get_file(test_name).data.decode("ascii")
            LOG.debug("interesting if 'required' in %r", contents)
            if "required" in contents:
                log_path = tmp_path / ("crash%d_logs" % (replayer.return_value.run.call_count,))
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(str(log_path), "bin")
                return [ReplayResult(report, [test_name], [], True)]
        return []
    replayer.return_value.run.side_effect = replay_run

    test = TestCase(test_name, None, "test-adapter")
    test.add_from_data(test_data, test_name)
    tests = [test]
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec=Target)
    target.relaunch = 1
    try:
        mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target, tests, strategies, log_path,
                            use_analysis=False)
        assert mgr.run()
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.return_value.run.call_count == expected_run_calls
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text().strip() for test in log_path.glob("reports/*-*/" + test_name)}
    assert tests == expected_results
    assert len(list((log_path / "reports").iterdir())) == expected_num_reports, \
        list((log_path / "reports").iterdir())
