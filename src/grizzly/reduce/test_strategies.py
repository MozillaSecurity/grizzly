# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.strategies`."""
from collections import namedtuple
from logging import getLogger
from pathlib import Path

from pytest import mark, raises

from sapphire import Sapphire

from ..common.report import Report
from ..common.storage import TestCase
from ..replay import ReplayResult
from ..target import AssetManager, Target
from . import ReduceManager
from .strategies import Strategy, _load_strategies

LOG = getLogger(__name__)
pytestmark = mark.usefixtures(
    "reporter_sequential_strftime",
    "tmp_path_status_db_reduce",
)


@mark.parametrize("is_hang", [True, False])
def test_strategy_tc_load(tmp_path, is_hang):
    """test that strategy base class dump and load doesn't change testcase metadata"""

    class _TestStrategy(Strategy):
        def __iter__(self):
            yield [TestCase.load(x) for x in sorted(self._testcase_root.iterdir())]

        def update(self, success):
            pass

    # create testcase
    with TestCase("a.htm", "adpt", input_fname="fn") as test:
        test.duration = 1.2
        test.hang = is_hang
        test.add_from_bytes(b"123", test.entry_point)
        test.dump(tmp_path / "src", include_details=True)

    with _TestStrategy([TestCase.load(tmp_path / "src")]) as strategy:
        for attempt in strategy:
            assert len(attempt) == 1
            assert attempt[0].hang == is_hang
            strategy.update(False)


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


def test_strategy_load_fail(mocker):
    """test that a broken strategy doesn't block other strategies"""

    class _GoodStrategy(Strategy):
        name = "good"

        @classmethod
        def load(cls):
            return cls

    class _BadStrategy:
        name = "bad"

        @classmethod
        def load(cls):
            raise RuntimeError("oops")

    mocker.patch(
        "grizzly.reduce.strategies.iter_entry_points",
        return_value=(_BadStrategy, _GoodStrategy),
    )
    mocker.patch("grizzly.reduce.strategies.DEFAULT_STRATEGIES", new=("good",))
    result = _load_strategies()
    assert result == {"good": _GoodStrategy}

    # missing strategy in defaults should raise
    mocker.patch("grizzly.reduce.strategies.DEFAULT_STRATEGIES", new=("good", "bad"))
    with raises(AssertionError):
        _load_strategies()


ListStrategyParams = namedtuple(
    "ListStrategyParams",
    "test_data, strategies, required_first, expected_run_calls, expected_results,"
    "expected_num_reports",
)


@mark.parametrize(
    ListStrategyParams._fields,
    [
        # "list" is a no-op with a single testcase
        ListStrategyParams(
            test_data=[b"123"],
            strategies=["check", "list"],
            required_first=False,
            expected_run_calls=1,
            expected_results={"123"},
            expected_num_reports=2,
        ),
        # "list" reduces a list of testcases down to one required
        ListStrategyParams(
            test_data=[b"", b"", b"123", b""],
            strategies=["list"],
            required_first=False,
            expected_run_calls=4,
            expected_results={"123"},
            expected_num_reports=2,
        ),
        # "list" reduces a list of testcases down to two required
        ListStrategyParams(
            test_data=[b"", b"required", b"123", b""],
            strategies=["list"],
            required_first=True,
            expected_run_calls=4,
            expected_results={"required", "123"},
            expected_num_reports=3,
        ),
    ],
)
def test_list(
    mocker,
    tmp_path,
    test_data,
    strategies,
    required_first,
    expected_run_calls,
    expected_results,
    expected_num_reports,
):
    """tests for the "list" strategy"""
    mocker.patch("grizzly.reduce.strategies.lithium._contains_dd", return_value=True)
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(testcases, _time_limit, **kw):
        kw["on_iteration_cb"]()
        required_seen = False
        for test in testcases:
            contents = test["test.html"].read_text()
            LOG.debug("interesting if %r == '123'", contents)
            if contents == "required" and required_first:
                required_seen = True
            elif contents == "123" and (required_seen or not required_first):
                log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(log_path, Path("bin"))
                return [ReplayResult(report, [], True)]
        return []

    replayer.run.side_effect = replay_run

    tests = []
    for num, data in enumerate(test_data):
        with TestCase("test.html", "test-adapter") as test:
            test.add_from_bytes(data, test.entry_point)
            test.dump(tmp_path / "src" / f"{num:02d}", include_details=True)
        tests.append(TestCase.load(tmp_path / "src" / f"{num:02d}"))
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
        assert mgr.run() == 0

    assert replayer.run.call_count == expected_run_calls
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text() for test in log_path.glob("reports/*-*/test.html")}
    assert tests == expected_results
    assert (
        sum(1 for _ in (log_path / "reports").iterdir()) == expected_num_reports
    ), list((log_path / "reports").iterdir())


def test_dd_only(mocker, tmp_path):
    """test that only files containing DDBEGIN/END are reduced"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(testcases, _time_limit, **kw):
        kw["on_iteration_cb"]()
        for test in testcases:
            contents = test["test.html"].read_text()
            LOG.debug("interesting if 'required' in %r", contents)
            interesting = "required" in contents
            if interesting:
                log_path = tmp_path / f"crash{replayer.run.call_count}_logs"
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(log_path, Path("bin"))
                return [ReplayResult(report, [], True)]
        return []

    replayer.run.side_effect = replay_run

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"DDBEGIN\n123\nrequired\nDDEND\n", "test.html")
        test.add_from_bytes(b"blah\n", "other.html")
        test.dump(tmp_path / "src", include_details=True)
    test = TestCase.load(tmp_path / "src", catalog=True)
    tests = [test]
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = {}
    target.asset_mgr = mocker.Mock(spec_set=AssetManager)
    with ReduceManager(
        set(),
        mocker.Mock(spec_set=Sapphire, timeout=30),
        target,
        tests,
        ["lines"],
        log_path,
        use_analysis=False,
    ) as mgr:
        assert mgr.run() == 0

    expected_run_calls = 3
    expected_results = {"DDBEGIN\nrequired\nDDEND\n"}
    expected_num_reports = 2

    assert replayer.run.call_count == expected_run_calls
    assert set(log_path.iterdir()) == {log_path / "reports"}
    assert len(tuple(log_path.glob("reports/*-*/*.html"))) == 2
    tests = {test.read_text() for test in log_path.glob("reports/*-*/test.html")}
    assert tests == expected_results
    assert (
        sum(1 for _ in (log_path / "reports").iterdir()) == expected_num_reports
    ), list((log_path / "reports").iterdir())
    others = {test.read_text() for test in log_path.glob("reports/*-*/other.html")}
    assert others == {"blah\n"}
