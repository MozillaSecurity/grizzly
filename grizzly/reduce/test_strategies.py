# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.strategies`."""
from collections import namedtuple
from logging import getLogger

from pytest import mark, raises

from sapphire import Sapphire

from ..common.reporter import Report
from ..common.storage import TestCase
from ..replay import ReplayResult
from ..target import AssetManager, Target
from . import ReduceManager
from .strategies import Strategy, _load_strategies

LOG = getLogger(__name__)
pytestmark = mark.usefixtures(
    "reporter_sequential_strftime",
    "tmp_path_fm_config",
    "tmp_path_replay_status_db",
    "tmp_path_reduce_status_db",
)


@mark.parametrize("is_hang", [True, False])
def test_strategy_tc_load(is_hang):
    """test that strategy base class dump and load doesn't change testcase metadata"""

    class _TestStrategy(Strategy):
        def __iter__(self):
            yield TestCase.load(str(self._testcase_root), False)

        def update(self, success, served=None):
            pass

    # create testcase that is_hang
    with TestCase("a.htm", None, "adpt", input_fname="fn", time_limit=2) as src:
        src.duration = 1.2
        src.hang = is_hang
        src.add_from_bytes(b"123", "a.htm")
        strategy = _TestStrategy([src])
    for attempt in strategy:
        assert len(attempt) == 1
        assert attempt[0].hang == is_hang
        attempt[0].cleanup()
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

    class _GoodStrategy:
        name = "good"

        @classmethod
        def sanity_check_cls_attrs(cls):
            pass

        @classmethod
        def load(cls):
            return cls

    class _BadStrategy:
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
            contents = test.get_file("test.html").data_file.read_text()
            LOG.debug("interesting if %r == '123'", contents)
            if contents == "required" and required_first:
                required_seen = True
            elif contents == "123" and (required_seen or not required_first):
                log_path = tmp_path / ("crash%d_logs" % (replayer.run.call_count,))
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(str(log_path), "bin")
                return [
                    ReplayResult(report, [["test.html"]] * len(testcases), [], True)
                ]
        return []

    replayer.run.side_effect = replay_run

    tests = []
    for data in test_data:
        test = TestCase("test.html", None, "test-adapter")
        test.add_from_bytes(data, "test.html")
        tests.append(test)
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = dict()
    target.assets = mocker.Mock(spec_set=AssetManager)
    try:
        mgr = ReduceManager(
            [],
            mocker.Mock(spec_set=Sapphire, timeout=30),
            target,
            tests,
            strategies,
            log_path,
            use_analysis=False,
        )
        assert mgr.run() == 0
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.run.call_count == expected_run_calls
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text() for test in log_path.glob("reports/*-*/test.html")}
    assert tests == expected_results
    assert (
        sum(1 for _ in (log_path / "reports").iterdir()) == expected_num_reports
    ), list((log_path / "reports").iterdir())


PurgeUnservedTestParams = namedtuple(
    "PurgeUnservedTestParams",
    "strategies, test_data, served, expected_results, expected_run_calls,"
    "expected_num_reports, purging_breaks",
)


@mark.parametrize(
    PurgeUnservedTestParams._fields,
    [
        # single test, first reduction uses 2 files, second uses only target file.
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[{"test.html": b"123", "opt.html": b"456"}],
            served=[[["test.html", "opt.html"]], [["test.html"]], [["test.html"]]],
            expected_results={"1"},
            expected_run_calls=5,
            expected_num_reports=2,
            purging_breaks=False,
        ),
        # single test, first reduction uses target only
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[{"test.html": b"123", "opt.html": b"456"}],
            served=[[["test.html"]], [["test.html"]]],
            expected_results={"1"},
            expected_run_calls=3,
            expected_num_reports=2,
            purging_breaks=False,
        ),
        # single test, first reduction uses 2 files, second uses only optional file.
        # (no results -> Assertion)
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[{"test.html": b"123", "opt.html": b"456"}],
            served=[[["test.html", "opt.html"]], [["opt.html"]]],
            expected_results=set(),
            expected_run_calls=4,
            expected_num_reports=None,
            purging_breaks=True,
        ),
        # double test, first reduction uses all files, second uses only target file in
        # second test.
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[
                {"test.html": b"123", "opt.html": b"456"},
                {"test.html": b"789", "opt.html": b"abc"},
            ],
            served=[
                [["test.html", "opt.html"], ["test.html", "opt.html"]],
                [["test.html", "opt.html"], ["test.html"]],
                [["test.html", "opt.html"], ["test.html"]],
            ],
            expected_results={"1", "4", "7"},
            expected_run_calls=6,
            expected_num_reports=3,
            purging_breaks=False,
        ),
        # double test, first reduction uses all files, second uses only optional file
        # (first test remains)
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[
                {"test.html": b"123", "opt.html": b"456"},
                {"test.html": b"789", "opt.html": b"abc"},
            ],
            served=[
                [["test.html", "opt.html"], ["test.html", "opt.html"]],
                [["test.html", "opt.html"], ["opt.html"]],
                [["test.html", "opt.html"]],
            ],
            expected_results={"1", "4"},
            expected_run_calls=5,
            expected_num_reports=2,
            purging_breaks=False,
        ),
        # triple test, list strategy. first test gets reduced, third gets eliminated
        PurgeUnservedTestParams(
            strategies=["list"],
            test_data=[
                {"test.html": b"123"},
                {"test.html": b"456"},
                {"test.html": b"789"},
            ],
            served=[[["test.html"]], [["test.html"]], [["test.html"]]],
            expected_results={"456"},
            expected_run_calls=2,
            expected_num_reports=2,
            purging_breaks=False,
        ),
        # triple test, list strategy. None for served still eliminates first two tests
        PurgeUnservedTestParams(
            strategies=["list"],
            test_data=[
                {"test.html": b"123"},
                {"test.html": b"456"},
                {"test.html": b"789"},
            ],
            served=[None, None, None],
            expected_results={"789"},
            expected_run_calls=2,
            expected_num_reports=2,
            purging_breaks=False,
        ),
    ],
)
def test_purge_unserved(
    mocker,
    tmp_path,
    strategies,
    test_data,
    served,
    expected_results,
    expected_run_calls,
    expected_num_reports,
    purging_breaks,
):
    """test purging unserved files"""
    mocker.patch("grizzly.reduce.strategies.lithium._contains_dd", return_value=True)
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)
    replayer = replayer.return_value

    def replay_run(testcases, _time_limit, **kw):
        kw["on_iteration_cb"]()
        # test.html and opt.html should always contain one line.
        # return [] (no result) if either of them exist and are empty
        has_any = False
        for test in testcases:
            for file in ("test.html", "opt.html"):
                if file in test.contents:
                    LOG.debug("testcase contains %s", file)
                    has_any = True
                    contents = test.get_file(file).data_file.read_text()
                    if not contents.strip():
                        return []
        if not has_any:
            return []
        log_path = tmp_path / ("crash%d_logs" % (replayer.run.call_count,))
        log_path.mkdir()
        _fake_save_logs_foo(log_path)
        report = Report(str(log_path), "bin")
        return [ReplayResult(report, served.pop(0), [], True)]

    replayer.run.side_effect = replay_run

    tests = []
    for testcase in test_data:
        test = TestCase("test.html", None, "test-adapter")
        for filename, data in testcase.items():
            test.add_from_bytes(data, filename)
        tests.append(test)
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = dict()
    target.assets = mocker.Mock(spec_set=AssetManager)
    try:
        mgr = ReduceManager(
            [],
            mocker.Mock(spec_set=Sapphire, timeout=30),
            target,
            tests,
            strategies,
            log_path,
            use_analysis=False,
        )
        if purging_breaks:
            with raises(AssertionError):
                mgr.run()
        else:
            assert mgr.run() == 0
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.run.call_count == expected_run_calls
    if purging_breaks:
        return
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text() for test in log_path.glob("reports/*-*/*.html")}
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
            contents = test.get_file("test.html").data_file.read_text()
            LOG.debug("interesting if 'required' in %r", contents)
            interesting = "required" in contents
            if interesting:
                log_path = tmp_path / ("crash%d_logs" % (replayer.run.call_count,))
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(str(log_path), "bin")
                return [ReplayResult(report, [["test.html", "other.html"]], [], True)]
        return []

    replayer.run.side_effect = replay_run

    test = TestCase("test.html", None, "test-adapter")
    test.add_from_bytes(b"DDBEGIN\n123\nrequired\nDDEND\n", "test.html")
    test.add_from_bytes(b"blah\n", "other.html")
    tests = [test]
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec_set=Target)
    target.filtered_environ.return_value = dict()
    target.assets = mocker.Mock(spec_set=AssetManager)
    try:
        mgr = ReduceManager(
            [],
            mocker.Mock(spec_set=Sapphire, timeout=30),
            target,
            tests,
            ["lines"],
            log_path,
            use_analysis=False,
        )
        assert mgr.run() == 0
    finally:
        for test in tests:
            test.cleanup()

    expected_run_calls = 3
    expected_results = {"DDBEGIN\nrequired\nDDEND\n"}
    expected_num_reports = 2

    assert replayer.run.call_count == expected_run_calls
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text() for test in log_path.glob("reports/*-*/test.html")}
    assert tests == expected_results
    assert (
        sum(1 for _ in (log_path / "reports").iterdir()) == expected_num_reports
    ), list((log_path / "reports").iterdir())
    others = {test.read_text() for test in log_path.glob("reports/*-*/other.html")}
    assert others == {"blah\n"}
