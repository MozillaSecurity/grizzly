# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.strategies`.
"""
from collections import namedtuple
from logging import getLogger

import pytest
from pytest import raises

from sapphire import Sapphire
from ..common import TestCase, Report
from ..replay import ReplayResult
from ..target import Target
from .strategies import _load_strategies, HAVE_CSSBEAUTIFIER, HAVE_JSBEAUTIFIER
from . import ReduceManager


LOG = getLogger(__name__)
pytestmark = pytest.mark.usefixtures("tmp_path_fm_config",
                                     "reporter_sequential_strftime")


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
    class _GoodStrategy(object):
        name = "good"
        @classmethod
        def sanity_check_cls_attrs(cls):
            pass

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
    "test_data, strategies, required_first, expected_run_calls, expected_results,"
    "expected_num_reports"
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
def test_list(mocker, tmp_path, test_data, strategies, required_first,
              expected_run_calls, expected_results, expected_num_reports):
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
                log_path = tmp_path / (
                    "crash%d_logs" % (replayer.return_value.run.call_count,)
                )
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(str(log_path), "bin")
                return [ReplayResult(report, [["test.html"]] * len(testcases), [],
                                     True)]
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
        mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target, tests, strategies,
                            log_path, use_analysis=False)
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
    "test_data, test_name, expected_run_calls, expected_results, expected_num_reports,"
    "strategies"
)


@pytest.mark.parametrize(
    BeautifyStrategyParams._fields,
    [
        # test beautify a .js file
        pytest.param(
            *BeautifyStrategyParams(
                test_data="try{'fluff';'required'}catch(e){}\n",
                test_name="test.js",
                expected_run_calls=1,
                expected_results={
                    "try {\n    'fluff';\n    'required'\n} catch (e) {}\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test beautify js embedded in html
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<script>try{'fluff';'required'}catch(e){}</script>\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={"<script>\ntry {\n    'fluff';\n    'required'\n} "
                                  "catch (e) {}\n</script>\n"},
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test beautify multiple js embedded in html
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<script>try{'fluff';'required'}catch(e){}</script>"
                "<script>'fluff';'requisite'</script>\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={"<script>\ntry {\n    'fluff';\n    'required'\n} "
                                  "catch (e) {}\n</script><script>\n'fluff';\n'"
                                  "requisite'\n</script>\n"},
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test beautify js embedded in html with no end
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<script>try{'fluff';'required'}catch(e){}\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<script>\ntry {\n    'fluff';\n    'required'\n} catch (e) {}\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test DDBEGIN/END respected in .js file
        pytest.param(
            *BeautifyStrategyParams(
                test_data="try{\n//DDBEGIN\n'fluff';'required'\n//DDEND\n}catch(e){}\n",
                test_name="test.js",
                expected_run_calls=1,
                expected_results={
                    "try{\n//DDBEGIN\n'fluff';\n'required'\n//DDEND\n}catch(e){}\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test DDBEGIN/END respected for js embedded in html, DD outside <script>
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<!--DDBEGIN-->\n<script>\ntry{'fluff';'required'}"
                          "catch(e){}\n</script><!--DDEND-->\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<!--DDBEGIN-->\n<script>\ntry {\n    'fluff';\n    'required'\n} "
                    "catch (e) {}\n</script><!--DDEND-->\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test DDBEGIN/END respected for js embedded in html, DD inside <script>
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<script>try{\n//DDBEGIN\n'fluff';'required'\n//DDEND\n}"
                          "catch(e){}</script>\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<script>try{\n//DDBEGIN\n'fluff';\n'required'\n//DDEND\n}"
                    "catch(e){}</script>\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test DDBEGIN/END respected for js embedded in html, DD straddle before
        # <script>
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<!--DDBEGIN-->\n<script>\ntry{'fluff';'required'}catch(e){}"
                          "\n//DDEND\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<!--DDBEGIN-->\n<script>\ntry {\n    'fluff';\n    'required'\n} "
                    "catch (e) {}\n//DDEND\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test DDBEGIN/END respected for js embedded in html, DD straddle after <script>
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<script>\n//DDBEGIN\ntry{'fluff';'required'}catch(e){}\n"
                          "//DDEND\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<script>\n//DDBEGIN\ntry {\n    'fluff';\n    'required'\n} "
                    "catch (e) {}\n//DDEND\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test DDBEGIN/END respected for js embedded in html, DD straddle after
        # </script>
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<script>\n//DDBEGIN\ntry{'fluff';'required'}catch(e){}\n"
                          "</script>\n<!--DDEND-->\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<script>\n//DDBEGIN\ntry {\n    'fluff';\n    'required'\n} "
                    "catch (e) {}\n</script>\n<!--DDEND-->\n"
                },
                expected_num_reports=2,
                strategies=["jsbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test beautify js embedded in html (no <script>)
        pytest.param(
            *BeautifyStrategyParams(
                test_data="try{'fluff';'required'}catch(e){}\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={"try{'fluff';'required'}catch(e){}\n"},
                expected_num_reports=2,
                # no beautify performed, add check so the run succeeds
                strategies=["jsbeautify", "check"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test beautify js where beautification breaks
        pytest.param(
            *BeautifyStrategyParams(
                test_data="try{'fluff';'requi'+'red'}catch(e){}\n",
                test_name="test.js",
                expected_run_calls=2,
                expected_results={"try{'fluff';'requi'+'red'}catch(e){}\n"},
                expected_num_reports=2,
                # no beautify performed, add check so the run succeeds
                strategies=["jsbeautify", "check"],
            ),
            marks=pytest.mark.skipif(not HAVE_JSBEAUTIFIER,
                                     reason="jsbeautifier required"),
        ),
        # test beautify a .css file
        pytest.param(
            *BeautifyStrategyParams(
                test_data="*,#a{fluff:0;required:1}\n",
                test_name="test.css",
                expected_run_calls=1,
                expected_results={"*,\n#a {\n  fluff: 0;\n  required: 1\n}\n"},
                expected_num_reports=2,
                strategies=["cssbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_CSSBEAUTIFIER,
                                     reason="cssbeautifier required"),
        ),
        # test beautify css embedded in html
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<style>*,#a{fluff:0;required:1}</style>\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<style>\n*,\n#a {\n  fluff: 0;\n  required: 1\n}\n</style>\n"
                },
                expected_num_reports=2,
                strategies=["cssbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_CSSBEAUTIFIER,
                                     reason="cssbeautifier required"),
        ),
        # test beautify css embedded in html with no end
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<style>*,#a{fluff:0;required:1}\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={"<style>\n*,\n#a {\n  fluff: 0;\n  required: 1\n}\n"},
                expected_num_reports=2,
                strategies=["cssbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_CSSBEAUTIFIER,
                                     reason="cssbeautifier required"),
        ),
        # test already beautified css (beautify does nothing)
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<style>\n*,\n#a {\n  fluff: 0;\n  required: 1\n}\n</style>\n",
                test_name="test.html",
                expected_run_calls=1,
                expected_results={
                    "<style>\n*,\n#a {\n  fluff: 0;\n  required: 1\n}\n</style>\n"
                },
                expected_num_reports=2,
                strategies=["check", "cssbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_CSSBEAUTIFIER,
                                     reason="cssbeautifier required"),
        ),
        # test almost beautified css (any change breaks test, beautify only removes an extra blank line,
        # so `lines` will have already tried it, and this will hit the cache)
        pytest.param(
            *BeautifyStrategyParams(
                test_data="<style nochange=true>\n/*DDBEGIN*/\n\nrequisite {\n  required: 1\n}\n/*DDEND*/\n</style>\n",
                test_name="test.html",
                expected_run_calls=8,
                expected_results={
                    "<style nochange=true>\n/*DDBEGIN*/\n\nrequisite {\n  required: 1\n}\n/*DDEND*/\n</style>\n"
                },
                expected_num_reports=2,
                strategies=["check", "lines", "cssbeautify"],
            ),
            marks=pytest.mark.skipif(not HAVE_CSSBEAUTIFIER,
                                     reason="cssbeautifier required"),
        ),
    ]
)
def test_beautifier(mocker, tmp_path, test_data, test_name, expected_run_calls,
                    expected_results, expected_num_reports, strategies):
    """test for the "beautify" strategies"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)

    def replay_run(testcases, **_):
        for test in testcases:
            contents = test.get_file(test_name).data.decode("ascii")
            if "nochange" in test_data:
                LOG.debug("interesting if test unchanged")
                interesting = test_data == contents
            elif "requisite" in test_data:
                LOG.debug("interesting if ('requisite' and 'required') or 'requi'+'red' in %r", contents)
                interesting = ("required" in contents and "requisite" in contents) or "'requi'+'red'" in contents
            else:
                LOG.debug("interesting if 'required' or 'requi'+'red' in %r", contents)
                interesting = "required" in contents or "'requi'+'red'" in contents
            if interesting:
                log_path = tmp_path / (
                    "crash%d_logs" % (replayer.return_value.run.call_count,)
                )
                log_path.mkdir()
                _fake_save_logs_foo(log_path)
                report = Report(str(log_path), "bin")
                return [ReplayResult(report, [[test_name]], [], True)]
        return []
    replayer.return_value.run.side_effect = replay_run

    test = TestCase(test_name, None, "test-adapter")
    test.add_from_data(test_data, test_name)
    tests = [test]
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec=Target)
    target.relaunch = 1
    try:
        mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target, tests, strategies,
                            log_path, use_analysis=False)
        assert mgr.run()
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.return_value.run.call_count == expected_run_calls
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text() for test in log_path.glob("reports/*-*/" + test_name)}
    assert tests == expected_results
    assert len(list((log_path / "reports").iterdir())) == expected_num_reports, \
        list((log_path / "reports").iterdir())


PurgeUnservedTestParams = namedtuple(
    "PurgeUnservedTestParams",
    "strategies, test_data, served, expected_results, expected_run_calls,"
    "expected_num_reports, purging_breaks"
)


@pytest.mark.parametrize(
    PurgeUnservedTestParams._fields,
    [
        # single test, first reduction uses 2 files, second uses only target file.
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[{"test.html": "123", "opt.html": "456"}],
            served=[[["test.html", "opt.html"]], [["test.html"]], [["test.html"]]],
            expected_results={"1"},
            expected_run_calls=5,
            expected_num_reports=2,
            purging_breaks=False,
        ),
        # single test, first reduction uses target only
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[{"test.html": "123", "opt.html": "456"}],
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
            test_data=[{"test.html": "123", "opt.html": "456"}],
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
            test_data=[{"test.html": "123", "opt.html": "456"},
                       {"test.html": "789", "opt.html": "abc"}],
            served=[[["test.html", "opt.html"], ["test.html", "opt.html"]],
                    [["test.html", "opt.html"], ["test.html"]],
                    [["test.html", "opt.html"], ["test.html"]]],
            expected_results={"1", "4", "7"},
            expected_run_calls=6,
            expected_num_reports=3,
            purging_breaks=False,
        ),
        # double test, first reduction uses all files, second uses only optional file
        # (first test remains)
        PurgeUnservedTestParams(
            strategies=["chars"],
            test_data=[{"test.html": "123", "opt.html": "456"},
                       {"test.html": "789", "opt.html": "abc"}],
            served=[[["test.html", "opt.html"], ["test.html", "opt.html"]],
                    [["test.html", "opt.html"], ["opt.html"]],
                    [["test.html", "opt.html"]]],
            expected_results={"1", "4"},
            expected_run_calls=5,
            expected_num_reports=2,
            purging_breaks=False,
        ),
        # triple test, list strategy. first test gets reduced, third gets eliminated
        PurgeUnservedTestParams(
            strategies=["list"],
            test_data=[{"test.html": "123"}, {"test.html": "456"},
                       {"test.html": "789"}],
            served=[[["test.html"]],
                    [["test.html"]],
                    [["test.html"]]],
            expected_results={"456"},
            expected_run_calls=2,
            expected_num_reports=2,
            purging_breaks=False,
        ),
        # triple test, list strategy. None for served still eliminates first two tests
        PurgeUnservedTestParams(
            strategies=["list"],
            test_data=[{"test.html": "123"}, {"test.html": "456"},
                       {"test.html": "789"}],
            served=[None, None, None],
            expected_results={"789"},
            expected_run_calls=2,
            expected_num_reports=2,
            purging_breaks=False,
        ),
    ]
)
def test_purge_unserved(mocker, tmp_path, strategies, test_data, served,
                        expected_results, expected_run_calls, expected_num_reports,
                        purging_breaks):
    """test purging unserved files"""
    replayer = mocker.patch("grizzly.reduce.core.ReplayManager", autospec=True)

    def replay_run(testcases, **_):
        # test.html and opt.html should always contain one line.
        # return [] (no result) if either of them exist and are empty
        has_any = False
        for test in testcases:
            for file in ("test.html", "opt.html"):
                if test.contains(file):
                    LOG.debug("testcase contains %s", file)
                    has_any = True
                    contents = test.get_file(file).data.decode("ascii")
                    if not contents.strip():
                        return []
        if not has_any:
            return []
        log_path = tmp_path / ("crash%d_logs" % (replayer.return_value.run.call_count,))
        log_path.mkdir()
        _fake_save_logs_foo(log_path)
        report = Report(str(log_path), "bin")
        return [ReplayResult(report, served.pop(0), [], True)]
    replayer.return_value.run.side_effect = replay_run

    tests = []
    for testcase in test_data:
        test = TestCase("test.html", None, "test-adapter")
        for filename, data in testcase.items():
            test.add_from_data(data, filename)
        tests.append(test)
    log_path = tmp_path / "logs"

    target = mocker.Mock(spec=Target)
    target.relaunch = 1
    try:
        mgr = ReduceManager([], mocker.Mock(spec=Sapphire), target, tests, strategies,
                            log_path, use_analysis=False)
        if purging_breaks:
            with raises(AssertionError):
                mgr.run()
        else:
            assert mgr.run()
    finally:
        for test in tests:
            test.cleanup()

    assert replayer.return_value.run.call_count == expected_run_calls
    if purging_breaks:
        return
    assert set(log_path.iterdir()) == {log_path / "reports"}
    tests = {test.read_text() for test in log_path.glob("reports/*-*/*.html")}
    assert tests == expected_results
    assert len(list((log_path / "reports").iterdir())) == expected_num_reports, \
        list((log_path / "reports").iterdir())
