# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.replay
"""
from itertools import cycle
from pathlib import Path

from pytest import mark, raises

from sapphire import Sapphire, Served

from ..common.reporter import Report
from ..common.storage import TestCase, TestCaseLoadFailure
from ..target import AssetManager, Result, Target
from .replay import ReplayManager, ReplayResult

pytestmark = mark.usefixtures(
    "patch_collector", "tmp_path_grz_tmp", "tmp_path_replay_status_db"
)


def _fake_save_logs(result_logs, _meta=False):
    """write fake log data to disk"""
    log_path = Path(result_logs)
    (log_path / "log_stderr.txt").write_text("STDERR log\n")
    (log_path / "log_stdout.txt").write_text("STDOUT log\n")
    with (log_path / "log_asan_blah.txt").open("w") as log_fp:
        log_fp.write("==1==ERROR: AddressSanitizer: ")
        log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")


def test_replay_01(mocker):
    """test ReplayManager.run() - no repro"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(spec_set=Target, closed=True, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    target.monitor.is_healthy.return_value = False
    iter_cb = mocker.Mock()
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True, relaunch=1) as replay:
            assert not replay.run([testcase], 10, on_iteration_cb=iter_cb)
            assert replay.signature is None
            assert replay.status.ignored == 0
            assert replay.status.iteration == iter_cb.call_count == 1
            assert replay.status.results.total == 0
            assert target.monitor.is_healthy.call_count == 1
            assert target.close.call_count == 2
            assert target.close.mock_calls[0] == mocker.call()
            assert target.close.mock_calls[1] == mocker.call(force_close=True)


def test_replay_02(mocker):
    """test ReplayManager.run() - no repro - with repeats"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(spec_set=Target, closed=False, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    target.monitor.is_healthy.return_value = False
    iter_cb = mocker.Mock()
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager(
            [], server, target, use_harness=True, relaunch=100
        ) as replay:
            assert not replay.run(
                [testcase], 10, repeat=10, min_results=1, on_iteration_cb=iter_cb
            )
            assert replay.signature is None
            assert replay.status.ignored == 0
            assert replay.status.iteration == iter_cb.call_count == 10
            assert replay.status.results.total == 0
            assert target.handle_hang.call_count == 0
            assert target.monitor.is_healthy.call_count == 1
            assert target.close.call_count == 2


def test_replay_03(mocker):
    """test ReplayManager.run() - exit - skip shutdown in runner"""
    # this will make runner appear to have just relaunched the target
    # and skip the expected shutdown
    mocker.patch(
        "grizzly.common.runner.Runner._tests_run",
        new_callable=mocker.PropertyMock,
        return_value=0,
    )
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(spec_set=Target, closed=False, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager(
            [], server, target, use_harness=True, relaunch=100
        ) as replay:
            assert not replay.run([testcase], 10, repeat=10, min_results=1)
            assert replay.status.ignored == 0
            assert replay.status.iteration == 10
            assert replay.status.results.total == 0
            assert target.handle_hang.call_count == 0
            assert target.monitor.is_healthy.call_count == 0
            assert target.close.call_count == 1


@mark.parametrize(
    "good_sig",
    [
        # success - FM parsed signature
        True,
        # signature could not be parsed
        False,
    ],
)
def test_replay_04(mocker, good_sig):
    """test ReplayManager.run() - successful repro"""
    served = ["index.html"]
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (Served.ALL, served)
    target = mocker.Mock(spec_set=Target, binary="C:\\fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    if good_sig:
        target.save_logs = _fake_save_logs
    else:

        def _save_logs(result_logs, _meta=False):
            """create uninteresting logs"""
            log_path = Path(result_logs)
            (log_path / "log_stderr.txt").write_text("STDERR log\n")
            (log_path / "log_stdout.txt").write_text("STDOUT log\n")

        target.save_logs = _save_logs
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, relaunch=10) as replay:
            assert replay.signature is None
            results = replay.run([testcase], 10)
            if good_sig:
                assert replay.signature is not None
            else:
                assert replay.signature is None
            assert replay.status.ignored == 0
            assert replay.status.iteration == 1
            assert replay.status.results.total == 1
            assert target.handle_hang.call_count == 0
            assert target.monitor.is_healthy.call_count == 1
            assert target.close.call_count == 2
        assert len(results) == 1
        assert results[0].count == 1
        assert results[0].expected
        assert results[0].report
        assert len(results[0].served) == 1
        assert results[0].served[0] == served
        assert len(results[0].durations) == 1
        results[0].report.cleanup()


def test_replay_05(mocker):
    """test ReplayManager.run() - error - landing page not requested"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(spec_set=Target, binary="bin", closed=True, launch_timeout=30)
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    # test target unresponsive
    target.check_result.return_value = Result.NONE
    server.serve_path.return_value = (Served.NONE, [])
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases, 10, repeat=1)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
        # target.close() called once in runner and once by ReplayManager.run()
        assert target.close.call_count == 2
    target.reset_mock()
    # test target crashed
    target.check_result.return_value = Result.FOUND
    target.save_logs = _fake_save_logs
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(testcases, 10, repeat=1)
        assert replay.status.ignored == 1
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
        assert replay._signature is None
        # target.close() called once in runner and once by ReplayManager.run()
        assert target.close.call_count == 2
    assert len(results) == 1
    assert results[0].count == 1
    assert not results[0].expected


def test_replay_06(mocker):
    """test ReplayManager.run()
    delayed failure - following test landing page not requested"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    target = mocker.Mock(spec_set=Target, binary="bin", launch_timeout=30)
    type(target).closed = mocker.PropertyMock(side_effect=(True, False, True))
    target.check_result.side_effect = (Result.NONE, Result.FOUND)
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    server.serve_path.side_effect = (
        (Served.ALL, ["a.html"]),
        (Served.REQUEST, ["x"]),
    )
    with ReplayManager([], server, target, use_harness=True, relaunch=10) as replay:
        assert replay.run(testcases, 10, repeat=2)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 2
        assert replay.status.results.total == 1
        # target.close() called once in runner and once by ReplayManager.run()
        assert target.close.call_count == 2


def test_replay_07(mocker):
    """test ReplayManager.run() - ignored"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, closed=True, launch_timeout=30)
    target.check_result.return_value = Result.IGNORED
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases, 10)
        assert target.monitor.is_healthy.call_count == 1
        assert target.close.call_count == 2
        assert replay.status.ignored == 1
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0


def test_replay_08(mocker):
    """test ReplayManager.run() - early exit"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, binary="path/fake_bin", launch_timeout=30)
    target.save_logs = _fake_save_logs
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    # early failure
    target.check_result.side_effect = (
        Result.FOUND,
        Result.IGNORED,
        Result.NONE,
    )
    target.monitor.is_healthy.side_effect = (False, False, True, False)
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases, 10, repeat=4, min_results=3)
        assert target.close.call_count == 4
        assert replay.status.iteration == 3
        assert replay.status.results.total == 1
        assert replay.status.ignored == 1
    # early success
    target.reset_mock()
    target.check_result.side_effect = (
        Result.FOUND,
        Result.IGNORED,
        Result.FOUND,
    )
    target.monitor.is_healthy.side_effect = (False, False, False)
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(testcases, 10, repeat=4, min_results=2)
        assert target.close.call_count == 4
        assert replay.status.iteration == 3
        assert replay.status.results.total == 2
        assert replay.status.ignored == 1
    assert len(results) == 1
    assert sum(x.count for x in results) == 2
    target.reset_mock()
    # ignore early failure (perform all repeats)
    target.check_result.return_value = Result.NONE
    target.check_result.side_effect = None
    target.monitor.is_healthy.side_effect = None
    target.monitor.is_healthy.return_value = True
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases, 10, repeat=4, min_results=4, exit_early=False)
        assert target.close.call_count == 5
        assert replay.status.iteration == 4
        assert replay.status.results.total == 0
        assert replay.status.ignored == 0
    target.reset_mock()
    # ignore early success (perform all repeats)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(testcases, 10, repeat=4, min_results=1, exit_early=False)
        assert target.close.call_count == 5
        assert replay.status.iteration == 4
        assert replay.status.results.total == 4
        assert replay.status.ignored == 0
    assert len(results) == 1
    assert sum(x.count for x in results) == 4


def test_replay_09(mocker):
    """test ReplayManager.run() - test signatures - fail to meet minimum"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    report_1 = mocker.Mock(
        spec_set=Report, crash_hash="hash1", major="0123abcd", minor="01239999"
    )
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(
        spec_set=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876"
    )
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    report_3 = mocker.Mock(
        spec_set=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876"
    )
    report_3.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2, report_3)
    fake_report.calc_hash.return_value = "bucketHASH"
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    signature = mocker.Mock()
    signature.matches.side_effect = (True, False, False)
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager(
        [], server, target, signature=signature, use_harness=False
    ) as replay:
        results = replay.run(testcases, 10, repeat=3, min_results=2)
        assert target.close.call_count == 4
        assert replay.signature == signature
        assert replay.status.iteration == 3
        assert replay.status.results.total == 1
        assert replay.status.ignored == 2
    assert fake_report.call_count == 3
    assert len(results) == 1
    assert not results[0].expected
    assert results[0].count == 2
    assert report_1.cleanup.call_count == 1
    assert report_2.cleanup.call_count == 0
    assert report_3.cleanup.call_count == 1
    assert signature.matches.call_count == 3


def test_replay_10(mocker):
    """test ReplayManager.run() - test signatures - multiple matches"""
    report_0 = mocker.Mock(
        spec_set=Report, crash_hash="hash1", major="0123abcd", minor="01239999"
    )
    report_0.crash_info.createShortSignature.return_value = "[@ test1]"
    report_1 = mocker.Mock(
        spec_set=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876"
    )
    report_1.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0, report_1)
    fake_report.calc_hash.return_value = "bucketHASH"
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    signature = mocker.Mock()
    signature.matches.side_effect = (True, True)
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager(
        [], server, target, signature=signature, use_harness=False
    ) as replay:
        results = replay.run(testcases, 10, repeat=2, min_results=2)
        assert target.close.call_count == 3
        assert replay.signature == signature
        assert replay.status.iteration == 2
        assert replay.status.results.total == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 2
    assert len(results) == 1
    assert results[0].expected
    assert results[0].count == 2
    assert report_0.cleanup.call_count == 0
    assert report_1.cleanup.call_count == 1
    assert signature.matches.call_count == 2


def test_replay_11(mocker):
    """test ReplayManager.run() - any crash - success"""
    report_1 = mocker.Mock(
        spec_set=Report, crash_hash="hash1", major="0123abcd", minor="01239999"
    )
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(
        spec_set=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876"
    )
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager([], server, target, any_crash=True, use_harness=False) as replay:
        results = replay.run(testcases, 10, repeat=2, min_results=2)
        assert target.close.call_count == 3
        assert replay.signature is None
        assert replay.status.iteration == 2
        assert replay.status.results.total == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 2
    assert len(results) == 2
    assert all(x.expected for x in results)
    assert sum(x.count for x in results if x.expected) == 2
    assert report_1.cleanup.call_count == 0
    assert report_2.cleanup.call_count == 0


def test_replay_12(mocker):
    """test ReplayManager.run() - any crash - fail to meet minimum"""
    report_1 = mocker.Mock(
        spec_set=Report, crash_hash="hash1", major="0123abcd", minor="01239999"
    )
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(
        spec_set=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876"
    )
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.side_effect = (
        Result.NONE,
        Result.FOUND,
        Result.FOUND,
        Result.NONE,
    )
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager([], server, target, any_crash=True) as replay:
        assert not replay.run(testcases, 10, repeat=4, min_results=3)
        assert target.close.call_count == 5
        assert replay.signature is None
        assert replay.status.iteration == 4
        assert replay.status.results.total == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 2
    assert report_1.cleanup.call_count == 1
    assert report_2.cleanup.call_count == 1


def test_replay_13(mocker):
    """test ReplayManager.run() - any crash - startup failure"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.NONE, [])
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.save_logs = _fake_save_logs
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager([], server, target, any_crash=True, use_harness=False) as replay:
        results = replay.run(testcases, 10, repeat=1, min_results=1)
        assert results
        assert not any(x.expected for x in results)
        assert target.close.call_count == 2
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
        assert replay.status.ignored == 1


def test_replay_14(mocker):
    """test ReplayManager.run() - no signature - use first crash"""
    report_1 = mocker.Mock(
        spec_set=Report, crash_hash="hash1", major="0123", minor="9999"
    )
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    auto_sig = mocker.Mock()
    auto_sig.matches.side_effect = (True, False, True)
    report_1.crash_signature = auto_sig
    report_2 = mocker.Mock(
        spec_set=Report, crash_hash="hash2", major="abcd", minor="9876"
    )
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    report_3 = mocker.Mock(
        spec_set=Report, crash_hash="hash1", major="0123", minor="9999"
    )
    report_3.crash_info.createShortSignature.return_value = "[@ test1]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2, report_3)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(testcases, 10, repeat=3, min_results=2)
        assert target.close.call_count == 4
        assert replay.signature == auto_sig
        assert replay.status.iteration == 3
        assert replay.status.results.total == 2
        assert replay.status.ignored == 1
    assert fake_report.call_count == 3
    assert len(results) == 2
    assert sum(x.expected for x in results) == 1
    assert sum(x.count for x in results if x.expected) == 2
    assert report_1.cleanup.call_count == 0
    assert report_2.cleanup.call_count == 0
    assert report_3.cleanup.call_count == 1


def test_replay_15(mocker):
    """test ReplayManager.run() - unexpected exception"""
    report_0 = mocker.Mock(
        spec_set=Report, crash_hash="hash1", major="0123abcd", minor="01239999"
    )
    report_0.crash_info.createShortSignature.return_value = "[@ test1]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0,)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.side_effect = ((Served.ALL, ["a.html"]), KeyboardInterrupt)
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
    ]
    with ReplayManager(
        [], server, target, any_crash=True, use_harness=True, relaunch=2
    ) as replay:
        with raises(KeyboardInterrupt):
            replay.run(testcases, 10, repeat=3, min_results=2)
        assert replay.signature is None
        assert replay.status.iteration == 2
        assert replay.status.results.total == 1
        assert replay.status.ignored == 0
    assert target.close.call_count == 1
    assert target.monitor.is_healthy.call_count == 0
    assert fake_report.call_count == 1
    assert report_0.cleanup.call_count == 1


def test_replay_16(mocker):
    """test ReplayManager.run() - multiple TestCases - no repro"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, closed=True, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
        for _ in range(3)
    ]
    with ReplayManager([], server, target, use_harness=True) as replay:
        assert not replay.run(testcases, 10)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
    assert target.close.call_count == 2


def test_replay_17(mocker):
    """test ReplayManager.run() - multiple TestCases - no repro - with repeats"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    # test relaunch < repeat
    type(target).closed = mocker.PropertyMock(side_effect=cycle([True, False]))
    target.check_result.return_value = Result.NONE
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[])
        for _ in range(3)
    ]
    with ReplayManager([], server, target, use_harness=True, relaunch=2) as replay:
        assert not replay.run(testcases, 10, repeat=10)
        assert server.serve_path.call_count == 30
        assert target.close.call_count == 6
        assert target.launch.call_count == 5
        assert replay.status.ignored == 0
        assert replay.status.iteration == 10
        assert replay.status.results.total == 0
    assert target.monitor.is_healthy.call_count == 5


def test_replay_18(mocker):
    """test ReplayManager.run() - multiple TestCases - successful repro"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.side_effect = (
        (Served.ALL, ["a.html"]),
        (Served.ALL, ["b.html"]),
        (Served.ALL, ["c.html"]),
    )
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.side_effect = (
        Result.NONE,
        Result.NONE,
        Result.FOUND,
    )
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    testcases = [
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="a.html", optional=[]),
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="b.html", optional=[]),
        mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="c.html", optional=[]),
    ]
    with ReplayManager([], server, target, use_harness=True) as replay:
        results = replay.run(testcases, 30)
        assert target.close.call_count == 2
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results.total == 1
    assert len(results) == 1
    assert len(results[0].served) == len(testcases)
    assert results[0].served[0][0] == "a.html"
    assert results[0].served[1][0] == "b.html"
    assert results[0].served[2][0] == "c.html"
    assert len(results[0].durations) == len(testcases)


def test_replay_19(mocker):
    """test ReplayManager.run() - multiple calls"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(spec_set=Target, closed=True, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True) as replay:
            assert not replay.run([testcase], 30)
            assert replay.status.iteration == 1
            assert not replay.run([testcase], 30)
            assert replay.status.iteration == 1
            assert not replay.run([testcase], 30)
            assert replay.status.iteration == 1
    assert server.serve_path.call_count == 3


def test_replay_20(mocker, tmp_path):
    """test ReplayManager.report_to_filesystem()"""
    # no reports
    ReplayManager.report_to_filesystem(tmp_path, [])
    assert not any(tmp_path.iterdir())
    # with reports and tests
    (tmp_path / "report_expected").mkdir()
    result0 = mocker.Mock(
        spec_set=ReplayResult, count=1, durations=[1], expected=True, served=[]
    )
    result0.report = mocker.Mock(
        spec_set=Report, path=tmp_path / "report_expected", prefix="expected"
    )
    (tmp_path / "report_other1").mkdir()
    result1 = mocker.Mock(
        spec_set=ReplayResult, count=1, durations=[1], expected=False, served=None
    )
    result1.report = mocker.Mock(
        spec_set=Report, path=tmp_path / "report_other1", prefix="other1"
    )
    (tmp_path / "report_other2").mkdir()
    result2 = mocker.Mock(
        spec_set=ReplayResult, count=1, durations=[1], expected=False, served=None
    )
    result2.report = mocker.Mock(
        spec_set=Report, path=tmp_path / "report_other2", prefix="other2"
    )
    test = mocker.Mock(spec_set=TestCase)
    path = tmp_path / "dest"
    ReplayManager.report_to_filesystem(path, [result0, result1, result2], tests=[test])
    assert test.dump.call_count == 3  # called once per report
    assert not (tmp_path / "report_expected").is_dir()
    assert not (tmp_path / "report_other1").is_dir()
    assert not (tmp_path / "report_other2").is_dir()
    assert path.is_dir()
    assert (path / "reports").is_dir()
    assert (path / "reports" / "expected_logs").is_dir()
    assert (path / "other_reports").is_dir()
    assert (path / "other_reports" / "other1_logs").is_dir()
    assert (path / "other_reports" / "other2_logs").is_dir()
    # with reports and no tests
    (tmp_path / "report_expected").mkdir()
    result0.reset_mock()
    path = tmp_path / "dest2"
    ReplayManager.report_to_filesystem(path, [result0])
    assert not (tmp_path / "report_expected").is_dir()
    assert path.is_dir()
    assert (path / "reports" / "expected_logs").is_dir()


def test_replay_21(mocker, tmp_path):
    """test ReplayManager.load_testcases()"""
    fake_load = mocker.patch("grizzly.replay.replay.TestCase.load")
    test0 = mocker.Mock(spec_set=TestCase, env_vars={"env": "var"})
    test0.pop_assets.return_value = None
    test1 = mocker.Mock(spec_set=TestCase, env_vars={}, landing_page="x.html")
    test1.pop_assets.return_value = None
    test2 = mocker.Mock(spec_set=TestCase, env_vars={})
    test2.pop_assets.return_value = None
    # failure
    fake_load.return_value = ()
    with raises(TestCaseLoadFailure, match="Failed to load TestCases"):
        ReplayManager.load_testcases(str(tmp_path))
    # success
    fake_load.return_value = [test0, test1]
    tests, assets, env_vars = ReplayManager.load_testcases(str(tmp_path))
    assert env_vars["env"] == "var"
    assert not any(x.env_vars for x in tests)
    assert len(tests) == 2
    assert tests[0].cleanup.call_count == 0
    assert tests[1].cleanup.call_count == 0
    assert assets is None
    # success select
    test0.pop_assets.return_value = mocker.Mock(spec_set=AssetManager)
    fake_load.return_value = [
        test0,
        test1,
        test2,
        mocker.Mock(spec_set=TestCase, env_vars={}),
    ]
    tests, assets, _ = ReplayManager.load_testcases(str(tmp_path), subset=[1, 3])
    assert len(tests) == 2
    assert tests[0].landing_page == "x.html"
    assert test0.cleanup.call_count == 1
    assert test1.cleanup.call_count == 0
    assert test2.cleanup.call_count == 1
    assert assets is not None
    test0.reset_mock()
    test2.reset_mock()
    # select (first and last) with invalid input
    test0.pop_assets.return_value = None
    fake_load.return_value = [test0, test1, test2]
    tests, _a, _e = ReplayManager.load_testcases(str(tmp_path), subset=[0, 10, -10, -1])
    assert len(tests) == 2
    assert test0.cleanup.call_count == 0
    assert test1.cleanup.call_count == 1
    assert test2.cleanup.call_count == 0


@mark.parametrize(
    "expect_hang, is_hang, use_sig, match_sig, ignored, results",
    [
        # reproduce expected hang
        (True, True, True, True, 0, 1),
        # expected hang (signature, hang - no match)
        (True, True, True, False, 1, 0),
        # expected hang got crash (signature)
        (True, False, True, False, 1, 0),
        # unexpected hang (signature, no match)
        (False, True, True, False, 1, 0),
        # unexpected hang (no signature)
        (False, True, False, False, 1, 0),
        # unexpected crash (signature)
        (False, False, True, False, 1, 0),
    ],
)
def test_replay_22(mocker, expect_hang, is_hang, use_sig, match_sig, ignored, results):
    """test ReplayManager.run() - detect hangs"""
    served = ["index.html"]
    server = mocker.Mock(spec_set=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (
        Served.TIMEOUT if is_hang else Served.ALL,
        served,
    )
    if use_sig:
        signature = mocker.Mock()
        signature.matches.return_value = match_sig
        signature.rawSignature = "fakesig"
    else:
        signature = None
    target = mocker.Mock(spec_set=Target, binary="fake_bin", launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.handle_hang.return_value = False
    target.save_logs = _fake_save_logs
    target.monitor.is_healthy.return_value = False
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        testcase.hang = is_hang
        with ReplayManager(
            [], server, target, signature=signature, relaunch=10
        ) as replay:
            found = replay.run([testcase], 10, expect_hang=expect_hang)
            assert replay.status.iteration == 1
            assert replay.status.ignored == ignored
            assert replay.status.results.total == results
            assert target.handle_hang.call_count == (1 if is_hang else 0)
            assert target.monitor.is_healthy.call_count == (0 if is_hang else 1)
            assert target.close.call_count == (1 if is_hang else 2)
        assert len(found) == 1
        assert found[0].count == 1
        assert found[0].expected == results
        assert found[0].report
        assert found[0].report.is_hang == is_hang
        assert len(found[0].served) == 1
        assert found[0].served[0] == served
        assert len(found[0].durations) == 1
        assert testcase.hang == is_hang
        found[0].report.cleanup()
