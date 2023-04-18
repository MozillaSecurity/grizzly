# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.replay
"""
from itertools import cycle
from pathlib import Path

from FTB.Signatures.CrashInfo import CrashSignature
from pytest import mark, raises

from sapphire import Served

from ..common.reporter import Report
from ..common.storage import TestCase, TestCaseLoadFailure
from ..target import AssetManager, Result, Target
from .replay import ReplayManager, ReplayResult

pytestmark = mark.usefixtures("patch_collector", "tmp_path_grz_tmp")


def _fake_save_logs(result_logs):
    """write fake log data to disk"""
    log_path = Path(result_logs)
    (log_path / "log_stderr.txt").write_text("STDERR log\n")
    (log_path / "log_stdout.txt").write_text("STDOUT log\n")
    with (log_path / "log_asan_blah.txt").open("w") as log_fp:
        log_fp.write("==1==ERROR: AddressSanitizer: ")
        log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")


def test_replay_01(mocker, server):
    """test ReplayManager.run() - no repro"""
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


def test_replay_02(mocker, server):
    """test ReplayManager.run() - no repro - with repeats"""
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(
        spec_set=Target, binary=Path("bin"), closed=False, launch_timeout=30
    )
    target.check_result.return_value = Result.NONE
    target.monitor.is_healthy.return_value = False
    iter_cb = mocker.Mock()
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True, relaunch=20) as replay:
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


def test_replay_03(mocker, server):
    """test ReplayManager.run() - exit - skip shutdown in runner"""
    # this will make runner appear to have just relaunched the target
    # and skip the expected shutdown
    mocker.patch(
        "grizzly.common.runner.Runner._tests_run",
        new_callable=mocker.PropertyMock,
        return_value=0,
    )
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(spec_set=Target, closed=False, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True, relaunch=20) as replay:
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
def test_replay_04(mocker, server, good_sig):
    """test ReplayManager.run() - successful repro"""
    served = ["index.html"]
    server.serve_path.return_value = (Served.ALL, served)
    target = mocker.Mock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    if good_sig:
        target.save_logs = _fake_save_logs
    else:

        def _save_logs(result_logs):
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


def test_replay_05(mocker, server):
    """test ReplayManager.run() - error - landing page not requested"""
    target = mocker.Mock(
        spec_set=Target, binary=Path("bin"), closed=True, launch_timeout=30
    )
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    # test target unresponsive
    target.check_result.return_value = Result.NONE
    server.serve_path.return_value = (Served.NONE, [])
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(tests, 10, repeat=1)
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
        results = replay.run(tests, 10, repeat=1)
        assert replay.status.ignored == 1
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
        assert replay._signature is None
        # target.close() called once in runner and once by ReplayManager.run()
        assert target.close.call_count == 2
    assert len(results) == 1
    assert results[0].count == 1
    assert not results[0].expected


def test_replay_06(mocker, server):
    """test ReplayManager.run()
    delayed failure - following test landing page not requested"""
    target = mocker.Mock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    type(target).closed = mocker.PropertyMock(side_effect=(True, False, True))
    target.check_result.side_effect = (Result.NONE, Result.FOUND)
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    server.serve_path.side_effect = (
        (Served.ALL, ["a.html"]),
        (Served.REQUEST, ["x"]),
    )
    with ReplayManager([], server, target, use_harness=True, relaunch=10) as replay:
        assert replay.run(tests, 10, repeat=2, post_launch_delay=-1)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 2
        assert replay.status.results.total == 1
        # target.close() called once in runner and once by ReplayManager.run()
        assert target.close.call_count == 2


def test_replay_07(mocker, server):
    """test ReplayManager.run() - ignored (timeout)"""
    server.serve_path.return_value = (Served.TIMEOUT, ["a.html"])
    target = mocker.Mock(spec_set=Target, closed=True, launch_timeout=30)
    target.check_result.return_value = Result.IGNORED
    target.handle_hang.return_value = True
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(tests, 10)
        assert replay.status.ignored == 1
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
    assert target.handle_hang.call_count == 1


def test_replay_08(mocker, server):
    """test ReplayManager.run() - early exit"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    target.save_logs = _fake_save_logs
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    # early failure
    target.check_result.side_effect = (
        Result.FOUND,
        Result.IGNORED,
        Result.NONE,
    )
    target.monitor.is_healthy.side_effect = (False, False, True, False)
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(tests, 10, repeat=4, min_results=3)
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
        results = replay.run(tests, 10, repeat=4, min_results=2)
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
        assert not replay.run(tests, 10, repeat=4, min_results=4, exit_early=False)
        assert target.close.call_count == 5
        assert replay.status.iteration == 4
        assert replay.status.results.total == 0
        assert replay.status.ignored == 0
    target.reset_mock()
    # ignore early success (perform all repeats)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(tests, 10, repeat=4, min_results=1, exit_early=False)
        assert target.close.call_count == 5
        assert replay.status.iteration == 4
        assert replay.status.results.total == 4
        assert replay.status.ignored == 0
    assert len(results) == 1
    assert sum(x.count for x in results) == 4


def test_replay_09(mocker, server):
    """test ReplayManager.run() - test signatures - fail to meet minimum"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    report_1 = mocker.Mock(spec_set=Report, crash_hash="h1", major="0123", minor="0123")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(spec_set=Report, crash_hash="h2", major="0123", minor="abcd")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    report_3 = mocker.Mock(spec_set=Report, crash_hash="h2", major="0123", minor="abcd")
    report_3.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2, report_3)
    fake_report.calc_hash.return_value = "bucketHASH"
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    signature = mocker.Mock()
    signature.matches.side_effect = (True, False, False)
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager(
        [], server, target, signature=signature, use_harness=False
    ) as replay:
        results = replay.run(tests, 10, repeat=3, min_results=2)
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


def test_replay_10(mocker, server):
    """test ReplayManager.run() - test signatures - multiple matches"""
    report_0 = mocker.Mock(spec_set=Report, crash_hash="h1", major="0123", minor="0123")
    report_0.crash_info.createShortSignature.return_value = "[@ test1]"
    report_1 = mocker.Mock(spec_set=Report, crash_hash="h2", major="0123", minor="abcd")
    report_1.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0, report_1)
    fake_report.calc_hash.return_value = "bucketHASH"
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    sig = mocker.Mock(spec_set=CrashSignature)
    sig.matches.side_effect = (True, True)
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager([], server, target, signature=sig, use_harness=False) as replay:
        results = replay.run(tests, 10, repeat=2, min_results=2)
        assert target.close.call_count == 3
        assert replay.signature == sig
        assert replay.status.iteration == 2
        assert replay.status.results.total == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 2
    assert len(results) == 1
    assert results[0].expected
    assert results[0].count == 2
    assert report_0.cleanup.call_count == 0
    assert report_1.cleanup.call_count == 1
    assert sig.matches.call_count == 2


def test_replay_11(mocker, server):
    """test ReplayManager.run() - any crash - success"""
    report_1 = mocker.Mock(spec_set=Report, crash_hash="h1", major="0123", minor="0123")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(spec_set=Report, crash_hash="h2", major="0123", minor="abcd")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager([], server, target, any_crash=True, use_harness=False) as replay:
        results = replay.run(tests, 10, repeat=2, min_results=2)
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


def test_replay_12(mocker, server):
    """test ReplayManager.run() - any crash - fail to meet minimum"""
    report_1 = mocker.Mock(spec_set=Report, crash_hash="h1", major="0123", minor="0123")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(spec_set=Report, crash_hash="h2", major="0123", minor="abcd")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    target.check_result.side_effect = (
        Result.NONE,
        Result.FOUND,
        Result.FOUND,
        Result.NONE,
    )
    target.monitor.is_healthy.return_value = False
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager([], server, target, any_crash=True) as replay:
        assert not replay.run(tests, 10, repeat=4, min_results=3)
        assert target.close.call_count == 5
        assert replay.signature is None
        assert replay.status.iteration == 4
        assert replay.status.results.total == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 2
    assert report_1.cleanup.call_count == 1
    assert report_2.cleanup.call_count == 1


def test_replay_13(mocker, server):
    """test ReplayManager.run() - any crash - startup failure"""
    server.serve_path.return_value = (Served.NONE, [])
    target = mocker.Mock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.save_logs = _fake_save_logs
    target.monitor.is_healthy.return_value = False
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager([], server, target, any_crash=True, use_harness=False) as replay:
        results = replay.run(tests, 10, repeat=1, min_results=1)
        assert results
        assert not any(x.expected for x in results)
        assert target.close.call_count == 2
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
        assert replay.status.ignored == 1


def test_replay_14(mocker, server):
    """test ReplayManager.run() - no signature - use first crash"""
    auto_sig = mocker.Mock(spec_set=CrashSignature)
    auto_sig.matches.side_effect = (True, False, True)
    # original
    report_1 = mocker.Mock(spec_set=Report, crash_hash="h1", major="012", minor="999")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_1.crash_signature = auto_sig
    # non matching report
    report_2 = mocker.Mock(spec_set=Report, crash_hash="h2", major="abc", minor="987")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    # matching report
    report_3 = mocker.Mock(spec_set=Report, crash_hash="h1", major="012", minor="999")
    report_3.crash_info.createShortSignature.return_value = "[@ test1]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2, report_3)
    fake_report.calc_hash.return_value = "bucket_hash"
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(tests, 10, repeat=3, min_results=2)
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


def test_replay_15(mocker, server):
    """test ReplayManager.run() - unexpected exception"""
    report_0 = mocker.Mock(spec_set=Report, crash_hash="h1", major="0123", minor="0123")
    report_0.crash_info.createShortSignature.return_value = "[@ test1]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0,)
    server.serve_path.side_effect = ((Served.ALL, ["a.html"]), KeyboardInterrupt)
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    tests = [mocker.MagicMock(spec_set=TestCase, landing_page="a.html")]
    with ReplayManager(
        [], server, target, any_crash=True, use_harness=True, relaunch=2
    ) as replay:
        with raises(KeyboardInterrupt):
            replay.run(tests, 10, repeat=3, min_results=2, post_launch_delay=-1)
        assert replay.signature is None
        assert replay.status.iteration == 2
        assert replay.status.results.total == 1
        assert replay.status.ignored == 0
    assert target.close.call_count == 1
    assert target.monitor.is_healthy.call_count == 0
    assert fake_report.call_count == 1
    assert report_0.cleanup.call_count == 1


def test_replay_16(mocker, server):
    """test ReplayManager.run() - multiple TestCases - no repro"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, closed=True, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    tests = [
        mocker.MagicMock(spec_set=TestCase, landing_page="a.html") for _ in range(3)
    ]
    with ReplayManager([], server, target, use_harness=True) as replay:
        assert not replay.run(tests, 10)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results.total == 0
    assert target.close.call_count == 2


def test_replay_17(mocker, server):
    """test ReplayManager.run() - multiple TestCases - no repro - with repeats"""
    server.serve_path.return_value = (Served.ALL, ["a.html"])
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    # test relaunch < repeat
    type(target).closed = mocker.PropertyMock(side_effect=cycle([True, False]))
    target.check_result.return_value = Result.NONE
    target.monitor.is_healthy.return_value = False
    tests = [
        mocker.MagicMock(spec_set=TestCase, landing_page="a.html") for _ in range(3)
    ]
    with ReplayManager([], server, target, use_harness=True, relaunch=2) as replay:
        assert not replay.run(tests, 10, repeat=10, post_launch_delay=-1)
        assert server.serve_path.call_count == 30
        assert target.close.call_count == 6
        assert target.launch.call_count == 5
        assert replay.status.ignored == 0
        assert replay.status.iteration == 10
        assert replay.status.results.total == 0
    assert target.monitor.is_healthy.call_count == 5


def test_replay_18(mocker, server):
    """test ReplayManager.run() - multiple TestCases - successful repro"""
    server.serve_path.side_effect = (
        (Served.ALL, ["0.html"]),
        (Served.ALL, ["1.html"]),
        (Served.ALL, ["2.html"]),
    )
    target = mocker.Mock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    target.check_result.side_effect = (
        Result.NONE,
        Result.NONE,
        Result.FOUND,
    )
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    tests = [
        mocker.MagicMock(spec_set=TestCase, landing_page=f"{i}.html") for i in range(3)
    ]
    with ReplayManager([], server, target, use_harness=True) as replay:
        results = replay.run(tests, 30, post_launch_delay=-1)
        assert target.close.call_count == 2
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results.total == 1
    assert len(results) == 1
    assert len(results[0].served) == len(tests)
    assert results[0].served[0][0] == "0.html"
    assert results[0].served[1][0] == "1.html"
    assert results[0].served[2][0] == "2.html"
    assert len(results[0].durations) == len(tests)


def test_replay_19(mocker, server):
    """test ReplayManager.run() - multiple calls"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(spec_set=Target, closed=True, launch_timeout=30)
    target.check_result.return_value = Result.NONE
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True) as replay:
            assert not replay.run([testcase], 30, post_launch_delay=-1)
            assert replay.status.iteration == 1
            assert not replay.run([testcase], 30, post_launch_delay=-1)
            assert replay.status.iteration == 1
            assert not replay.run([testcase], 30, post_launch_delay=-1)
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
    test = mocker.Mock(spec_set=TestCase, timestamp=1.0)
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
        ReplayManager.load_testcases(tmp_path)
    # success
    fake_load.return_value = [test0, test1]
    tests, assets, env_vars = ReplayManager.load_testcases(tmp_path)
    assert env_vars
    assert env_vars["env"] == "var"
    assert not any(x.env_vars for x in tests)
    assert len(tests) == 2
    assert tests[0].cleanup.call_count == 0
    assert tests[1].cleanup.call_count == 0
    assert assets is None
    # success select
    test0.pop_assets.return_value = mocker.Mock(spec_set=AssetManager)
    fake_load.return_value = [test0, test1, test2, mocker.MagicMock(spec_set=TestCase)]
    tests, assets, _ = ReplayManager.load_testcases(tmp_path, subset=[1, 3])
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
    tests, _a, _e = ReplayManager.load_testcases(tmp_path, subset=[0, 10, -10, -1])
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
def test_replay_22(
    mocker, server, expect_hang, is_hang, use_sig, match_sig, ignored, results
):
    """test ReplayManager.run() - detect hangs"""
    served = ["index.html"]
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
    target = mocker.Mock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.handle_hang.return_value = False
    target.save_logs = _fake_save_logs
    target.monitor.is_healthy.return_value = False
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        testcase.hang = is_hang
        with ReplayManager(
            [], server, target, signature=signature, relaunch=10
        ) as replay:
            found = replay.run(
                [testcase], 10, expect_hang=expect_hang, post_launch_delay=-1
            )
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


def test_replay_23(mocker):
    """test ReplayManager.report_to_fuzzmanager()"""
    reporter = mocker.patch("grizzly.replay.replay.FuzzManagerReporter")
    # no reports or tests
    ReplayManager.report_to_fuzzmanager([], [])
    assert reporter.call_args == (("grizzly-replay",),)
    assert reporter.return_value.submit.call_count == 0
    reporter.reset_mock()
    # with reports and tests
    results = [
        mocker.Mock(
            spec_set=ReplayResult, report=mocker.Mock(spec_set=Report), expected=True
        ),
        mocker.Mock(
            spec_set=ReplayResult, report=mocker.Mock(spec_set=Report), expected=False
        ),
    ]
    test = mocker.Mock(spec_set=TestCase, adapter_name="test-tool-name")
    ReplayManager.report_to_fuzzmanager(results, [test])
    # check 'grizzy-' prefix is added
    assert reporter.call_args == (("grizzly-test-tool-name",),)
    assert reporter.return_value.submit.call_count == 2
    reporter.reset_mock()
    # with reports and no tests
    ReplayManager.report_to_fuzzmanager(results, [], tool="test-override")
    assert reporter.call_args == (("test-override",),)
    assert reporter.return_value.submit.call_count == 2


def test_replay_24(mocker, server, tmp_path):
    """test ReplayManager.run() - signature - matching stacks"""
    sig_file = tmp_path / "sig.json"
    sig_file.write_text(
        "{\n"
        '  "symptoms": [\n'
        "    {\n"
        '      "src": "stderr",\n'
        '      "type": "output",\n'
        '      "value": "/STDERR/"\n'
        "    }\n"
        "  ]\n"
        "}\n"
    )
    sig = CrashSignature.fromFile(str(sig_file))

    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.MagicMock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False

    call_count = 0

    def _save_logs_variation(result_logs):
        """create different stacks each call"""
        nonlocal call_count
        call_count += 1
        log_path = Path(result_logs)
        (log_path / "log_stderr.txt").write_text("STDERR log\n")
        (log_path / "log_stdout.txt").write_text("STDOUT log\n")
        with (log_path / "log_asan_blah.txt").open("w") as log_fp:
            log_fp.write("==1==ERROR: AddressSanitizer: ")
            log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
            log_fp.write(f"    #0 0xbad000 in call_a{call_count:02d} file.c:23:34\n")
            log_fp.write(f"    #1 0xbad001 in call_b{call_count:02d} file.c:12:45\n")

    target.save_logs.side_effect = _save_logs_variation

    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, relaunch=10, signature=sig) as replay:
            results = replay.run([testcase], 10, min_results=2, repeat=2)
            assert replay.signature is not None
            assert replay.status.ignored == 0
            assert replay.status.iteration == 2
            assert replay.status.results.total == 2
        assert len(results) == 1
        assert results[0].count == 2
        assert results[0].expected
        assert results[0].report
        results[0].report.cleanup()


@mark.parametrize(
    "stderr_log, ignored, total, include_stack",
    [
        # match stack only
        (["STDERR log\n", "STDERR log\n"], 0, 2, [True] * 2),
        # match stack only
        (["STDERR log\n", "STDERR log\nAssertion failure: test\n"], 0, 2, [True] * 2),
        # match stack and assertion message
        (["STDERR log\nAssertion failure: test\n", "STDERR log\n"], 1, 1, [True] * 2),
        # match stack and assertion message
        (["Assertion failure: 1\n", "Assertion failure: 2\n"], 1, 1, [True] * 2),
        # match, no match, match
        (["Assertion failure: 1\n", "a\n", "Assertion failure: 1\n"], 1, 2, [True] * 3),
        # fail to create signature x2 (missing stack)
        (["STDERR log\n", "STDERR log\n"], 0, 2, [False] * 2),
        # fail to create signature, create signature
        (["STDERR log\n", "STDERR log\n"], 1, 1, [False, True]),
        # create signature, fail to create signature
        (["STDERR log\n", "STDERR log\n"], 1, 1, [True, False]),
    ],
)
def test_replay_25(mocker, server, stderr_log, ignored, total, include_stack):
    """test ReplayManager.run() - no signature - match first result"""
    # NOTE: this is similar to "no signature - use first crash" test
    # but this is more of an integration test
    iters = len(stderr_log)
    assert iters == ignored + total, "test is broken"
    assert iters == len(include_stack), "test is broken"
    server.serve_path.return_value = (Served.ALL, ["index.html"])
    target = mocker.Mock(spec_set=Target, binary=Path("bin"), launch_timeout=30)
    target.check_result.return_value = Result.FOUND
    target.monitor.is_healthy.return_value = False

    def _save_logs_variation(result_logs):
        """create logs"""
        nonlocal stderr_log
        nonlocal include_stack
        log_path = Path(result_logs)
        (log_path / "log_stderr.txt").write_text(stderr_log.pop(0))
        (log_path / "log_stdout.txt").write_text("STDOUT log\n")
        if include_stack.pop(0):
            with (log_path / "log_asan_blah.txt").open("w") as log_fp:
                log_fp.write("==1==ERROR: AddressSanitizer: ")
                log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
                log_fp.write("    #0 0xbad000 in call_a file.c:23:34\n")
                log_fp.write("    #1 0xbad001 in call_b file.c:12:45\n")

    target.save_logs.side_effect = _save_logs_variation

    has_sig = include_stack[0]
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, relaunch=10) as replay:
            results = replay.run([testcase], 10, min_results=2, repeat=iters)
            if has_sig:
                assert replay.signature is not None
            else:
                assert replay.signature is None
            assert replay.status.ignored == ignored
            assert replay.status.iteration == iters
            assert replay.status.results.total == total
        for result in results:
            result.report.cleanup()
        assert results
