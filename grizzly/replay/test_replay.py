# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.replay
"""
from itertools import cycle
from os.path import join as pathjoin

from pytest import raises

from sapphire import Sapphire, SERVED_ALL, SERVED_REQUEST
from .replay import ReplayManager, ReplayResult
from ..common import Report, Status, TestCase, TestCaseLoadFailure
from ..target import Target


def _fake_save_logs(result_logs, meta=False):  # pylint: disable=unused-argument
    """write fake log data to disk"""
    with open(pathjoin(result_logs, "log_stderr.txt"), "w") as log_fp:
        log_fp.write("STDERR log\n")
    with open(pathjoin(result_logs, "log_stdout.txt"), "w") as log_fp:
        log_fp.write("STDOUT log\n")
    with open(pathjoin(result_logs, "log_asan_blah.txt"), "w") as log_fp:
        log_fp.write("==1==ERROR: AddressSanitizer: ")
        log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")

def test_replay_01(mocker):
    """test ReplayManager.cleanup()"""
    replay = ReplayManager([], mocker.Mock(spec=Sapphire), mocker.Mock(spec=Target), [mocker.Mock()])
    replay.status = mocker.Mock(spec=Status)
    replay.cleanup()
    assert replay.status.cleanup.call_count == 1

def test_replay_02(mocker, tmp_path):
    """test ReplayManager.run() - no repro"""
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, closed=True, launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    target.monitor.is_healthy.return_value = False
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True, relaunch=1) as replay:
            assert not replay.run([testcase])
            assert replay.signature is None
            assert replay.status.ignored == 0
            assert replay.status.iteration == 1
            assert replay.status.results == 0
            assert target.monitor.is_healthy.call_count == 1
            assert target.close.call_count == 2
        assert not any(tmp_path.glob("*"))

def test_replay_03(mocker):
    """test ReplayManager.run() - no repro - with repeats"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, closed=False, launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    target.monitor.is_healthy.return_value = False
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True, relaunch=100) as replay:
            assert not replay.run([testcase], repeat=10, min_results=1)
            assert replay.signature is None
            assert replay.status.ignored == 0
            assert replay.status.iteration == 10
            assert replay.status.results == 0
            assert target.monitor.is_healthy.call_count == 1
            assert target.close.call_count == 2

def test_replay_04(mocker):
    """test ReplayManager.run() - exit - skip shutdown in runner"""
    # this will make runner appear to have just relaunched the target
    # and skip the expected shutdown
    mocker.patch(
        "grizzly.common.runner.Runner._tests_run",
        new_callable=mocker.PropertyMock,
        return_value=0)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, closed=False, launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True, relaunch=100) as replay:
            assert not replay.run([testcase], repeat=10, min_results=1)
            assert replay.status.ignored == 0
            assert replay.status.iteration == 10
            assert replay.status.results == 0
            assert target.monitor.is_healthy.call_count == 0
            assert target.close.call_count == 1

def test_replay_05(mocker, tmp_path):
    """test ReplayManager.run() - successful repro"""
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    served = ["index.html"]
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (SERVED_ALL, served)
    target = mocker.Mock(spec=Target, binary="C:\\fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, relaunch=10) as replay:
            results = replay.run([testcase])
            assert replay.signature is not None
            assert replay.status.ignored == 0
            assert replay.status.iteration == 1
            assert replay.status.results == 1
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
        assert not any(tmp_path.glob("*"))

def test_replay_06(mocker, tmp_path):
    """test ReplayManager.run() - error - landing page not requested on first iteration"""
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target, closed=True, launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    server.serve_path.return_value = (SERVED_REQUEST, ["x"])
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases, repeat=2)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 0
        # target.close() called once in runner and once by ReplayManager.run()
        assert target.close.call_count == 2
    assert target.save_logs.call_count == 1

def test_replay_07(mocker, tmp_path):
    """test ReplayManager.run() - delayed failure - following test landing page not requested"""
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    target = mocker.Mock(spec=Target, binary="bin", launch_timeout=30)
    type(target).closed = mocker.PropertyMock(side_effect=(True, False, True))
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.side_effect = (Target.RESULT_NONE, Target.RESULT_FAILURE)
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    server.serve_path.side_effect = ((SERVED_ALL, ["index.html"]), (SERVED_REQUEST, ["x"]))
    with ReplayManager([], server, target, use_harness=True, relaunch=10) as replay:
        assert replay.run(testcases, repeat=2)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 2
        assert replay.status.results == 1
        # target.close() called once in runner and once by ReplayManager.run()
        assert target.close.call_count == 2

def test_replay_08(mocker, tmp_path):
    """test ReplayManager.run() - ignored"""
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, closed=True, launch_timeout=30)
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.detect_failure.return_value = Target.RESULT_IGNORED
    target.monitor.is_healthy.return_value = False
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases)
        assert target.monitor.is_healthy.call_count == 1
        assert target.close.call_count == 2
        assert replay.status.ignored == 1
        assert replay.status.iteration == 1
        assert replay.status.results == 0
    assert not any(tmp_path.glob("*"))

def test_replay_09(mocker, tmp_path):
    """test ReplayManager.run() - early exit"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, binary="path/fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_IGNORED = Target.RESULT_IGNORED
    target.RESULT_NONE = Target.RESULT_NONE
    target.save_logs = _fake_save_logs
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    # early failure
    target.detect_failure.side_effect = (Target.RESULT_FAILURE, Target.RESULT_IGNORED, Target.RESULT_NONE)
    target.monitor.is_healthy.side_effect = (False, False, True, False)
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases, repeat=4, min_results=3)
        assert target.close.call_count == 4
        assert replay.status.iteration == 3
        assert replay.status.results == 1
        assert replay.status.ignored == 1
    # early success
    target.reset_mock()
    target.detect_failure.side_effect = (Target.RESULT_FAILURE, Target.RESULT_IGNORED, Target.RESULT_FAILURE)
    target.monitor.is_healthy.side_effect = (False, False, False)
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(testcases, repeat=4, min_results=2)
        assert target.close.call_count == 4
        assert replay.status.iteration == 3
        assert replay.status.results == 2
        assert replay.status.ignored == 1
    assert len(results) == 1
    assert sum(x.count for x in results) == 2
    target.reset_mock()
    # ignore early failure (perform all repeats)
    target.detect_failure.return_value = Target.RESULT_NONE
    target.detect_failure.side_effect = None
    target.monitor.is_healthy.side_effect = None
    target.monitor.is_healthy.return_value = True
    with ReplayManager([], server, target, use_harness=False) as replay:
        assert not replay.run(testcases, repeat=4, min_results=4, exit_early=False)
        assert target.close.call_count == 5
        assert replay.status.iteration == 4
        assert replay.status.results == 0
        assert replay.status.ignored == 0
    target.reset_mock()
    # ignore early success (perform all repeats)
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.monitor.is_healthy.return_value = False
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(testcases, repeat=4, min_results=1, exit_early=False)
        assert target.close.call_count == 5
        assert replay.status.iteration == 4
        assert replay.status.results == 4
        assert replay.status.ignored == 0
    assert len(results) == 1
    assert sum(x.count for x in results) == 4

def test_replay_10(mocker, tmp_path):
    """test ReplayManager.run() - test signatures - fail to meet minimum"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_0 = mocker.Mock(spec=Report)
    report_0.crash_info.createShortSignature.return_value = "No crash detected"
    report_1 = mocker.Mock(spec=Report, crash_hash="hash1", major="0123abcd", minor="01239999")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(spec=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    report_3 = mocker.Mock(spec=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876")
    report_3.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0, report_1, report_2, report_3)
    fake_report.calc_hash.return_value = "bucketHASH"
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    signature = mocker.Mock()
    signature.matches.side_effect = (True, False, False)
    target = mocker.Mock(spec=Target, binary="fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, signature=signature, use_harness=False) as replay:
        results = replay.run(testcases, repeat=4, min_results=2)
        assert target.close.call_count == 5
        assert replay.signature == signature
        assert replay.status.iteration == 4
        assert replay.status.results == 1
        assert replay.status.ignored == 2
    assert fake_report.call_count == 4
    assert len(results) == 1
    assert not results[0].expected
    assert results[0].count == 2
    assert report_0.cleanup.call_count == 1
    assert report_1.cleanup.call_count == 1
    assert report_2.cleanup.call_count == 0
    assert report_3.cleanup.call_count == 1
    assert signature.matches.call_count == 3

def test_replay_11(mocker, tmp_path):
    """test ReplayManager.run() - test signatures - multiple matches"""
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_0 = mocker.Mock(spec=Report, crash_hash="hash1", major="0123abcd", minor="01239999")
    report_0.crash_info.createShortSignature.return_value = "[@ test1]"
    report_1 = mocker.Mock(spec=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876")
    report_1.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0, report_1)
    fake_report.calc_hash.return_value = "bucketHASH"
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["a.html"])
    signature = mocker.Mock()
    signature.matches.side_effect = (True, True)
    target = mocker.Mock(spec=Target, binary="fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.monitor.is_healthy.return_value = False
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="a.html", optional=[])]
    with ReplayManager([], server, target, signature=signature, use_harness=False) as replay:
        results = replay.run(testcases, repeat=2, min_results=2)
        assert target.close.call_count == 3
        assert replay.signature == signature
        assert replay.status.iteration == 2
        assert replay.status.results == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 2
    assert len(results) == 1
    assert results[0].expected
    assert results[0].count == 2
    assert report_0.cleanup.call_count == 0
    assert report_1.cleanup.call_count == 1
    assert signature.matches.call_count == 2

def test_replay_12(mocker, tmp_path):
    """test ReplayManager.run() - any crash - success"""
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_0 = mocker.Mock(spec=Report)
    report_0.crash_info.createShortSignature.return_value = "No crash detected"
    report_1 = mocker.Mock(spec=Report, crash_hash="hash1", major="0123abcd", minor="01239999")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(spec=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0, report_1, report_2)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, binary="fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.monitor.is_healthy.return_value = False
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, any_crash=True, use_harness=False) as replay:
        results = replay.run(testcases, repeat=3, min_results=2)
        assert target.close.call_count == 4
        assert replay.signature is None
        assert replay.status.iteration == 3
        assert replay.status.results == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 3
    assert len(results) == 2
    assert all(x.expected for x in results)
    assert sum(x.count for x in results if x.expected) == 2
    assert report_0.cleanup.call_count == 1
    assert report_1.cleanup.call_count == 0
    assert report_2.cleanup.call_count == 0

def test_replay_13(mocker, tmp_path):
    """test ReplayManager.run() - any crash - fail to meet minimum"""
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_0 = mocker.Mock(spec=Report)
    report_0.crash_info.createShortSignature.return_value = "No crash detected"
    report_1 = mocker.Mock(spec=Report, crash_hash="hash1", major="0123abcd", minor="01239999")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    report_2 = mocker.Mock(spec=Report, crash_hash="hash2", major="0123abcd", minor="abcd9876")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    report_3 = mocker.Mock(spec=Report)
    report_3.crash_info.createShortSignature.return_value = "No crash detected"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0, report_1, report_2, report_3)
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, binary="fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.monitor.is_healthy.return_value = False
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, any_crash=True) as replay:
        assert not replay.run(testcases, repeat=4, min_results=3)
        assert target.close.call_count == 5
        assert replay.signature is None
        assert replay.status.iteration == 4
        assert replay.status.results == 2
        assert replay.status.ignored == 0
    assert fake_report.call_count == 4
    assert report_0.cleanup.call_count == 1
    assert report_1.cleanup.call_count == 1
    assert report_2.cleanup.call_count == 1
    assert report_3.cleanup.call_count == 1

def test_replay_14(mocker, tmp_path):
    """test ReplayManager.run() - no signature - use first crash"""
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_1 = mocker.Mock(spec=Report, crash_hash="hash1", major="0123", minor="9999")
    report_1.crash_info.createShortSignature.return_value = "[@ test1]"
    auto_sig = mocker.Mock()
    auto_sig.matches.side_effect = (True, False, True)
    report_1.crash_signature = auto_sig
    report_2 = mocker.Mock(spec=Report, crash_hash="hash2", major="abcd", minor="9876")
    report_2.crash_info.createShortSignature.return_value = "[@ test2]"
    report_3 = mocker.Mock(spec=Report, crash_hash="hash1", major="0123", minor="9999")
    report_3.crash_info.createShortSignature.return_value = "[@ test1]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_1, report_2, report_3)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, binary="fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    target.monitor.is_healthy.return_value = False
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, use_harness=False) as replay:
        results = replay.run(testcases, repeat=3, min_results=2)
        assert target.close.call_count == 4
        assert replay.signature == auto_sig
        assert replay.status.iteration == 3
        assert replay.status.results == 2
        assert replay.status.ignored == 1
    assert fake_report.call_count == 3
    assert len(results) == 2
    assert sum(x.expected for x in results) == 1
    assert sum(x.count for x in results if x.expected) == 2
    assert report_1.cleanup.call_count == 0
    assert report_2.cleanup.call_count == 0
    assert report_3.cleanup.call_count == 1

def test_replay_15(mocker, tmp_path):
    """test ReplayManager.run() - unexpected exception"""
    mocker.patch("grizzly.replay.replay.mkdtemp", autospec=True, return_value=str(tmp_path))
    report_0 = mocker.Mock(spec=Report, crash_hash="hash1", major="0123abcd", minor="01239999")
    report_0.crash_info.createShortSignature.return_value = "[@ test1]"
    fake_report = mocker.patch("grizzly.replay.replay.Report", autospec=True)
    fake_report.side_effect = (report_0,)
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.side_effect = ((SERVED_ALL, ["index.html"]), KeyboardInterrupt)
    target = mocker.Mock(spec=Target, binary="fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.detect_failure.return_value = Target.RESULT_FAILURE
    testcases = [mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, any_crash=True, use_harness=True, relaunch=2) as replay:
        with raises(KeyboardInterrupt):
            replay.run(testcases, repeat=3, min_results=2)
        assert replay.signature is None
        assert replay.status.iteration == 2
        assert replay.status.results == 1
        assert replay.status.ignored == 0
    assert target.close.call_count == 1
    assert target.monitor.is_healthy.call_count == 0
    assert fake_report.call_count == 1
    assert report_0.cleanup.call_count == 1

def test_replay_16(mocker):
    """test ReplayManager.run() - multiple TestCases - no repro"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, closed=True, launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    testcases = [
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[]),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[]),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, use_harness=True) as replay:
        assert not replay.run(testcases)
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 0
    assert target.close.call_count == 2
    assert all(x.dump.call_count == 1 for x in testcases)

def test_replay_17(mocker):
    """test ReplayManager.run() - multiple TestCases - no repro - with repeats"""
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, launch_timeout=30)
    # test relaunch < repeat
    type(target).closed = mocker.PropertyMock(side_effect=cycle([True, False]))
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    target.monitor.is_healthy.return_value = False
    testcases = [
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[]),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[]),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="index.html", optional=[])]
    with ReplayManager([], server, target, use_harness=True, relaunch=2) as replay:
        assert not replay.run(testcases, repeat=10)
        assert server.serve_path.call_count == 30
        assert target.close.call_count == 6
        assert target.launch.call_count == 5
        assert replay.status.ignored == 0
        assert replay.status.iteration == 10
        assert replay.status.results == 0
    assert target.monitor.is_healthy.call_count == 5
    assert all(x.dump.call_count == 1 for x in testcases)

def test_replay_18(mocker, tmp_path):
    """test ReplayManager.run() - multiple TestCases - successful repro"""
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.side_effect = (
        (SERVED_ALL, ["a.html"]),
        (SERVED_ALL, ["b.html"]),
        (SERVED_ALL, ["c.html"]))
    target = mocker.Mock(spec=Target, binary="fake_bin", launch_timeout=30)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.side_effect = (
        Target.RESULT_NONE,
        Target.RESULT_NONE,
        Target.RESULT_FAILURE)
    target.monitor.is_healthy.return_value = False
    target.save_logs = _fake_save_logs
    testcases = [
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="a.html", optional=[]),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="b.html", optional=[]),
        mocker.Mock(spec=TestCase, env_vars=[], landing_page="c.html", optional=[])]
    with ReplayManager([], server, target, use_harness=True) as replay:
        results = replay.run(testcases)
        assert target.close.call_count == 2
        assert replay.status.ignored == 0
        assert replay.status.iteration == 1
        assert replay.status.results == 1
    assert len(results) == 1
    assert len(results[0].served) == len(testcases)
    assert results[0].served[0][0] == "a.html"
    assert results[0].served[1][0] == "b.html"
    assert results[0].served[2][0] == "c.html"
    assert len(results[0].durations) == len(testcases)
    assert all(x.dump.call_count == 1 for x in testcases)

def test_replay_19(mocker, tmp_path):
    """test ReplayManager.run() - multiple calls"""
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    mocker.patch("grizzly.replay.replay.grz_tmp", return_value=str(tmp_path))
    server = mocker.Mock(spec=Sapphire, port=0x1337, timeout=10)
    server.serve_path.return_value = (SERVED_ALL, ["index.html"])
    target = mocker.Mock(spec=Target, closed=True, launch_timeout=30)
    target.RESULT_NONE = Target.RESULT_NONE
    target.detect_failure.return_value = Target.RESULT_NONE
    with TestCase("index.html", "redirect.html", "test-adapter") as testcase:
        with ReplayManager([], server, target, use_harness=True) as replay:
            assert not replay.run([testcase])
            assert replay.status.iteration == 1
            assert not replay.run([testcase])
            assert replay.status.iteration == 1
            assert not replay.run([testcase])
            assert replay.status.iteration == 1
    assert server.serve_path.call_count == 3

def test_replay_20(mocker, tmp_path):
    """test ReplayManager.report_to_filesystem()"""
    # no reports
    ReplayManager.report_to_filesystem(str(tmp_path), [])
    assert not any(tmp_path.glob("*"))
    # with reports and tests
    (tmp_path / "report_expected").mkdir()
    result0 = mocker.Mock(ReplayResult, count=1, durations=[1], expected=True, served=[])
    result0.report = mocker.Mock(
        spec=Report,
        path=str(tmp_path / "report_expected"),
        prefix="expected")
    (tmp_path / "report_other1").mkdir()
    result1 = mocker.Mock(ReplayResult, count=1, durations=[1], expected=False, served=None)
    result1.report = mocker.Mock(
        spec=Report,
        path=str(tmp_path / "report_other1"),
        prefix="other1")
    (tmp_path / "report_other2").mkdir()
    result2 = mocker.Mock(ReplayResult, count=1, durations=[1], expected=False, served=None)
    result2.report = mocker.Mock(
        spec=Report,
        path=str(tmp_path / "report_other2"),
        prefix="other2")
    test = mocker.Mock(spec=TestCase)
    path = tmp_path / "dest"
    ReplayManager.report_to_filesystem(str(path), [result0, result1, result2], tests=[test])
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
    ReplayManager.report_to_filesystem(str(path), [result0])
    assert not (tmp_path / "report_expected").is_dir()
    assert path.is_dir()
    assert (path / "reports" / "expected_logs").is_dir()

def test_replay_21(mocker, tmp_path):
    """test ReplayManager.load_testcases()"""
    fake_load = mocker.patch("grizzly.replay.replay.TestCase.load")
    test0 = mocker.Mock(spec=TestCase)
    test1 = mocker.Mock(spec=TestCase, landing_page="x.html")
    test2 = mocker.Mock(spec=TestCase)
    # failure
    fake_load.return_value = ()
    with raises(TestCaseLoadFailure, match="Failed to load TestCases"):
        ReplayManager.load_testcases(str(tmp_path), False)
    # success
    fake_load.return_value = [test0, test1]
    tests = ReplayManager.load_testcases(str(tmp_path), False)
    assert len(tests) == 2
    assert tests[0].cleanup.call_count == 0
    assert tests[1].cleanup.call_count == 0
    # success select
    fake_load.return_value = [test0, test1, test2, mocker.Mock(spec=TestCase)]
    tests = ReplayManager.load_testcases(str(tmp_path), False, subset=[1, 3])
    assert len(tests) == 2
    assert tests[0].landing_page == "x.html"
    assert test0.cleanup.call_count == 1
    assert test1.cleanup.call_count == 0
    assert test2.cleanup.call_count == 1
    test0.reset_mock()
    test2.reset_mock()
    # select (first and last) with invalid input
    fake_load.return_value = [test0, test1, test2]
    tests = ReplayManager.load_testcases(str(tmp_path), False, subset=[0, 10, -10, -1])
    assert len(tests) == 2
    assert test0.cleanup.call_count == 0
    assert test1.cleanup.call_count == 1
    assert test2.cleanup.call_count == 0
