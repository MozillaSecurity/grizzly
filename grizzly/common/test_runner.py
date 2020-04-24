# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
import pytest

from sapphire import Sapphire, SERVED_ALL, SERVED_NONE, SERVED_REQUEST, SERVED_TIMEOUT, ServerMap

from .runner import _IdleChecker, Runner
from .storage import TestCase
from ..target import Target, TargetLaunchError, TargetLaunchTimeout

def test_runner_01(mocker):
    """test Runner()"""
    server = mocker.Mock(spec=Sapphire)
    target = mocker.Mock(spec=Target)
    target.detect_failure.return_value = target.RESULT_NONE
    runner = Runner(server, target)
    assert runner._idle is None
    assert runner.result is None
    assert runner.served is None
    assert not runner.timeout
    serv_files = ["a.bin", "/another/file.bin"]
    testcase = mocker.Mock(spec=TestCase)
    testcase.landing_page = serv_files[0]
    # all files served
    server.serve_testcase.return_value = (SERVED_ALL, serv_files)
    runner.run([], ServerMap(), testcase)
    assert runner.result == runner.COMPLETE
    assert runner.served == serv_files
    assert not runner.timeout
    # some files served
    server.serve_testcase.return_value = (SERVED_REQUEST, serv_files)
    runner.run([], ServerMap(), testcase)
    assert runner.result == runner.COMPLETE
    assert runner.served == serv_files
    assert not runner.timeout

def test_runner_02(mocker):
    """test Runner() errors"""
    server = mocker.Mock(spec=Sapphire)
    target = mocker.Mock(spec=Target)
    testcase = mocker.Mock(spec=TestCase, landing_page="x")
    runner = Runner(server, target)
    # no files served
    server.serve_testcase.return_value = (SERVED_NONE, [])
    target.detect_failure.return_value = target.RESULT_NONE
    runner.run([], ServerMap(), testcase)
    assert runner.result == runner.ERROR
    assert not runner.served
    assert not runner.timeout
    # landing page not served
    server.serve_testcase.return_value = (SERVED_REQUEST, ["harness"])
    target.detect_failure.return_value = target.RESULT_NONE
    runner.run([], ServerMap(), testcase)
    assert runner.result == runner.ERROR
    assert runner.served

def test_runner_03(mocker):
    """test reporting timeout"""
    server = mocker.Mock(spec=Sapphire)
    target = mocker.Mock(spec=Target)
    serv_files = ["a.bin", "/another/file.bin"]
    server.serve_testcase.return_value = (SERVED_TIMEOUT, serv_files)
    runner = Runner(server, target)
    target.detect_failure.return_value = target.RESULT_FAILURE
    runner.run([], ServerMap(), mocker.Mock(spec=TestCase, landing_page="x"))
    assert runner.result == runner.FAILED
    assert runner.served == serv_files
    assert runner.timeout

def test_runner_04(mocker):
    """test reporting failures"""
    server = mocker.Mock(spec=Sapphire)
    target = mocker.Mock(spec=Target)
    serv_files = ["file.bin"]
    server.serve_testcase.return_value = (SERVED_REQUEST, serv_files)
    testcase = mocker.Mock(spec=TestCase, landing_page=serv_files[0])
    runner = Runner(server, target)
    # test FAILURE
    target.detect_failure.return_value = target.RESULT_FAILURE
    runner.run([], ServerMap(), testcase)
    assert runner.result == runner.FAILED
    assert runner.served == serv_files
    assert not runner.timeout
    # test IGNORED
    target.detect_failure.return_value = target.RESULT_IGNORED
    runner.run([], ServerMap(), testcase)
    assert runner.result == runner.IGNORED
    assert runner.served == serv_files
    assert not runner.timeout
    # failure before serving landing page
    server.serve_testcase.return_value = (SERVED_REQUEST, ["harness"])
    target.detect_failure.return_value = target.RESULT_FAILURE
    runner.run([], ServerMap(), testcase)
    assert runner.result == runner.FAILED
    assert runner.served
    assert not runner.timeout

def test_runner_05(mocker):
    """test Runner() with idle checking"""
    server = mocker.Mock(spec=Sapphire)
    target = mocker.Mock(spec=Target)
    target.detect_failure.return_value = target.RESULT_NONE
    serv_files = ["/fake/file", "/another/file.bin"]
    server.serve_testcase.return_value = (SERVED_REQUEST, serv_files)
    runner = Runner(server, target, idle_threshold=0.01, idle_delay=0.01)
    assert runner._idle is not None
    runner.run([], ServerMap(), mocker.Mock(spec=TestCase, landing_page=serv_files[0]))
    assert runner.result == runner.COMPLETE

def test_runner_06(mocker):
    """test Runner._keep_waiting()"""
    server = mocker.Mock(spec=Sapphire)
    target = mocker.Mock(spec=Target)

    target.monitor.is_healthy.return_value = True
    runner = Runner(server, target)
    assert runner._keep_waiting()

    target.monitor.is_healthy.return_value = False
    assert not runner._keep_waiting()

    runner._idle = mocker.Mock(spec=_IdleChecker)
    runner._idle.is_idle.return_value = False
    target.monitor.is_healthy.return_value = True
    assert runner._keep_waiting()

    runner._idle.is_idle.return_value = True
    target.monitor.is_healthy.return_value = True
    assert not runner._keep_waiting()

    runner._idle.is_idle.return_value = False
    target.monitor.is_healthy.return_value = False
    assert not runner._keep_waiting()

def test_runner_07():
    """test Runner.location()"""
    result = Runner.location("a.html", 34567)
    assert result == "http://127.0.0.1:34567/a.html"
    result = Runner.location("a.html", 34567, close_after=10)
    assert result == "http://127.0.0.1:34567/a.html?close_after=10"
    result = Runner.location("a.html", 34567, close_after=10, forced_close=False)
    assert result == "http://127.0.0.1:34567/a.html?close_after=10&forced_close=0"
    result = Runner.location("a.html", 34567, forced_close=False)
    assert result == "http://127.0.0.1:34567/a.html?forced_close=0"
    result = Runner.location("a.html", 9999, close_after=10, forced_close=False, timeout=60)
    assert result == "http://127.0.0.1:9999/a.html?close_after=10&forced_close=0&timeout=60000"

def test_runner_08(mocker):
    """test Runner.launch()"""
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target)

    runner = Runner(server, target)
    runner.launch("http://a/")
    assert target.launch.call_count == 1
    target.reset_mock()

    target.launch.side_effect = TargetLaunchError
    with pytest.raises(TargetLaunchError):
        runner.launch("http://a/")
    assert target.launch.call_count == 1
    target.reset_mock()

    target.launch.side_effect = TargetLaunchTimeout
    with pytest.raises(TargetLaunchTimeout):
        runner.launch("http://a/", max_retries=3)
    assert target.launch.call_count == 3

def test_idle_check_01(mocker):
    """test simple _IdleChecker"""
    fake_time = mocker.patch("grizzly.common.runner.time", autospec=True)
    ichk = _IdleChecker(mocker.Mock(), 100, 10, poll_delay=1)
    assert ichk._threshold == 100
    assert ichk._init_delay == 10
    assert ichk._poll_delay == 1
    assert ichk._next_poll is None
    fake_time.time.return_value = 0
    ichk.schedule_poll(initial=True)
    assert ichk._next_poll == 10
    ichk.schedule_poll()
    assert ichk._next_poll == 1

def test_idle_check_02(mocker):
    """test _IdleChecker.is_idle()"""
    fake_time = mocker.patch("grizzly.common.runner.time", autospec=True)
    callbk = mocker.Mock()
    callbk.return_value = False
    #check_cb, delay, duration, threshold
    ichk = _IdleChecker(callbk, 100, 10, poll_delay=1)
    fake_time.time.return_value = 0
    ichk.schedule_poll()
    # early check
    assert not ichk.is_idle()
    assert callbk.call_count == 0
    # not idle
    fake_time.time.return_value = 10
    assert not ichk.is_idle()
    assert ichk._next_poll == 11
    assert callbk.call_count == 1
    # idle
    callbk.return_value = True
    fake_time.time.return_value = ichk._next_poll
    assert ichk.is_idle()
    assert callbk.call_count == 2
