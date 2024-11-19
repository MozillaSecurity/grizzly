# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from itertools import count

from pytest import mark, raises

from sapphire import Sapphire, Served, ServerMap

from ..target import Result, Target, TargetLaunchError, TargetLaunchTimeout
from .report import Report
from .runner import Runner, _IdleChecker
from .storage import TestCase


@mark.parametrize(
    "coverage, scheme",
    [
        # coverage disabled
        (False, "http"),
        # coverage enabled
        (True, "http"),
        # https enabled
        (False, "https"),
    ],
)
def test_runner_01(mocker, coverage, scheme):
    """test Runner()"""
    mocker.patch(
        "grizzly.common.runner.perf_counter", autospec=True, side_effect=count()
    )
    server = mocker.Mock(spec_set=Sapphire, scheme=scheme)
    target = mocker.Mock(spec_set=Target)
    target.check_result.return_value = Result.NONE
    runner = Runner(server, target, relaunch=10)
    assert runner.initial
    assert not runner.startup_failure
    assert runner._idle is None
    assert runner._relaunch == 10
    assert runner._tests_run == 0
    serv_map = ServerMap()
    with TestCase("a.bin", "x") as testcase:
        testcase.add_from_bytes(b"", testcase.entry_point)
        serv_files = {"a.bin": testcase.root / "a.bin"}
        server.serve_path.return_value = (Served.ALL, serv_files)
        result = runner.run(set(), serv_map, testcase, coverage=coverage)
        assert testcase.https == (scheme == "https")
    assert runner.initial
    assert runner._tests_run == 1
    assert result.attempted
    assert result.duration == 1
    assert result.status == Result.NONE
    assert result.served == tuple(serv_files)
    assert not result.timeout
    assert not result.idle
    assert not serv_map.dynamic
    assert target.launch.call_count == 0
    assert target.close.call_count == 0
    assert target.dump_coverage.call_count == (1 if coverage else 0)
    assert target.handle_hang.call_count == 0


def test_runner_02(mocker):
    """test Runner.run() relaunch"""
    mocker.patch("grizzly.common.runner.perf_counter", autospec=True, return_value=1)
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    server = mocker.Mock(spec_set=Sapphire)
    target = mocker.Mock(spec_set=Target)
    target.check_result.return_value = Result.NONE
    serv_files = ("a.bin",)
    server.serve_path.return_value = (Served.ALL, {"a.bin": ""})
    testcase = mocker.Mock(
        spec_set=TestCase,
        __iter__=serv_files,
        entry_point=serv_files[0],
        required=serv_files,
    )
    # single run/iteration relaunch (not idle exit)
    target.monitor.is_idle.return_value = False
    runner = Runner(server, target, relaunch=1)
    assert runner._relaunch == 1
    smap = ServerMap()
    result = runner.run(set(), smap, testcase)
    assert runner.initial
    assert result.attempted
    assert target.close.call_count == 1
    assert target.monitor.is_idle.call_count > 0
    assert target.monitor.is_healthy.call_count > 0
    assert result.status == Result.NONE
    assert result.served == serv_files
    assert not smap.dynamic
    resource = smap.redirect.get("grz_next_test")
    assert resource
    assert resource.target == "grz_empty"
    assert not result.timeout
    target.reset_mock()
    testcase.reset_mock()
    # single run/iteration relaunch (idle exit)
    target.monitor.is_idle.return_value = True
    runner = Runner(server, target, relaunch=1)
    assert runner._relaunch == 1
    result = runner.run(set(), ServerMap(), testcase)
    assert result.attempted
    assert target.close.call_count == 1
    assert target.monitor.is_healthy.call_count > 0
    target.reset_mock()
    testcase.reset_mock()
    # multiple runs/iterations relaunch (is_healthy exit)
    runner = Runner(server, target, relaunch=3)
    target.monitor.is_healthy.return_value = False
    for _ in range(2):
        smap = ServerMap()
        result = runner.run(set(), smap, testcase)
        assert result.attempted
        assert target.close.call_count == 0
        assert target.monitor.is_healthy.call_count == 0
        assert result.status == Result.NONE
        assert result.served == serv_files
        assert not result.timeout
        assert not smap.dynamic
        assert "grz_next_test" not in smap.redirect
    smap = ServerMap()
    result = runner.run([], smap, testcase)
    assert runner._tests_run == 3
    assert not runner.initial
    assert result.attempted
    assert target.close.call_count == 1
    assert target.monitor.is_idle.call_count == 0
    assert target.monitor.is_healthy.call_count == 1
    assert result
    assert result.status == Result.NONE
    assert result.served == serv_files
    assert not smap.dynamic
    resource = smap.redirect.get("grz_next_test")
    assert resource
    assert resource.target == "grz_empty"


@mark.parametrize(
    "srv_result, served",
    [
        # no files served
        (Served.NONE, {}),
        # entry point not served
        (Served.REQUEST, {"harness": ""}),
    ],
)
def test_runner_03(mocker, srv_result, served):
    """test Runner() errors"""
    server = mocker.Mock(spec_set=Sapphire)
    server.serve_path.return_value = (srv_result, served)
    target = mocker.Mock(spec_set=Target)
    target.check_result.return_value = Result.NONE
    test = mocker.Mock(spec_set=TestCase, entry_point="x", required=["x"])
    runner = Runner(server, target)
    result = runner.run(set(), ServerMap(), test)
    assert runner.initial
    assert runner.startup_failure
    assert result
    assert result.status == Result.NONE
    assert not result.attempted
    assert set(result.served) == set(served)
    assert not result.timeout
    assert target.close.call_count == 1


@mark.parametrize(
    "ignore, status, idle, check_result",
    [
        # detect a hang
        ({"foo"}, Result.FOUND, False, 1),
        # ignore a hang
        ({"timeout"}, Result.IGNORED, False, 0),
        # ignore idle hang
        (set(), Result.IGNORED, True, 0),
    ],
)
def test_runner_04(mocker, ignore, status, idle, check_result):
    """test reporting timeout"""
    server = mocker.Mock(spec_set=Sapphire)
    target = mocker.Mock(spec_set=Target)
    serv_files = {"a.bin": ""}
    test = mocker.Mock(
        spec_set=TestCase,
        __iter__=tuple(serv_files),
        entry_point="a.bin",
        required=["a.bin"],
    )
    server.serve_path.return_value = (Served.TIMEOUT, serv_files)
    target.check_result.return_value = Result.FOUND
    target.handle_hang.return_value = idle
    target.monitor.is_healthy.return_value = False
    runner = Runner(server, target, relaunch=1)
    serv_map = ServerMap()
    result = runner.run(ignore, serv_map, test)
    assert result.status == status
    assert result.served == tuple(serv_files)
    assert result.timeout
    assert result.idle == idle
    assert "grz_empty" not in serv_map.dynamic
    assert target.check_result.call_count == check_result
    assert target.handle_hang.call_count == 1


@mark.parametrize(
    "served, attempted, target_result, status",
    [
        # FAILURE
        ({"a.bin": ""}, True, Result.FOUND, Result.FOUND),
        # IGNORED
        ({"a.bin": ""}, True, Result.IGNORED, Result.IGNORED),
        # failure before serving entry point
        ({"harness": ""}, False, Result.FOUND, Result.FOUND),
    ],
)
def test_runner_05(mocker, served, attempted, target_result, status):
    """test reporting failures"""
    server = mocker.Mock(spec_set=Sapphire)
    server.serve_path.return_value = (Served.REQUEST, served)
    target = mocker.Mock(spec_set=Target, launch_timeout=10)
    target.check_result.return_value = target_result
    target.monitor.is_healthy.return_value = False
    testcase = mocker.Mock(spec_set=TestCase, entry_point="a.bin", required=["a.bin"])
    runner = Runner(server, target)
    runner.launch("http://a/")
    result = runner.run(set(), ServerMap(), testcase)
    assert result.attempted == attempted
    assert result.status == status
    assert not result.timeout
    assert target.handle_hang.call_count == 0
    assert target.close.call_count == 1


def test_runner_06(mocker):
    """test Runner() with idle checking"""
    server = mocker.Mock(spec_set=Sapphire)
    target = mocker.Mock(spec_set=Target)
    target.check_result.return_value = Result.NONE
    serv_files = {"a.bin": ""}
    server.serve_path.return_value = (Served.ALL, serv_files)
    runner = Runner(server, target, idle_threshold=0.01, idle_delay=0.01, relaunch=10)
    assert runner._idle is not None
    result = runner.run(
        set(),
        ServerMap(),
        mocker.Mock(spec_set=TestCase, entry_point="a.bin", required=tuple(serv_files)),
    )
    assert result.status == Result.NONE
    assert result.attempted
    assert target.close.call_count == 0


def test_runner_07(mocker):
    """test Runner._keep_waiting()"""
    server = mocker.Mock(spec_set=Sapphire)
    target = mocker.Mock(spec_set=Target)

    target.monitor.is_healthy.return_value = True
    runner = Runner(server, target)
    assert runner._idle is None
    assert runner._keep_waiting()

    target.monitor.is_healthy.return_value = False
    assert not runner._keep_waiting()

    runner._idle = mocker.Mock(spec_set=_IdleChecker)
    runner._idle.is_idle.return_value = False
    target.monitor.is_healthy.return_value = True
    assert runner._keep_waiting()

    runner._idle.is_idle.return_value = True
    target.monitor.is_healthy.return_value = True
    assert not runner._keep_waiting()

    runner._idle.is_idle.return_value = False
    target.monitor.is_healthy.return_value = False
    assert not runner._keep_waiting()


def test_runner_08():
    """test Runner.location()"""
    result = Runner.location("a.html", 34567)
    assert result == "http://localhost:34567/a.html"
    result = Runner.location("/a.html", 34567)
    assert result == "http://localhost:34567/a.html"
    result = Runner.location("a.html", 34567, close_after=10)
    assert result == "http://localhost:34567/a.html?close_after=10"
    result = Runner.location("a.html", 9999, time_limit=60)
    assert result == "http://localhost:9999/a.html?time_limit=60000"
    result = Runner.location("a.html", 9999, close_after=10, time_limit=60)
    assert result == "http://localhost:9999/a.html?close_after=10&time_limit=60000"
    result = Runner.location("a.html", 9999, post_launch_delay=10)
    assert result == "http://localhost:9999/a.html?post_launch_delay=10"


def test_runner_09(mocker):
    """test Runner.launch()"""
    # set SLOW_LAUNCH_THRESHOLD for test coverage
    mocker.patch("grizzly.common.runner.SLOW_LAUNCH_THRESHOLD", 0)
    mocker.patch(
        "grizzly.common.runner.perf_counter", autospec=True, side_effect=count()
    )
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(spec_set=Target, launch_timeout=30)
    runner = Runner(server, target)
    # successful launch
    runner._tests_run = 1
    runner.launch("http://a/")
    assert runner._tests_run == 0
    assert target.launch.call_count == 1
    assert not runner.startup_failure
    target.reset_mock()
    # target launch error
    target.launch.side_effect = TargetLaunchError("test", mocker.Mock(spec_set=Report))
    with raises(TargetLaunchError, match="test"):
        runner.launch("http://a/")
    assert target.launch.call_count == 3
    assert runner.startup_failure
    target.reset_mock()
    # target launch timeout
    target.launch.side_effect = TargetLaunchTimeout
    with raises(TargetLaunchTimeout):
        runner.launch("http://a/", max_retries=3)
    assert target.launch.call_count == 3
    assert runner.startup_failure


def test_runner_10(mocker, tmp_path):
    """test Runner.run() adding includes to testcase"""
    server = mocker.Mock(spec_set=Sapphire)
    target = mocker.Mock(spec_set=Target)
    target.check_result.return_value = Result.NONE
    runner = Runner(server, target, relaunch=10)
    # create test files
    inc_path1 = tmp_path / "include"
    inc_path1.mkdir()
    inc1 = inc_path1 / "inc_file.bin"
    inc1.write_bytes(b"a")
    (inc_path1 / "nested").mkdir()
    inc2 = inc_path1 / "nested" / "nested_inc.bin"
    inc2.write_bytes(b"a")
    inc_path2 = tmp_path / "include2"
    inc_path2.mkdir()
    inc3 = inc_path2 / "inc_file3.txt"
    inc3.write_bytes(b"a")
    # build server map
    smap = ServerMap()
    smap.set_include("/", inc_path1)
    smap.set_include("/test", inc_path2)
    with TestCase("a.b", "x") as test:
        test.add_from_bytes(b"", test.entry_point)
        serv_files = {
            "a.b": test.root / "a.b",
            "inc_file.bin": inc1,
            "nested/nested_inc.bin": inc2,
            "test/inc_file3.txt": inc3,
        }
        server.serve_path.return_value = (Served.ALL, serv_files)
        result = runner.run(set(), smap, test)
        assert result.attempted
        assert result.status == Result.NONE
        assert "inc_file.bin" in test
        assert "nested/nested_inc.bin" in test
        assert "test/inc_file3.txt" in test


def test_runner_11(mocker):
    """test Runner.run() - remove unserved and add served test files"""
    server = mocker.Mock(spec_set=Sapphire)
    target = mocker.Mock(spec_set=Target)
    target.check_result.return_value = Result.NONE
    runner = Runner(server, target, relaunch=10)

    with TestCase("test.html", "x") as test:
        test.add_from_bytes(b"", test.entry_point)
        test.add_from_bytes(b"", "other.html")
        # add untracked file
        (test.root / "extra.js").touch()
        assert "extra.html" not in test
        assert "other.html" in test
        server.serve_path.return_value = (
            Served.ALL,
            {
                "test.html": test.root / "test.html",
                "extra.js": test.root / "extra.js",
            },
        )
        result = runner.run(set(), ServerMap(), test)
        assert result.attempted
        assert result.status == Result.NONE
        assert "test.html" in test
        assert "extra.js" in test
        assert "other.html" not in test


@mark.parametrize(
    "delay, srv_result, startup_failure",
    [
        # with delay
        (10, (Served.ALL, None), False),
        # continue immediately
        (0, (Served.ALL, None), False),
        # startup failure
        (0, (Served.NONE, None), True),
        # target hang while loading content
        (0, (Served.TIMEOUT, None), True),
    ],
)
def test_runner_12(mocker, delay, srv_result, startup_failure):
    """test Runner.post_launch()"""
    srv_timeout = 1
    server = mocker.Mock(spec_set=Sapphire, timeout=srv_timeout)
    server.serve_path.return_value = srv_result
    runner = Runner(server, mocker.Mock(spec_set=Target, launch_timeout=30))
    runner.launch("http://a/")
    runner.post_launch(delay=delay)
    assert server.serve_path.call_count == (1 if srv_result else 0)
    assert server.timeout == srv_timeout
    assert runner.startup_failure == startup_failure


def test_idle_check_01(mocker):
    """test simple _IdleChecker"""
    fake_time = mocker.patch("grizzly.common.runner.perf_counter", autospec=True)
    ichk = _IdleChecker(mocker.Mock(), 95, 10, poll_delay=1)
    assert ichk._threshold == 95
    assert ichk._init_delay == 10
    assert ichk._poll_delay == 1
    assert ichk._next_poll is None
    fake_time.return_value = 0
    ichk.schedule_poll(initial=True)
    assert ichk._next_poll == 10
    ichk.schedule_poll()
    assert ichk._next_poll == 1


def test_idle_check_02(mocker):
    """test _IdleChecker.is_idle()"""
    fake_time = mocker.patch("grizzly.common.runner.perf_counter", autospec=True)
    callbk = mocker.Mock()
    callbk.return_value = False
    ichk = _IdleChecker(callbk, 99, 10, poll_delay=1)
    fake_time.return_value = 0
    ichk.schedule_poll()
    # early check
    assert not ichk.is_idle()
    assert callbk.call_count == 0
    # not idle
    fake_time.return_value = 10
    assert not ichk.is_idle()
    assert ichk._next_poll == 11
    assert callbk.call_count == 1
    # idle
    callbk.return_value = True
    fake_time.return_value = ichk._next_poll
    assert ichk.is_idle()
    assert callbk.call_count == 2
