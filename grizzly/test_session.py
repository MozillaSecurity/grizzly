# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.Session
"""
from pytest import mark, raises

from sapphire import SERVED_ALL, SERVED_NONE, SERVED_TIMEOUT, Sapphire

from .adapter import Adapter
from .common import Report, Reporter, RunResult, Status
from .session import LogOutputLimiter, Session, SessionError
from .target import Target, TargetLaunchError


class SimpleAdapter(Adapter):
    def __init__(self, use_harness, remaining=None):
        super().__init__("simple")
        self.remaining = remaining
        self._use_harness = use_harness

    def setup(self, input_path, _server_map):
        if self._use_harness:
            self.enable_harness()
        self.fuzz["input"] = input_path

    def generate(self, testcase, _server_map):
        assert testcase.adapter_name == self.name
        testcase.input_fname = self.fuzz["input"]
        testcase.add_from_data("test", testcase.landing_page)
        if self.remaining is not None:
            assert self.remaining > 0
            self.remaining -= 1


@mark.parametrize(
    "harness, profiling, coverage, relaunch, iters",
    [
        # with harness, single iteration
        (True, False, False, 1, 1),
        # with harness, 10 iterations relaunch every iteration
        (True, False, False, 1, 10),
        # with harness, 10 iterations relaunch every other iteration
        (True, False, False, 2, 10),
        # with harness, 10 iterations no relaunches
        (True, False, False, 10, 10),
        # no harness, single iteration
        (False, False, False, 1, 1),
        # no harness, 10 iterations
        (False, False, False, 1, 10),
        # test enable profiling
        (True, True, False, 10, 10),
        # test Session.dump_coverage()
        (True, True, True, 2, 2),
    ],
)
def test_session_01(mocker, tmp_path, harness, profiling, coverage, relaunch, iters):
    """test Session with typical fuzzer Adapter"""
    Status.PATH = str(tmp_path)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    target = mocker.Mock(spec=Target, launch_timeout=30, prefs=str(prefs))
    target.log_size.return_value = 1000
    target.monitor.launches = 1
    # avoid shutdown delay
    target.monitor.is_healthy.return_value = False
    # calculate if the target is 'closed' based on relaunch
    type(target).closed = mocker.PropertyMock(
        side_effect=((x % relaunch == 0) for x in range(iters))
    )
    with Session(
        SimpleAdapter(harness),
        None,
        server,
        target,
        coverage=coverage,
        enable_profiling=profiling,
        relaunch=relaunch,
    ) as session:
        server.serve_path = lambda *a, **kv: (
            SERVED_ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run([], 10, input_path="file.bin", iteration_limit=iters)
        assert session.status.iteration == iters
        assert session.status.test_name == "file.bin"
        assert target.close.call_count == iters / relaunch
        assert target.detect_failure.call_count == iters
        assert target.handle_hang.call_count == 0
        if profiling:
            assert any(session.status.profile_entries())
        else:
            assert not any(session.status.profile_entries())
        if coverage:
            assert target.dump_coverage.call_count == iters
        else:
            assert target.dump_coverage.call_count == 0


@mark.parametrize(
    "harness, relaunch, remaining",
    [
        # no harness, 1 iteration
        (False, 1, 1),
        # no harness, 5 iterations, relaunch every iteration
        (False, 1, 5),
        # harness, 1 iteration
        (True, 1, 1),
        # harness, 10 iterations, relaunch every other iteration
        (True, 2, 10),
        # harness, 10 iterations
        (True, 10, 10),
    ],
)
def test_session_02(tmp_path, mocker, harness, relaunch, remaining):
    """test Session with playback Adapter"""
    Status.PATH = str(tmp_path)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target, launch_timeout=30, prefs=None)
    # calculate if the target is 'closed' based on relaunch
    type(target).closed = mocker.PropertyMock(
        side_effect=((x % relaunch == 0) for x in range(remaining))
    )
    # avoid shutdown delay
    target.monitor.is_healthy.return_value = False
    # set target.log_size to test warning code path
    target.log_size.return_value = Session.TARGET_LOG_SIZE_WARN + 1
    with Session(
        SimpleAdapter(harness, remaining=remaining),
        None,
        server,
        target,
        relaunch=relaunch,
    ) as session:
        server.serve_path = lambda *a, **kv: (
            SERVED_ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run([], 10)
        assert session.status.iteration == remaining
        assert session.status.test_name is None
        assert target.detect_failure.call_count == remaining
        assert target.handle_hang.call_count == 0


@mark.parametrize(
    "harness, report_size, relaunch, iters",
    [
        # with harness, collect 1 test case
        (True, 1, 1, 1),
        # with harness, collect 2 test cases
        (True, 2, 2, 2),
        # with harness, collect 2 test cases,
        (True, 2, 3, 3),
        # with harness, collect 3 test cases, relaunch 1
        (True, 3, 1, 3),
        # without harness, collect 1 test case
        (False, 1, 1, 1),
        # without harness, collect 1 test case, 3 iterations
        (False, 1, 1, 3),
    ],
)
def test_session_03(mocker, tmp_path, harness, report_size, relaunch, iters):
    """test Session - detecting failure"""
    Status.PATH = str(tmp_path)
    adapter = SimpleAdapter(harness)
    reporter = mocker.Mock(spec=Reporter)
    report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target, launch_timeout=30, prefs=None)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_NONE = Target.RESULT_NONE
    target.monitor.launches = 1
    # avoid shutdown delay
    target.monitor.is_healthy.return_value = False
    # calculate if the target is 'closed' based on relaunch
    type(target).closed = mocker.PropertyMock(
        side_effect=((x % relaunch == 0) for x in range(iters))
    )
    # failure is on final iteration
    target.detect_failure.side_effect = [
        Target.RESULT_NONE for x in range(iters - 1)
    ] + [Target.RESULT_FAILURE]
    target.log_size.return_value = 1
    target.create_report.return_value = report
    with Session(
        adapter, reporter, server, target, relaunch=relaunch, report_size=report_size
    ) as session:
        server.serve_path = lambda *a, **kv: (
            SERVED_ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run([], 10, input_path="file.bin", iteration_limit=iters)
        assert reporter.submit.call_count == 1
        assert len(reporter.submit.call_args[0][0]) == min(report_size, relaunch)
        assert reporter.submit.call_args[0][1].major == "major123"


def test_session_04(mocker, tmp_path):
    """test Adapter creating invalid test case"""

    class FuzzAdapter(Adapter):
        def generate(self, _testcase, _server_map):
            pass

    Status.PATH = str(tmp_path)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_NONE, [])
    target = mocker.Mock(spec=Target, launch_timeout=30, prefs=None)
    target.monitor.launches = 1
    with Session(FuzzAdapter("fuzz"), None, server, target) as session:
        with raises(SessionError, match="Test case is missing landing page"):
            session.run([], 10)


def test_session_05(mocker, tmp_path):
    """test Target not requesting landing page"""
    Status.PATH = str(tmp_path)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    server.serve_path.return_value = (SERVED_TIMEOUT, [])
    target = mocker.Mock(spec=Target, launch_timeout=30, prefs=None)
    target.monitor.launches = 1
    with Session(SimpleAdapter(False), None, server, target) as session:
        with raises(SessionError, match="Please check Adapter and Target"):
            session.run([], 10)


@mark.parametrize(
    "harness, report_size",
    [
        # with harness, collect 1 test case
        (True, 1),
        # with harness, collect 2 test cases
        (True, 2),
        # without harness, collect 1 test case
        (False, 1),
    ],
)
def test_session_06(mocker, tmp_path, harness, report_size):
    """test Session - handle Target delayed failures"""
    Status.PATH = str(tmp_path)
    reporter = mocker.Mock(spec=Reporter)
    report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target, launch_timeout=30, prefs=None)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_NONE = Target.RESULT_NONE
    target.monitor.launches = 1
    type(target).closed = mocker.PropertyMock(side_effect=(True, False))
    target.detect_failure.side_effect = (Target.RESULT_NONE, Target.RESULT_FAILURE)
    target.log_size.return_value = 1
    target.create_report.return_value = report
    with Session(
        SimpleAdapter(harness),
        reporter,
        server,
        target,
        relaunch=2,
        report_size=report_size,
    ) as session:
        server.serve_path.side_effect = (
            (SERVED_ALL, [session.iomanager.page_name()]),
            (SERVED_NONE, []),
        )
        session.run([], 10, iteration_limit=2)
        assert reporter.submit.call_count == 1
        assert len(reporter.submit.call_args[0][0]) == 1
        assert reporter.submit.call_args[0][1].major == "major123"


@mark.parametrize(
    "srv_results, target_result, ignored, results",
    [
        # delayed startup crash
        (SERVED_NONE, Target.RESULT_FAILURE, 0, 1),
        # startup hang/unresponsive
        (SERVED_TIMEOUT, Target.RESULT_NONE, 1, 0),
    ],
)
def test_session_07(mocker, tmp_path, srv_results, target_result, ignored, results):
    """test Session.run() - initial test case was not served"""
    Status.PATH = str(tmp_path)
    report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    reporter = mocker.Mock(spec=Reporter)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target, closed=True, launch_timeout=30, prefs=None)
    target.RESULT_FAILURE = Target.RESULT_FAILURE
    target.RESULT_NONE = Target.RESULT_NONE
    target.monitor.launches = 1
    target.detect_failure.side_effect = (target_result,)
    target.create_report.return_value = report
    with Session(SimpleAdapter(False), reporter, server, target) as session:
        server.serve_path.return_value = (srv_results, [])
        with raises(SessionError, match="Please check Adapter and Target"):
            session.run([], 10, iteration_limit=2)
        assert session.status.iteration == 1
        assert session.status.results == results
        assert session.status.ignored == ignored
        assert reporter.submit.call_count == results
        assert target.detect_failure.call_count == results
        assert target.handle_hang.call_count == ignored


def test_session_08(tmp_path, mocker):
    """test Session.run() ignoring failures"""
    Status.PATH = str(tmp_path)
    result = RunResult([], 0.1, status=RunResult.IGNORED)
    result.attempted = True
    runner = mocker.patch("grizzly.session.Runner", autospec=True)
    runner.return_value.run.return_value = result
    mocker.patch("grizzly.session.TestFile", autospec=True)
    adapter = mocker.Mock(spec=Adapter, remaining=None)
    adapter.IGNORE_UNSERVED = False
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target, prefs=None)
    target.monitor.launches = 1
    with Session(adapter, None, server, target) as session:
        session.run([], 10, iteration_limit=1)
        assert runner.return_value.run.call_count == 1
        assert adapter.on_served.call_count == 1
        assert adapter.on_timeout.call_count == 0
        assert target.create_report.call_count == 0
        assert session.status.iteration == 1
        assert session.status.results == 0
        assert session.status.ignored == 1


def test_session_09(tmp_path, mocker):
    """test Session.run() handle TargetLaunchError"""
    Status.PATH = str(tmp_path)
    report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    runner = mocker.patch("grizzly.session.Runner", autospec=True)
    runner.return_value.launch.side_effect = TargetLaunchError("test", report)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    adapter = mocker.Mock(spec=Adapter, remaining=None)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target)
    target.monitor.launches = 1
    with Session(adapter, mocker.Mock(spec=Reporter), server, target) as session:
        with raises(TargetLaunchError, match="test"):
            session.run([], 10, iteration_limit=2)
        assert session.status.iteration == 1
        assert session.status.results == 1
        assert session.status.ignored == 0


def test_session_10(tmp_path, mocker):
    """test Session.run() report hang"""
    Status.PATH = str(tmp_path)
    result = RunResult([], 60.0, status=RunResult.FAILED, timeout=True)
    result.attempted = True
    runner = mocker.patch("grizzly.session.Runner", autospec=True)
    runner.return_value.run.return_value = result
    mocker.patch("grizzly.session.TestFile", autospec=True)
    adapter = mocker.Mock(spec=Adapter, remaining=None)
    report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    reporter = mocker.Mock(spec=Reporter)
    server = mocker.Mock(spec=Sapphire, port=0x1337)
    target = mocker.Mock(spec=Target, prefs=None)
    target.monitor.launches = 1
    target.create_report.return_value = report
    with Session(adapter, reporter, server, target) as session:
        session.run([], 10, iteration_limit=1)
        assert runner.return_value.run.call_count == 1
        assert adapter.on_served.call_count == 0
        assert adapter.on_timeout.call_count == 1
        assert target.create_report.call_count == 1
        assert reporter.submit.call_count == 1
        assert session.status.iteration == 1
        assert session.status.results == 1
        assert session.status.ignored == 0


def test_log_output_limiter_01(mocker):
    """test LogOutputLimiter.ready() not ready"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.return_value = 1.0
    lol = LogOutputLimiter(delay=10, delta_multiplier=2)
    assert lol._delay == 10
    assert lol._iterations == 1
    assert lol._launches == 1
    assert lol._multiplier == 2
    assert lol._time == 1.0
    assert not lol._verbose
    fake_time.return_value = 1.1
    assert not lol.ready(0, 0)
    assert lol._iterations == 1
    assert lol._launches == 1
    assert lol._time == 1.0
    lol._verbose = True
    assert lol.ready(0, 0)


def test_log_output_limiter_02(mocker):
    """test LogOutputLimiter.ready() due to iterations"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.return_value = 1.0
    lol = LogOutputLimiter(delay=10, delta_multiplier=2)
    fake_time.return_value = 1.1
    lol._launches = 2
    assert lol.ready(1, 1)
    assert lol._iterations == 2
    assert lol._launches == 2
    assert lol._time == 1.1


def test_log_output_limiter_03(mocker):
    """test LogOutputLimiter.ready() due to launches"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.return_value = 1.0
    lol = LogOutputLimiter(delay=10, delta_multiplier=2)
    lol._iterations = 4
    assert lol.ready(3, 1)
    assert lol._launches == 2
    assert lol._iterations == 4
    assert lol._time == 1.0


def test_log_output_limiter_04(mocker):
    """test LogOutputLimiter.ready() due to time"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.return_value = 1.0
    lol = LogOutputLimiter(delay=1, delta_multiplier=2)
    lol._iterations = 4
    fake_time.return_value = 2.0
    assert lol.ready(3, 0)
    assert lol._iterations == 4
    assert lol._launches == 1
    assert lol._time == 2.0
