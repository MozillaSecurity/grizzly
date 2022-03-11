# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.Session
"""
from itertools import chain, count, repeat

from pytest import mark, raises

from sapphire import Sapphire, Served

from .adapter import Adapter
from .common.reporter import Report, Reporter
from .common.runner import RunResult
from .session import LogOutputLimiter, Session, SessionError
from .target import AssetManager, Result, Target, TargetLaunchError

pytestmark = mark.usefixtures("patch_collector", "tmp_path_status_db")


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
        testcase.add_from_bytes(b"test", testcase.landing_page)
        if self.remaining is not None:
            assert self.remaining > 0
            self.remaining -= 1


@mark.parametrize(
    "harness, profiling, coverage, relaunch, iters, runtime",
    [
        # with harness, single iteration
        (True, False, False, 1, 1, 0),
        # with harness, 10 iterations relaunch every iteration
        (True, False, False, 1, 10, 0),
        # with harness, 10 iterations relaunch every other iteration
        (True, False, False, 2, 10, 0),
        # with harness, 10 iterations no relaunches
        (True, False, False, 10, 10, 0),
        # no harness, single iteration
        (False, False, False, 1, 1, 0),
        # no harness, 10 iterations
        (False, False, False, 1, 10, 0),
        # test enable profiling
        (True, True, False, 10, 10, 0),
        # test Session.dump_coverage()
        (True, True, True, 2, 2, 0),
        # with harness, runtime limit
        (True, False, False, 1, 0, 1),
    ],
)
def test_session_01(mocker, harness, profiling, coverage, relaunch, iters, runtime):
    """test Session with typical fuzzer Adapter"""
    mocker.patch("grizzly.common.status.time", side_effect=count(start=1.0, step=1.0))
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
    target.log_size.return_value = 1000
    target.monitor.launches = 1
    # avoid shutdown delay
    target.monitor.is_healthy.return_value = False
    # we can only test iter limit OR runtime limit not both
    assert bool(iters) != bool(runtime), "test is broken!"
    max_iters = iters or 1
    # calculate if the target is 'closed' based on relaunch
    type(target).closed = mocker.PropertyMock(
        side_effect=((x % relaunch == 0) for x in range(max_iters))
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
            Served.ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run(
            [],
            10,
            input_path="file.bin",
            iteration_limit=iters,
            runtime_limit=runtime,
        )
        assert session.status.iteration == max_iters
        assert session.status.test_name == "file.bin"
        assert target.close.call_count == max_iters / relaunch
        assert target.check_result.call_count == max_iters
        assert target.handle_hang.call_count == 0
        if profiling:
            assert any(session.status.profile_entries()) == profiling
        else:
            assert not any(session.status.profile_entries())
        if coverage:
            assert target.dump_coverage.call_count == max_iters
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
def test_session_02(mocker, harness, relaunch, remaining):
    """test Session with playback Adapter"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
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
            Served.ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run([], 10)
        assert session.status.iteration == remaining
        assert session.status.test_name is None
        assert target.check_result.call_count == remaining
        assert target.handle_hang.call_count == 0


@mark.parametrize(
    "harness, report_size, relaunch, iters, has_sig",
    [
        # with harness, collect 1 test case
        (True, 1, 1, 1, True),
        # with harness, collect 2 test cases
        (True, 2, 2, 2, True),
        # with harness, collect 2 test cases,
        (True, 2, 3, 3, True),
        # with harness, collect 3 test cases, relaunch 1
        (True, 3, 1, 3, True),
        # without harness, collect 1 test case
        (False, 1, 1, 1, True),
        # without harness, collect 1 test case, 3 iterations
        (False, 1, 1, 3, True),
        # with harness, collect 1 test case, failed to generate FM signature
        (True, 1, 1, 1, False),
    ],
)
def test_session_03(mocker, tmp_path, harness, report_size, relaunch, iters, has_sig):
    """test Session - detecting failure"""
    adapter = SimpleAdapter(harness)
    reporter = mocker.Mock(spec_set=Reporter)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
    target.monitor.launches = 1
    # avoid shutdown delay
    target.monitor.is_healthy.return_value = False
    # calculate if the target is 'closed' based on relaunch
    type(target).closed = mocker.PropertyMock(
        side_effect=((x % relaunch == 0) for x in range(iters))
    )
    # failure is on final iteration
    target.check_result.side_effect = chain(
        repeat(Result.NONE, iters - 1), (Result.FOUND,)
    )
    target.log_size.return_value = 1
    # create Report
    log_path = tmp_path / "logs"
    log_path.mkdir()
    (log_path / "log_stderr.txt").write_bytes(b"STDERR log")
    (log_path / "log_stdout.txt").write_bytes(b"STDOUT log")
    if has_sig:
        with (log_path / "log_asan_blah.txt").open("w") as log_fp:
            log_fp.write("==1==ERROR: AddressSanitizer: ")
            log_fp.write("SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19\n")
    report = Report(str(log_path), "bin")
    target.create_report.return_value = report
    with Session(
        adapter, reporter, server, target, relaunch=relaunch, report_size=report_size
    ) as session:
        server.serve_path = lambda *a, **kv: (
            Served.ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run([], 10, input_path="file.bin", iteration_limit=iters)
        assert reporter.submit.call_count == 1
        assert len(reporter.submit.call_args[0][0]) == min(report_size, relaunch)


def test_session_04(mocker):
    """test Adapter creating invalid test case"""

    class FuzzAdapter(Adapter):
        def generate(self, _testcase, _server_map):
            pass

    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.NONE, [])
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
    target.monitor.launches = 1
    with Session(FuzzAdapter("fuzz"), None, server, target) as session:
        with raises(SessionError, match="Test case is missing landing page"):
            session.run([], 10)


def test_session_05(mocker):
    """test Target not requesting landing page"""
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    server.serve_path.return_value = (Served.TIMEOUT, [])
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
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
def test_session_06(mocker, harness, report_size):
    """test Session - handle Target delayed failures"""
    reporter = mocker.Mock(spec_set=Reporter)
    report = mocker.Mock(
        spec_set=Report, major="major123", minor="minor456", crash_hash="1234"
    )
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
    target.monitor.launches = 1
    type(target).closed = mocker.PropertyMock(side_effect=(True, False))
    target.check_result.side_effect = (Result.NONE, Result.FOUND)
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
            (Served.ALL, [session.iomanager.page_name()]),
            (Served.NONE, []),
        )
        session.run([], 10, iteration_limit=2)
        assert reporter.submit.call_count == 1
        assert len(reporter.submit.call_args[0][0]) == 1
        assert reporter.submit.call_args[0][1].major == "major123"


@mark.parametrize(
    "srv_results, target_result, ignored, results",
    [
        # delayed startup crash
        (Served.NONE, Result.FOUND, 0, 1),
        # startup hang/unresponsive
        (Served.TIMEOUT, Result.NONE, 1, 0),
    ],
)
def test_session_07(mocker, srv_results, target_result, ignored, results):
    """test Session.run() - initial test case was not served"""
    report = mocker.Mock(
        spec_set=Report, major="major123", minor="minor456", crash_hash="123"
    )
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    reporter = mocker.Mock(spec_set=Reporter)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        closed=True,
        environ=dict(),
        launch_timeout=30,
    )
    target.monitor.launches = 1
    target.check_result.side_effect = (target_result,)
    target.create_report.return_value = report
    with Session(SimpleAdapter(False), reporter, server, target) as session:
        server.serve_path.return_value = (srv_results, [])
        with raises(SessionError, match="Please check Adapter and Target"):
            session.run([], 10, iteration_limit=2)
        assert session.status.iteration == 1
        assert session.status.results.total == results
        assert session.status.ignored == ignored
        assert reporter.submit.call_count == results
        assert target.check_result.call_count == results
        assert target.handle_hang.call_count == ignored


def test_session_08(mocker):
    """test Session.run() ignoring failures"""
    result = RunResult([], 0.1, status=Result.IGNORED)
    result.attempted = True
    runner = mocker.patch("grizzly.session.Runner", autospec=True)
    runner.return_value.run.return_value = result
    runner.return_value.startup_failure = False
    adapter = mocker.Mock(spec_set=Adapter, remaining=None)
    adapter.IGNORE_UNSERVED = False
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target, assets=mocker.Mock(spec_set=AssetManager), environ=dict()
    )
    target.monitor.launches = 1
    with Session(adapter, None, server, target) as session:
        session.run([], 10, iteration_limit=1)
        assert runner.return_value.run.call_count == 1
        assert adapter.on_served.call_count == 1
        assert adapter.on_timeout.call_count == 0
        assert target.create_report.call_count == 0
        assert session.status.iteration == 1
        assert session.status.results.total == 0
        assert session.status.ignored == 1


def test_session_09(mocker):
    """test Session.run() handle TargetLaunchError"""
    report = mocker.Mock(
        spec_set=Report, major="major123", minor="minor456", crash_hash="123"
    )
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    runner = mocker.patch("grizzly.session.Runner", autospec=True)
    runner.return_value.launch.side_effect = TargetLaunchError("test", report)
    runner.return_value.startup_failure = True
    adapter = mocker.Mock(spec_set=Adapter, remaining=None)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(spec_set=Target)
    target.monitor.launches = 1
    with Session(adapter, mocker.Mock(spec_set=Reporter), server, target) as session:
        with raises(TargetLaunchError, match="test"):
            session.run([], 10, iteration_limit=2)
        assert session.status.iteration == 1
        assert session.status.results.total == 1
        assert session.status.ignored == 0


def test_session_10(mocker):
    """test Session.run() report hang"""
    result = RunResult([], 60.0, status=Result.FOUND, timeout=True)
    result.attempted = True
    runner = mocker.patch("grizzly.session.Runner", autospec=True)
    runner.return_value.run.return_value = result
    runner.return_value.startup_failure = False
    adapter = mocker.Mock(spec_set=Adapter, remaining=None)
    report = mocker.Mock(spec_set=Report, major="major123", minor="minor456")
    reporter = mocker.Mock(spec_set=Reporter)
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
    )
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
        assert session.status.results.total == 1
        assert session.status.ignored == 0


@mark.parametrize(
    "harness, report_size, relaunch, iters, report_limit",
    [
        # no limit, always submit reports
        (True, 1, 1, 10, 0),
        # limit, only submit initial reports
        (True, 1, 1, 10, 5),
    ],
)
def test_session_11(mocker, harness, report_size, relaunch, iters, report_limit):
    """test Session - limit report submission"""
    adapter = SimpleAdapter(harness)
    reporter = mocker.Mock(spec_set=Reporter)
    report = mocker.Mock(spec_set=Report, major="abc", minor="def", crash_hash="123")
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
    target.monitor.launches = 1
    # avoid shutdown delay
    target.monitor.is_healthy.return_value = False
    type(target).closed = mocker.PropertyMock(return_value=True)
    target.check_result.return_value = Result.FOUND
    target.log_size.return_value = 1
    target.create_report.return_value = report
    with Session(
        adapter, reporter, server, target, report_limit=report_limit, relaunch=1
    ) as session:
        server.serve_path = lambda *a, **kv: (
            Served.ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run([], 10, input_path="file.bin", iteration_limit=iters)
        if report_limit > 0:
            assert reporter.submit.call_count == report_limit
        else:
            assert reporter.submit.call_count == iters
        assert len(reporter.submit.call_args[0][0]) == min(report_size, relaunch)
        assert reporter.submit.call_args[0][1].major == "abc"


@mark.parametrize(
    "harness, iters, result_limit, results",
    [
        # hit result limit
        (True, 0, 1, 1),
        # don't hit result limit (one result)
        (True, 10, 5, 1),
        # don't hit result limit (no results)
        (True, 2, 1, 0),
    ],
)
def test_session_12(mocker, harness, iters, result_limit, results):
    """test Session - limit results"""
    adapter = SimpleAdapter(harness)
    reporter = mocker.Mock(spec_set=Reporter)
    report = mocker.Mock(spec_set=Report, major="abc", minor="def", crash_hash="123")
    report.crash_info.createShortSignature.return_value = "[@ sig]"
    server = mocker.Mock(spec_set=Sapphire, port=0x1337)
    target = mocker.Mock(
        spec_set=Target,
        assets=mocker.Mock(spec_set=AssetManager),
        environ=dict(),
        launch_timeout=30,
    )
    target.monitor.launches = 1
    # avoid shutdown delay
    target.monitor.is_healthy.return_value = False
    type(target).closed = mocker.PropertyMock(return_value=True)
    target.check_result.side_effect = chain(
        repeat(Result.FOUND, results), repeat(Result.NONE, iters - results)
    )
    target.log_size.return_value = 1
    target.create_report.return_value = report
    with Session(adapter, reporter, server, target, relaunch=1) as session:
        server.serve_path = lambda *a, **kv: (
            Served.ALL,
            [session.iomanager.page_name(offset=-1)],
        )
        session.run(
            [], 10, input_path="a.bin", iteration_limit=iters, result_limit=result_limit
        )
    if results >= result_limit > iters:
        # limited by result_limit
        assert session.status.iteration == result_limit
    else:
        assert session.status.iteration == iters


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
