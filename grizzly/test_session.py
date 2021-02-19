# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.Session
"""
from collections import deque

from pytest import raises

from sapphire import Sapphire, ServerMap, SERVED_ALL, SERVED_NONE, SERVED_TIMEOUT
from .common import Adapter, IOManager, Report, Reporter, RunResult, Status, TestCase
from .session import LogOutputLimiter, Session, SessionError
from .target import Target, TargetLaunchError


class NullReporter(Reporter):
    def __init__(self):
        self.submit_calls = 0

    def _post_submit(self):
        pass

    def _pre_submit(self, report):
        pass

    def _submit_report(self, report, test_cases):
        assert isinstance(report, Report)
        for test in test_cases:
            assert isinstance(test, TestCase)
        self.submit_calls += 1

def test_session_01(tmp_path, mocker):
    """test Session with playback Adapter"""
    class PlaybackAdapter(Adapter):
        NAME = "playback"
        def setup(self, input_path, server_map):
            self.remaining = 5
        def generate(self, testcase, server_map):
            assert testcase.adapter_name == self.NAME
            testcase.input_fname = "file.bin"
            testcase.add_from_data("test", testcase.landing_page)
            self.remaining -= 1
    Status.PATH = str(tmp_path)
    adapter = PlaybackAdapter()
    adapter.setup(None, None)
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    fake_target = mocker.Mock(spec=Target, launch_timeout=30, prefs=str(prefs))
    # set target.log_size to test warning code path
    fake_target.log_size.return_value = Session.TARGET_LOG_SIZE_WARN + 1
    with IOManager() as iomgr:
        fake_serv.serve_path = lambda *a, **kv: (SERVED_ALL, [iomgr.page_name(offset=-1)])
        with Session(adapter, iomgr, None, fake_serv, fake_target, relaunch=10) as session:
            session.run([], 10)
            assert session.status.iteration == 5
            assert session.status.test_name == "file.bin"

def test_session_02(tmp_path, mocker):
    """test Session with basic fuzzer Adapter (w/harness)"""
    class FuzzAdapter(Adapter):
        NAME = "fuzz"
        def setup(self, input_path, server_map):
            self.enable_harness()
        def generate(self, testcase, server_map):
            assert testcase.adapter_name == self.NAME
            testcase.add_from_data("test", testcase.landing_page)
    Status.PATH = str(tmp_path)
    adapter = FuzzAdapter()
    adapter.setup(None, None)
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    fake_target = mocker.Mock(spec=Target, launch_timeout=30, prefs=str(prefs))
    fake_target.log_size.return_value = 1000
    fake_target.monitor.launches = 1
    with IOManager() as iomgr:
        iomgr.harness = adapter.get_harness()
        fake_serv.serve_path = lambda *a, **kv: (SERVED_ALL, [iomgr.page_name(offset=-1)])
        # enable profiling for test coverage
        with Session(adapter, iomgr, None, fake_serv, fake_target, enable_profiling=True, relaunch=10) as session:
            session.run([], 10, iteration_limit=10)
            assert session.status.iteration == 10
            assert session.status.test_name is None

def test_session_03(tmp_path, mocker):
    """test Session.dump_coverage()"""
    class FuzzAdapter(Adapter):
        NAME = "fuzz"
        def setup(self, input_path, server_map):
            self.enable_harness()
        def generate(self, testcase, server_map):
            assert testcase.adapter_name == self.NAME
            testcase.add_from_data("test", testcase.landing_page)
    Status.PATH = str(tmp_path)
    mocker.patch("grizzly.common.runner.sleep", autospec=True)
    adapter = FuzzAdapter()
    adapter.setup(None, None)
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    fake_target = mocker.Mock(spec=Target, prefs=None)
    fake_target.log_size.return_value = 1000
    fake_target.monitor.launches = 1
    # target.launch() call will be skipped
    fake_target.closed = False
    with IOManager() as iomgr:
        fake_serv.serve_path = lambda *a, **kv: (SERVED_ALL, [iomgr.page_name(offset=-1)])
        with Session(adapter, iomgr, None, fake_serv, fake_target, coverage=True, relaunch=2) as session:
            session.run([], 10, iteration_limit=2)
            assert session.status.iteration == 2
    assert fake_target.dump_coverage.call_count == 2

def test_session_04(tmp_path, mocker):
    """test Target not requesting landing page"""
    class FuzzAdapter(Adapter):
        NAME = "fuzz"
        def setup(self, input_path, server_map):
            pass
        def generate(self, testcase, server_map):
            assert testcase.adapter_name == self.NAME
    Status.PATH = str(tmp_path)
    adapter = FuzzAdapter()
    adapter.setup(None, None)
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    fake_target = mocker.Mock(spec=Target, launch_timeout=30, prefs=None)
    fake_target.monitor.launches = 1
    with IOManager() as iomgr:
        fake_serv.serve_path.return_value = (SERVED_NONE, [])
        with Session(adapter, iomgr, None, fake_serv, fake_target, relaunch=10) as session:
            with raises(SessionError, match="Test case is missing landing page"):
                session.run([], 10, iteration_limit=10)

def test_session_05(tmp_path, mocker):
    """test basic Session functions"""
    Status.PATH = str(tmp_path)
    fake_adapter = mocker.Mock(spec=Adapter, remaining=None)
    fake_adapter.IGNORE_UNSERVED = True
    fake_testcase = mocker.Mock(spec_set=TestCase, landing_page="page.htm", optional=[], time_limit=10)
    fake_iomgr = mocker.Mock(spec=IOManager, harness=None, server_map=ServerMap())
    fake_iomgr.create_testcase.return_value = fake_testcase
    fake_iomgr.tests = mocker.Mock(spec=deque)
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    fake_serv.serve_path.return_value = (SERVED_TIMEOUT, [fake_testcase.landing_page])
    fake_target = mocker.Mock(spec=Target, launch_timeout=30, prefs=None)
    fake_target.monitor.launches = 1
    with Session(fake_adapter, fake_iomgr, None, fake_serv, fake_target) as session:
        session.run([], 10, iteration_limit=1)
    assert fake_adapter.setup.call_count == 0
    assert fake_adapter.pre_launch.call_count == 1
    assert fake_adapter.generate.call_count == 1
    assert fake_adapter.on_served.call_count == 0
    assert fake_adapter.on_timeout.call_count == 1
    assert fake_iomgr.create_testcase.call_count == 1
    assert fake_iomgr.tests.pop.call_count == 0
    assert fake_testcase.purge_optional.call_count == 1
    assert fake_serv.serve_path.call_count == 1
    assert fake_target.launch.call_count == 1
    assert fake_target.detect_failure.call_count == 0
    assert fake_target.handle_hang.call_count == 1
    assert fake_target.monitor.is_healthy.call_count == 0

def test_session_06(tmp_path, mocker):
    """test Session.generate_testcase()"""
    Status.PATH = str(tmp_path)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.NAME = "fake_adapter"
    fake_iomgr = mocker.Mock(spec=IOManager, server_map=ServerMap())
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec_set=TestCase, time_limit=10)
    fake_target = mocker.Mock(spec=Target, prefs="fake")
    with Session(fake_adapter, fake_iomgr, None, None, fake_target) as session:
        assert fake_adapter.generate.call_count == 0
        testcase = session.generate_testcase(10)
        assert fake_iomgr.create_testcase.call_count == 1
        fake_iomgr.create_testcase.assert_called_with("fake_adapter", 10)
        assert fake_adapter.generate.call_count == 1
        fake_adapter.generate.assert_called_with(testcase, fake_iomgr.server_map)
        assert testcase.add_meta.call_count == 1

def test_session_07(tmp_path, mocker):
    """test Session.run() - test case was not served"""
    Status.PATH = str(tmp_path)
    fake_runner = mocker.patch("grizzly.session.Runner", autospec=True)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter, remaining=None)
    fake_iomgr = mocker.Mock(spec=IOManager, harness=None, server_map=ServerMap())
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec=TestCase)
    fake_iomgr.tests = mocker.Mock(spec=deque)
    fake_report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    fake_report.crash_info.createShortSignature.return_value = "[@ sig]"
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    fake_target = mocker.Mock(spec=Target, prefs="prefs.js")
    fake_target.monitor.launches = 1
    fake_target.create_report.return_value = fake_report
    fake_reporter = mocker.Mock(spec=Reporter)
    # between iterations
    run_result = RunResult([], 1, status=RunResult.FAILED)
    run_result.attempted = False
    run_result.initial = False
    fake_runner.return_value.run.return_value = run_result
    with Session(fake_adapter, fake_iomgr, fake_reporter, fake_serv, fake_target) as session:
        session.run([], 10, iteration_limit=1)
        assert fake_runner.return_value.run.call_count == 1
        assert fake_adapter.on_served.call_count == 1
        assert fake_adapter.on_timeout.call_count == 0
        assert fake_iomgr.purge_tests.call_count == 1
        assert fake_runner.return_value.launch.call_count == 1
        assert session.status.iteration == 1
        assert session.status.results == 1
        assert session.status.ignored == 0
        assert fake_reporter.submit.call_count == 1
        assert fake_iomgr.tests.pop.call_count == 1
    fake_reporter.reset_mock()
    fake_runner.reset_mock()
    # delayed startup crash
    run_result = RunResult([], 1, status=RunResult.FAILED)
    run_result.attempted = False
    run_result.initial = True
    fake_runner.return_value.run.return_value = run_result
    with Session(fake_adapter, fake_iomgr, fake_reporter, fake_serv, fake_target) as session:
        with raises(SessionError, match="Please check Adapter and Target"):
            session.run([], 10, iteration_limit=1)
        assert fake_runner.return_value.run.call_count == 1
        assert fake_runner.return_value.launch.call_count == 1
        assert session.status.iteration == 1
        assert session.status.results == 1
        assert session.status.ignored == 0
        assert fake_reporter.submit.call_count == 1
    fake_reporter.reset_mock()
    fake_runner.reset_mock()
    # startup hang/unresponsive
    run_result = RunResult([], 1)
    run_result.attempted = False
    run_result.initial = True
    fake_runner.return_value.run.return_value = run_result
    with Session(fake_adapter, fake_iomgr, fake_reporter, fake_serv, fake_target) as session:
        with raises(SessionError, match="Please check Adapter and Target"):
            session.run([], 10, iteration_limit=1)
        assert fake_runner.return_value.run.call_count == 1
        assert fake_runner.return_value.launch.call_count == 1
        assert session.status.iteration == 1
        assert session.status.results == 0
        assert session.status.ignored == 0
        assert fake_reporter.submit.call_count == 0

def test_session_08(tmp_path, mocker):
    """test Session.run() ignoring failures"""
    Status.PATH = str(tmp_path)
    result = RunResult([], 0.1, status=RunResult.IGNORED)
    result.attempted = True
    fake_runner = mocker.patch("grizzly.session.Runner", autospec=True)
    fake_runner.return_value.run.return_value = result
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter, remaining=None)
    fake_adapter.IGNORE_UNSERVED = False
    fake_iomgr = mocker.Mock(spec=IOManager, harness=None, server_map=ServerMap())
    fake_test = mocker.Mock(spec=TestCase)
    fake_iomgr.create_testcase.return_value = fake_test
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    fake_target = mocker.Mock(spec=Target, prefs="prefs.js")
    fake_target.monitor.launches = 1
    with Session(fake_adapter, fake_iomgr, None, fake_serv, fake_target) as session:
        session.run([], 10, iteration_limit=1)
        assert fake_runner.return_value.run.call_count == 1
        assert fake_adapter.on_served.call_count == 1
        assert fake_adapter.on_timeout.call_count == 0
        assert fake_iomgr.purge_tests.call_count == 1
        assert fake_test.purge_optional.call_count == 0
        assert fake_runner.return_value.launch.call_count == fake_iomgr.purge_tests.call_count
        assert fake_target.create_report.call_count == 0
        assert session.status.iteration == 1
        assert session.status.results == 0
        assert session.status.ignored == 1

def test_session_09(tmp_path, mocker):
    """test Session.run() handle TargetLaunchError"""
    Status.PATH = str(tmp_path)
    fake_report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    fake_report.crash_info.createShortSignature.return_value = "[@ sig]"
    fake_runner = mocker.patch("grizzly.session.Runner", autospec=True)
    fake_runner.return_value.launch.side_effect = TargetLaunchError("test", fake_report)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter, remaining=None)
    fake_iomgr = mocker.Mock(spec=IOManager, harness=None, server_map=ServerMap())
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    fake_target = mocker.Mock(spec=Target)
    fake_target.monitor.launches = 1
    with Session(fake_adapter, fake_iomgr, mocker.Mock(), fake_serv, fake_target) as session:
        with raises(TargetLaunchError, match="test"):
            session.run([], 10, iteration_limit=1)
        assert session.status.iteration == 1
        assert session.status.results == 1
        assert session.status.ignored == 0

def test_session_10(tmp_path, mocker):
    """test Session.run() report hang"""
    Status.PATH = str(tmp_path)
    result = RunResult([], 60.0, status=RunResult.FAILED, timeout=True)
    result.attempted = True
    fake_runner = mocker.patch("grizzly.session.Runner", autospec=True)
    fake_runner.return_value.run.return_value = result
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter, remaining=None)
    fake_iomgr = mocker.Mock(
        spec=IOManager,
        harness=None,
        server_map=ServerMap(),
        tests=mocker.Mock(spec=deque))
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec=TestCase)
    fake_report = mocker.Mock(spec=Report, major="major123", minor="minor456")
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_serv = mocker.Mock(spec=Sapphire, port=0x1337)
    fake_target = mocker.Mock(spec=Target, prefs="prefs.js")
    fake_target.monitor.launches = 1
    fake_target.create_report.return_value = fake_report
    with Session(fake_adapter, fake_iomgr, fake_reporter, fake_serv, fake_target) as session:
        session.run([], 10, iteration_limit=1)
        assert fake_runner.return_value.run.call_count == 1
        assert fake_adapter.on_served.call_count == 0
        assert fake_adapter.on_timeout.call_count == 1
        assert fake_iomgr.purge_tests.call_count == 1
        assert fake_target.create_report.call_count == 1
        assert fake_reporter.submit.call_count == 1
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
