# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
unit tests for grizzly.Session
"""
from collections import deque

import pytest

from sapphire import Sapphire, ServerMap, SERVED_ALL, SERVED_REQUEST, SERVED_TIMEOUT
from .common import Adapter, InputFile, IOManager, Reporter, Status, TestCase, TestFile
from .session import LogOutputLimiter, Session
from .target import Target, TargetLaunchError


def test_session_01(tmp_path, mocker):
    """test basic Session functions"""
    Status.PATH = str(tmp_path)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.ROTATION_PERIOD = 0
    fake_adapter.TEST_DURATION = 10
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.server_map.includes = []
    fake_iomgr.server_map.redirects = []
    fake_iomgr.server_map.dynamic_responses = []
    fake_iomgr.active_input = mocker.Mock(spec=InputFile)
    fake_iomgr.active_input.file_name = "input.txt"
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec=TestCase)
    fake_iomgr.harness = mocker.Mock(spec=TestFile)
    fake_iomgr.input_files = []
    fake_iomgr.landing_page.return_value = "HOMEPAGE.HTM"
    fake_iomgr.tests = deque([mocker.Mock(spec=TestCase)])
    fake_iomgr.working_path = str(tmp_path)
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_serv = mocker.Mock(spec=Sapphire)
    fake_serv.serve_testcase.return_value = (SERVED_TIMEOUT, [])
    fake_serv.port = 0x1337
    fake_target = mocker.Mock(spec=Target)
    fake_target.log_size.return_value = 1000
    fake_target.rl_reset = 10
    fake_target.prefs = None

    session = Session(fake_adapter, True, fake_iomgr, fake_reporter, fake_serv, fake_target)
    session.TARGET_LOG_SIZE_WARN = 100
    session.run([])
    session.close()

    assert fake_iomgr.create_testcase.call_count == 1
    assert fake_serv.serve_testcase.call_count == 1
    assert fake_target.detect_failure.call_count == 1

def test_session_02(tmp_path, mocker):
    """test Session.generate_testcase()"""
    Status.PATH = str(tmp_path)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.NAME = "fake_adapter"
    fake_adapter.ROTATION_PERIOD = 123
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.active_input = mocker.Mock(spec=InputFile)
    fake_iomgr.active_input.file_name = "infile"
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec=TestCase)
    fake_target = mocker.Mock(spec=Target)
    fake_target.prefs = "fake_prefs.js"

    session = Session(fake_adapter, False, fake_iomgr, None, None, fake_target)
    assert fake_adapter.generate.call_count == 0
    testcase = session.generate_testcase()
    assert fake_iomgr.create_testcase.call_count == 1
    fake_iomgr.create_testcase.assert_called_with("fake_adapter", rotation_period=123)
    assert fake_adapter.generate.call_count == 1
    fake_adapter.generate.assert_called_with(testcase, fake_iomgr.active_input, fake_iomgr.server_map)
    assert testcase.add_meta.call_count == 1

def test_session_03(tmp_path, mocker):
    """test Session.run()"""
    Status.PATH = str(tmp_path)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.IGNORE_UNSERVED = True
    fake_adapter.ROTATION_PERIOD = 2
    fake_adapter.TEST_DURATION = 10
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.active_input = mocker.Mock(spec=InputFile)
    fake_iomgr.active_input.file_name = "input.txt"
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec=TestCase)
    fake_iomgr.harness = None
    fake_iomgr.input_files = []
    fake_iomgr.landing_page.return_value = "HOMEPAGE.HTM"
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.tests = mocker.Mock(spec=deque)
    fake_iomgr.tests.pop.return_value = mocker.Mock(spec=TestCase)
    fake_iomgr.working_path = str(tmp_path)
    fake_serv = mocker.Mock(spec=Sapphire)
    fake_serv.port = 0x1337
    fake_serv.serve_testcase.side_effect = (
        (SERVED_ALL, ["/fake/file"]),
        (SERVED_TIMEOUT, []),
        (SERVED_ALL, ["/fake/file"]),
        (SERVED_TIMEOUT, []),
        (SERVED_ALL, ["/fake/file"]),
        (SERVED_TIMEOUT, []),
        (SERVED_ALL, ["/fake/file"]),
        (SERVED_TIMEOUT, []),
        (SERVED_ALL, ["/fake/file"]),
        (SERVED_TIMEOUT, []))
    fake_target = mocker.Mock(spec=Target)
    fake_target.log_size.return_value = 1000
    fake_target.monitor.launches = 1
    fake_target.prefs = "prefs.js"

    session = Session(fake_adapter, False, fake_iomgr, mocker.Mock(spec=Reporter), fake_serv, fake_target)
    assert fake_adapter.on_served.call_count == 0
    assert fake_adapter.on_timeout.call_count == 0
    assert fake_adapter.pre_launch.call_count == 0
    session.run([], iteration_limit=10)
    assert fake_adapter.on_served.call_count == 5
    assert fake_adapter.on_timeout.call_count == 5
    assert fake_adapter.pre_launch.call_count == 10
    assert fake_iomgr.purge_tests.call_count == 10
    assert fake_target.launch.call_count == fake_iomgr.purge_tests.call_count
    session.close()
    assert session.status.ignored == 0
    assert session.status.iteration == 10
    assert session.status.results == 0
    assert fake_iomgr.create_testcase.call_count == 10
    assert fake_target.detect_failure.call_count == 10
    assert fake_iomgr.create_testcase.return_value.purge_optional.call_count == 5
    assert fake_iomgr.tests.pop.call_count == 5

def test_session_04(tmp_path, mocker):
    """test Session.run() reporting failures"""
    Status.PATH = str(tmp_path)
    mocker.patch("grizzly.session.Report", autospec=True)
    fake_runner = mocker.patch("grizzly.session.Runner", autospec=True)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.IGNORE_UNSERVED = True
    fake_adapter.TEST_DURATION = 10
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.active_input = mocker.Mock(spec=InputFile)
    fake_iomgr.active_input.file_name = "input.txt"
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec=TestCase)
    fake_iomgr.harness = None
    fake_iomgr.input_files = []
    fake_iomgr.landing_page.return_value = "HOMEPAGE.HTM"
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.tests = mocker.Mock(spec=deque)
    fake_iomgr.working_path = str(tmp_path)
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_serv = mocker.Mock(spec=Sapphire)
    fake_serv.port = 0x1337
    fake_target = mocker.Mock(spec=Target)
    fake_target.log_size.return_value = 1000
    fake_target.monitor.launches = 1
    fake_target.prefs = "prefs.js"

    session = Session(fake_adapter, False, fake_iomgr, fake_reporter, fake_serv, fake_target)
    session.server.serve_testcase.return_value = SERVED_REQUEST
    fake_runner.return_value.result = fake_runner.return_value.FAILED
    fake_runner.return_value.served = ["/fake/file"]
    fake_runner.return_value.timeout = False
    session.run([], iteration_limit=1)
    assert fake_adapter.on_served.call_count == 1
    assert fake_adapter.on_timeout.call_count == 0
    assert fake_adapter.pre_launch.call_count == 1
    assert fake_iomgr.purge_tests.call_count == 1
    assert fake_runner.return_value.launch.call_count == fake_iomgr.purge_tests.call_count
    session.close()
    assert session.status.iteration == 1
    assert session.status.results == 1
    assert session.status.ignored == 0
    assert fake_reporter.submit.call_count == 1

def test_session_05(tmp_path, mocker):
    """test Session.run() ignoring failures"""
    Status.PATH = str(tmp_path)
    fake_runner = mocker.patch("grizzly.session.Runner", autospec=True)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.IGNORE_UNSERVED = True
    fake_adapter.TEST_DURATION = 10
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.active_input = mocker.Mock(spec=InputFile)
    fake_iomgr.active_input.file_name = "input.txt"
    fake_iomgr.create_testcase.return_value = mocker.Mock(spec=TestCase)
    fake_iomgr.harness = None
    fake_iomgr.input_files = []
    fake_iomgr.landing_page.return_value = "HOMEPAGE.HTM"
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.tests = mocker.Mock(spec=deque)
    fake_iomgr.tests.pop.return_value = mocker.Mock(spec=TestCase)
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_serv = mocker.Mock(spec=Sapphire)
    fake_serv.port = 0x1337
    fake_target = mocker.Mock(spec=Target)
    fake_target.log_size.return_value = 1000
    fake_target.monitor.launches = 1
    fake_target.prefs = "prefs.js"

    # ignored results should not be reported so raise AssertionError if report_result is called
    mocker.patch.object(Session, 'report_result', side_effect=AssertionError)
    session = Session(fake_adapter, False, fake_iomgr, fake_reporter, fake_serv, fake_target)
    session.server.serve_testcase.return_value = SERVED_REQUEST
    fake_runner.return_value.result = fake_runner.return_value.IGNORED
    fake_runner.return_value.served = ["/fake/file"]
    fake_runner.return_value.timeout = False
    session.run([], iteration_limit=1)
    assert fake_adapter.on_served.call_count == 1
    assert fake_adapter.on_timeout.call_count == 0
    assert fake_adapter.pre_launch.call_count == 1
    assert fake_iomgr.purge_tests.call_count == 1
    assert fake_runner.return_value.launch.call_count == fake_iomgr.purge_tests.call_count
    session.close()
    assert session.status.iteration == 1
    assert session.status.results == 0
    assert session.status.ignored == 1

def test_session_06(tmp_path, mocker):
    """test Session.run() handle TargetLaunchError"""
    Status.PATH = str(tmp_path)
    mocker.patch("grizzly.session.Report", autospec=True)
    fake_runner = mocker.patch("grizzly.session.Runner", autospec=True)
    fake_runner.return_value.launch.side_effect = TargetLaunchError
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.harness = None
    fake_iomgr.input_files = []
    fake_iomgr.landing_page.return_value = "x.html"
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.tests = mocker.Mock(spec=deque)
    fake_iomgr.working_path = str(tmp_path)
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_serv = mocker.Mock(spec=Sapphire)
    fake_serv.port = 0x1337
    fake_target = mocker.Mock(spec=Target)
    fake_target.log_size.return_value = 1000
    fake_target.monitor.launches = 1
    fake_target.prefs = "prefs.js"

    session = Session(fake_adapter, False, fake_iomgr, fake_reporter, fake_serv, fake_target)
    with pytest.raises(TargetLaunchError):
        session.run([], iteration_limit=1)
    session.close()
    assert session.status.iteration == 1
    assert session.status.results == 1
    assert session.status.ignored == 0
    assert fake_reporter.submit.call_count == 1

def test_session_07(tmp_path, mocker):
    """test Session.report_result()"""
    tmpd = tmp_path / "fake_temp_path"
    tmpd.mkdir()
    (tmpd / "log_stderr.txt").write_bytes(b"STDERR log\n")
    (tmpd / "log_stdout.txt").write_bytes(b"STDOUT log\n")
    with (tmpd / "log_asan_blah.txt").open("wb") as log_fp:
        log_fp.write(b"==1==ERROR: AddressSanitizer: ")
        log_fp.write(b"SEGV on unknown address 0x0 (pc 0x0 bp 0x0 sp 0x0 T0)\n")
        log_fp.write(b"    #0 0xbad000 in foo /file1.c:123:234\n")
        log_fp.write(b"    #1 0x1337dd in bar /file2.c:1806:19\n")
    fake_report = mocker.patch("grizzly.session.Report", autospec=True)
    mocker.patch("grizzly.session.tempfile.mkdtemp", autospec=True, return_value=str(tmpd))
    Status.PATH = str(tmp_path)
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.tests = mocker.Mock(spec=deque)
    fake_iomgr.working_path = str(tmp_path)
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_target = mocker.Mock(spec=Target)
    fake_target.binary = "bin"
    session = Session(None, False, fake_iomgr, fake_reporter, None, fake_target)
    session.report_result()
    assert fake_target.save_logs.call_count == 1
    fake_target.save_logs.assert_called_with(str(tmpd), meta=True)
    assert fake_report.from_path.return_value.crash_info.call_count == 1
    fake_report.from_path.return_value.crash_info.assert_called_with("bin")
    assert fake_reporter.submit.call_count == 1
    assert not tmpd.is_dir()

def test_log_output_limiter_01(mocker):
    """test LogOutputLimiter.ready() not ready"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.time.return_value = 1.0
    lol = LogOutputLimiter(delay=10, delta_multiplier=2)
    assert lol._delay == 10
    assert lol._iterations == 1
    assert lol._launches == 1
    assert lol._multiplier == 2
    assert lol._time == 1.0
    assert not lol._verbose
    fake_time.time.return_value = 1.1
    assert not lol.ready(0, 0)
    assert lol._iterations == 1
    assert lol._launches == 1
    assert lol._time == 1.0
    lol._verbose = True
    assert lol.ready(0, 0)

def test_log_output_limiter_02(mocker):
    """test LogOutputLimiter.ready() due to iterations"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.time.return_value = 1.0
    lol = LogOutputLimiter(delay=10, delta_multiplier=2)
    fake_time.time.return_value = 1.1
    lol._launches = 2
    assert lol.ready(1, 1)
    assert lol._iterations == 2
    assert lol._launches == 2
    assert lol._time == 1.1

def test_log_output_limiter_03(mocker):
    """test LogOutputLimiter.ready() due to launches"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.time.return_value = 1.0
    lol = LogOutputLimiter(delay=10, delta_multiplier=2)
    lol._iterations = 4
    assert lol.ready(3, 1)
    assert lol._launches == 2
    assert lol._iterations == 4
    assert lol._time == 1.0

def test_log_output_limiter_04(mocker):
    """test LogOutputLimiter.ready() due to time"""
    fake_time = mocker.patch("grizzly.session.time", autospec=True)
    fake_time.time.return_value = 1.0
    lol = LogOutputLimiter(delay=1, delta_multiplier=2)
    lol._iterations = 4
    fake_time.time.return_value = 2.0
    assert lol.ready(3, 0)
    assert lol._iterations == 4
    assert lol._launches == 1
    assert lol._time == 2.0
