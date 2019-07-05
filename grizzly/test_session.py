# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
unit tests for grizzly.Session
"""

import pytest

from sapphire import Sapphire, SERVED_ALL, SERVED_TIMEOUT
from grizzly.common import Adapter, IOManager, Reporter, ServerMap, Status, TestCase, TestFile
from grizzly.session import Session
from grizzly.target import Target, TargetLaunchError, TargetLaunchTimeout


def test_session_00(tmp_path, mocker):
    """test basic Session functions"""
    Status.DB_FILE = str(tmp_path / "test.db")
    fake_server = mocker.patch("sapphire.Sapphire", autospec=True)
    fake_server.return_value.serve_testcase.return_value = (SERVED_TIMEOUT, [])
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 10
    fake_adapter.ROTATION_PERIOD = 0
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.server_map.includes = []
    fake_iomgr.server_map.redirects = []
    fake_iomgr.server_map.dynamic_responses = []
    fake_iomgr.active_input = mocker.Mock(spec=TestFile)
    fake_iomgr.active_input.file_name = "input.txt"
    fake_iomgr.harness = None
    fake_iomgr.input_files = []
    fake_iomgr.landing_page.return_value = "HOMEPAGE.HTM"
    fake_iomgr.tests = [mocker.Mock(spec=TestCase)]
    fake_iomgr.working_path = str(tmp_path)
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_target = mocker.Mock(spec=Target)
    fake_target.log_size.return_value = 1000
    fake_target.rl_reset = 10
    fake_target.prefs = None

    session = Session(fake_adapter, False, [], fake_iomgr, fake_reporter, fake_target)
    session.TARGET_LOG_SIZE_WARN = 100
    session.coverage = True
    session.config_server(5)
    session.run()
    session.close()

    assert fake_iomgr.create_testcase.call_count == 1
    assert fake_server.call_count == 1
    assert fake_server.return_value.serve_testcase.call_count == 1
    assert fake_server.return_value.close.call_count == 1
    assert fake_target.detect_failure.call_count == 1

def test_session_01(tmp_path, mocker):
    """test Session.check_results()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.IGNORE_UNSERVED = True
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.tests = [mocker.Mock(spec=TestCase)]
    fake_target = mocker.Mock(spec=Target)

    session = Session(fake_adapter, False, [], fake_iomgr, None, fake_target)
    session.report_result = mocker.Mock(return_value=None)

    session.check_results(True, False)
    assert not fake_iomgr.tests
    assert fake_target.detect_failure.call_count == 1
    fake_iomgr.reset_mock()
    fake_target.reset_mock()

    fake_target.detect_failure.return_value = fake_target.RESULT_FAILURE
    session.check_results(False, False)
    assert fake_target.detect_failure.call_count == 1
    assert session.report_result.call_count == 1
    assert session.status.results == 1
    fake_iomgr.reset_mock()
    fake_target.reset_mock()

    fake_target.detect_failure.return_value = fake_target.RESULT_IGNORED
    session.check_results(False, False)
    assert fake_target.detect_failure.call_count == 1
    assert session.status.ignored == 1

    session.close()

def test_session_02(tmp_path, mocker):
    """test Session.generate_testcase()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    fake_server = mocker.patch("sapphire.Sapphire", autospec=True)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.active_input = mocker.Mock(spec=TestFile)
    fake_iomgr.active_input.file_name = "infile"
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.server_map.includes = []
    fake_iomgr.server_map.redirects = []
    fake_iomgr.server_map.dynamic_responses = []
    fake_iomgr.server_map.redirects = ({"url":"", "file_name":"somefile", "required":True},)
    fake_target = mocker.Mock(spec=Target)
    fake_target.prefs = "fake_prefs.js"

    session = Session(fake_adapter, False, [], fake_iomgr, None, fake_target)
    session.config_server(5)
    fake_adapter.generate.assert_not_called()
    testcase = session.generate_testcase()
    assert fake_adapter.generate.call_count == 1
    assert testcase.add_meta.call_count == 1
    assert fake_server.return_value.set_redirect.call_count == 1

def test_session_03(mocker, tmp_path):
    """test Session.launch_target()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    fake_server = mocker.Mock(spec=Sapphire)
    fake_server.get_port.return_value = 1
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 10
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.harness = None
    fake_iomgr.tests = []
    fake_iomgr.working_path = str(tmp_path)
    fake_iomgr.landing_page.return_value = "x"
    class FakeTarget(object):
        def __init__(self, launch_raise=None):
            self._closed = True
            self._raise = launch_raise
            self.forced_close = False
            self.prefs = None
            self.rl_reset = 10
        def cleanup(self):
            pass
        def close(self):
            pass
        @property
        def closed(self):
            return self._closed
        def detect_failure(self, ignored, was_timeout):
            pass
        def launch(self, _):
            if self._raise is not None:
                raise self._raise("Test")
            self._closed = False
        def monitor(self):
            pass
        def save_logs(self, result_logs, meta=True):
            pass
    fake_target = FakeTarget()
    session = Session(fake_adapter, False, [], fake_iomgr, None, fake_target)
    session.server = fake_server
    session.launch_target()
    assert not fake_target.closed

    fake_target = FakeTarget(launch_raise=TargetLaunchError)
    fake_reporter = mocker.Mock(spec=Reporter)
    session = Session(fake_adapter, False, [], fake_iomgr, fake_reporter, fake_target)
    session.server = fake_server
    with pytest.raises(TargetLaunchError):
        session.launch_target()
    assert fake_target.closed
    assert session.status.results == 1

    fake_target = FakeTarget(launch_raise=TargetLaunchTimeout)
    fake_reporter = mocker.Mock(spec=Reporter)
    session = Session(fake_adapter, False, [], fake_iomgr, fake_reporter, fake_target)
    session.server = fake_server
    with pytest.raises(TargetLaunchTimeout):
        session.launch_target()
    assert fake_target.closed

def test_session_04(tmp_path, mocker):
    """test Session.location"""
    Status.DB_FILE = str(tmp_path / "test.db")
    fake_server = mocker.Mock(spec=Sapphire)
    fake_server.get_port.return_value = 1
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 1
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.harness = mocker.Mock(spec=TestFile)
    fake_iomgr.landing_page.return_value = "x"
    fake_target = mocker.Mock(spec=Target)
    fake_target.rl_reset = 1

    fake_target.forced_close = False
    session = Session(fake_adapter, False, [], fake_iomgr, fake_adapter, fake_target)
    session.server = fake_server
    assert session.location == "http://127.0.0.1:1/x?timeout=1000&close_after=1&forced_close=0"

    fake_target.forced_close = True
    session = Session(fake_adapter, False, [], fake_iomgr, fake_adapter, fake_target)
    session.server = fake_server
    assert session.location == "http://127.0.0.1:1/x?timeout=1000&close_after=1"

    fake_iomgr.harness = None
    session = Session(fake_adapter, False, [], fake_iomgr, fake_adapter, fake_target)
    session.server = fake_server
    assert session.location == "http://127.0.0.1:1/x"

def test_session_05(tmp_path, mocker):
    """test Session.config_server()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_server = mocker.patch("sapphire.Sapphire", autospec=True)
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.server_map.includes = [("test", "test")]
    fake_iomgr.server_map.dynamic_responses = [{"url": "a", "callback": lambda: 1, "mime": "x"}]
    fake_iomgr.server_map.redirects = [{"url":"", "file_name":"somefile", "required":True}]
    session = Session(fake_adapter, False, [], fake_iomgr, None, mocker.Mock(spec=Target))
    session.config_server(5)
    assert fake_server.return_value.add_dynamic_response.call_count == 2
    assert fake_server.return_value.add_include.call_count == 1

def test_session_06(tmp_path, mocker):
    """test Session.run()"""
    Status.DB_FILE = str(tmp_path / "test.db")
    fake_server = mocker.patch("sapphire.Sapphire", spec=True)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.IGNORE_UNSERVED = True
    fake_adapter.ROTATION_PERIOD = 2
    fake_adapter.TEST_DURATION = 10
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.server_map.includes = []
    fake_iomgr.server_map.redirects = []
    fake_iomgr.server_map.dynamic_responses = []
    fake_iomgr.active_input = mocker.Mock(spec=TestFile)
    fake_iomgr.active_input.file_name = "input.txt"
    fake_iomgr.harness = None
    fake_iomgr.input_files = []
    fake_iomgr.landing_page.return_value = "HOMEPAGE.HTM"
    fake_iomgr.tests = mocker.Mock(spec=list)
    fake_iomgr.tests.pop.return_value = mocker.Mock(spec=TestCase)
    fake_iomgr.working_path = str(tmp_path)
    fake_reporter = mocker.Mock(spec=Reporter)
    fake_target = mocker.Mock(spec=Target)
    fake_target.rl_reset = 5
    fake_target.log_size.return_value = 1000
    fake_target.prefs = "prefs.js"

    session = Session(fake_adapter, False, [], fake_iomgr, fake_reporter, fake_target)
    session.TARGET_LOG_SIZE_WARN = 100
    session.config_server(5)
    def fake_serve_testcase(*_a, **_kw):
        return SERVED_TIMEOUT if session.status.iteration % 2 else SERVED_ALL, []
    session.server.serve_testcase = fake_serve_testcase
    fake_adapter.on_served.assert_not_called()
    fake_adapter.on_timeout.assert_not_called()
    fake_adapter.pre_launch.assert_not_called()
    session.run(10)
    assert fake_adapter.on_served.call_count == 5
    assert fake_adapter.on_timeout.call_count == 5
    assert fake_adapter.pre_launch.call_count == 10
    assert fake_iomgr.purge_tests.call_count == 10
    assert fake_target.launch.call_count == fake_iomgr.purge_tests.call_count
    session.close()

    assert fake_server.call_count == 1
    assert fake_server.return_value.close.call_count == 1
    assert session.status.iteration == 10
    assert fake_iomgr.create_testcase.call_count == 10
    assert fake_target.detect_failure.call_count == 10
    assert fake_iomgr.create_testcase.return_value.remove_files_not_served.call_count == 10
