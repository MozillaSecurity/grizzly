# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
unit tests for grizzly.Session
"""

import pytest

from ffpuppet import BrowserTerminatedError, BrowserTimeoutError
from sapphire import SERVED_ALL, SERVED_TIMEOUT
from .corpman.adapter import Adapter
from .corpman.iomanager import IOManager, ServerMap
from .corpman.storage import TestCase, TestFile
from .reporter import Reporter
from .session import Session
from .target import Target


def test_session_00(tmp_path, mocker):
    """test basic Session functions"""
    fake_server = mocker.patch("sapphire.Sapphire", autospec=True)
    fake_server.return_value.serve_path.return_value = (SERVED_TIMEOUT, [])
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

    fake_iomgr.create_testcase.assert_called_once()
    fake_server.assert_called_once()
    fake_server.return_value.serve_path.assert_called_once()
    fake_server.return_value.close.assert_called_once()
    fake_target.detect_failure.assert_called_once()

def test_session_01(mocker):
    """test Session.check_results()"""
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.IGNORE_UNSERVED = True
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.tests = [mocker.Mock(spec=TestCase)]
    fake_target = mocker.Mock(spec=Target)

    session = Session(fake_adapter, False, [], fake_iomgr, None, fake_target)
    session.report_result = mocker.Mock()

    session.check_results(True, False)
    assert not fake_iomgr.tests
    fake_target.detect_failure.assert_called_once()
    fake_iomgr.reset_mock()
    fake_target.reset_mock()

    fake_target.detect_failure.return_value = fake_target.RESULT_FAILURE
    session.check_results(False, False)
    fake_target.detect_failure.assert_called_once()
    session.report_result.assert_called_once()
    assert session.status.results == 1
    fake_iomgr.reset_mock()
    fake_target.reset_mock()

    fake_target.detect_failure.return_value = fake_target.RESULT_IGNORED
    session.check_results(False, False)
    fake_target.detect_failure.assert_called_once()
    assert session.status.ignored == 1

    session.close()

def test_session_02(mocker):
    """test Session.generate_testcase()"""
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
    testcase = session.generate_testcase("fake_path")
    testcase.add_meta.assert_called_once()
    testcase.dump.assert_called_once()
    fake_server.return_value.set_redirect.assert_called_once()

def test_session_03(mocker, tmp_path):
    """test Session.launch_target()"""
    fake_server = mocker.Mock()
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

    fake_target = FakeTarget(launch_raise=BrowserTerminatedError)
    fake_reporter = mocker.Mock(spec=Reporter)
    session = Session(fake_adapter, False, [], fake_iomgr, fake_reporter, fake_target)
    session.server = fake_server
    with pytest.raises(BrowserTerminatedError):
        session.launch_target()
    assert fake_target.closed
    assert session.status.results == 1

    fake_target = FakeTarget(launch_raise=BrowserTimeoutError)
    fake_reporter = mocker.Mock(spec=Reporter)
    session = Session(fake_adapter, False, [], fake_iomgr, fake_reporter, fake_target)
    session.server = fake_server
    with pytest.raises(BrowserTimeoutError):
        session.launch_target()
    assert fake_target.closed

def test_session_04(mocker):
    """test Session.location"""
    fake_server = mocker.Mock()
    fake_server.get_port.return_value = 1
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 1
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.harness = mocker.Mock()
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

def test_session_05(mocker):
    """test Session.config_server()"""
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_server = mocker.patch("sapphire.Sapphire", autospec=True)
    fake_iomgr = mocker.Mock(spec=IOManager)
    fake_iomgr.server_map = mocker.Mock(spec=ServerMap)
    fake_iomgr.server_map.includes = [("test", "test")]
    fake_iomgr.server_map.dynamic_responses = [{"url": "a", "callback": lambda: 1, "mime": "x"}]
    fake_iomgr.server_map.redirects = [{"url":"", "file_name":"somefile", "required":True}]
    fake_target = mocker.Mock(spec=Target)
    session = Session(fake_adapter, False, [], fake_iomgr, None, fake_target)
    session.config_server(5)
    assert fake_server.return_value.add_dynamic_response.call_count == 2
    fake_server.return_value.add_include.assert_called_once()

def test_session_06(tmp_path, mocker):
    """test Session.run()"""
    fake_server = mocker.patch("sapphire.Sapphire", spec=True)
    mocker.patch("grizzly.session.TestFile", autospec=True)
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 10
    fake_adapter.ROTATION_PERIOD = 2
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
    def fake_serve_path(*_a, **_kw):
        return SERVED_TIMEOUT if session.status.iteration % 2 else SERVED_ALL, []
    session.server.serve_path = fake_serve_path
    session.run(10)
    session.close()

    fake_server.assert_called_once()
    fake_server.return_value.close.assert_called_once()
    assert session.status.iteration == 10
    assert fake_iomgr.create_testcase.call_count == 10
    assert fake_target.detect_failure.call_count == 10
