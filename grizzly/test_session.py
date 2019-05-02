# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
unit tests for grizzly.Session
"""

import tempfile
import sapphire
from .core import Session


def test_session_00(mocker):
    """test basic Session functions"""
    fake_server = mocker.patch("sapphire.Sapphire", spec=sapphire.Sapphire)
    fake_server.return_value.serve_path.return_value = (sapphire.SERVED_TIMEOUT, [])
    mocker.patch("grizzly.core.TestFile", autospec=True)
    fake_adapter = mocker.Mock(autospec=True)
    fake_adapter.TEST_DURATION = 10
    fake_adapter.ROTATION_PERIOD = 0
    fake_adapter.size.return_value = 0
    fake_iomgr = mocker.Mock(autospec=True)
    fake_iomgr.server_map.includes = []
    fake_iomgr.server_map.redirects = []
    fake_iomgr.server_map.dynamic_responses = []
    fake_iomgr.landing_page.return_value = "HOMEPAGE.HTM"
    fake_iomgr.active_input.file_name = "HOMEPAGE.HTM"
    fake_iomgr.working_path = tempfile.gettempdir()
    fake_reporter = mocker.Mock(autospec=True)
    fake_target = mocker.Mock(autospec=True)
    fake_target.rl_reset = 10
    fake_target.log_size.return_value = 1000

    session = Session(fake_adapter, False, [], fake_iomgr, fake_reporter, fake_target)
    session.config_server(5)
    session.run()

    fake_iomgr.create_testcase.assert_called_once()
    fake_server.assert_called_once()
    fake_server.return_value.serve_path.assert_called_once()
    fake_target.detect_failure.assert_called_once()
