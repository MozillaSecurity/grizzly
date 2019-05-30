# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly main"""

import pytest

from ffpuppet import LaunchError

from .core import main
from .corpman.adapter import Adapter
from .session import Session


class FakeArgs(object):
    def __init__(self, working_path):
        self.binary = None
        self.input = None
        self.accepted_extensions = None
        self.adapter = None
        self.cache = 0
        self.coverage = False
        self.extension = None
        self.fuzzmanager = False
        self.ignore = list()
        self.launch_timeout = 300
        self.log_limit = 0
        self.memory = 0
        self.mime = None
        self.platform = "test"
        self.prefs = None
        self.rr = False
        self.relaunch = 1000
        self.s3_fuzzmanager = False
        self.soft_asserts = False
        self.timeout = 60
        self.tool = None
        self.valgrind = False
        self.working_path = working_path
        self.xvfb = False

def test_main_01(tmp_path, mocker):
    """test main()"""
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 10
    adapter_get = mocker.patch("grizzly.corpman.adapters.get")
    adapter_get.return_value = lambda: fake_adapter
    targets = mocker.patch("grizzly.target.TARGETS")
    targets.return_value = "fake-target"
    fake_session = mocker.patch("grizzly.core.Session", autospec=True)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    args = FakeArgs(str(tmp_path))
    args.adapter = "fake"
    args.input = "fake"
    args.ignore = ["fake", "fake"]
    args.soft_asserts = True
    args.rr = True
    args.valgrind = True
    args.xvfb = True
    assert main(args) == Session.EXIT_SUCCESS
    mocker.patch("grizzly.core.FuzzManagerReporter", autospec=True)
    args.fuzzmanager = True
    args.coverage = True
    assert main(args) == Session.EXIT_SUCCESS
    mocker.patch("grizzly.core.S3FuzzManagerReporter", autospec=True)
    args.fuzzmanager = False
    args.s3_fuzzmanager = True
    assert main(args) == Session.EXIT_SUCCESS

def test_main_02(tmp_path, mocker):
    """test main()"""
    fake_adapter = mocker.Mock(spec=Adapter)
    adapter_get = mocker.patch("grizzly.corpman.adapters.get")
    adapter_get.return_value = lambda: fake_adapter
    fake_session = mocker.patch("grizzly.core.Session", autospec=True)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    args = FakeArgs(str(tmp_path))
    args.adapter = "fake"
    args.input = "fake"
    fake_adapter.TEST_DURATION = args.timeout + 10
    with pytest.raises(RuntimeError):
        main(args)

def test_main_03(tmp_path, mocker):
    """test main() exit codes"""
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 10
    fake_adapter.ROTATION_PERIOD = 0
    adapter_get = mocker.patch("grizzly.corpman.adapters.get")
    adapter_get.return_value = lambda: fake_adapter
    targets = mocker.patch("grizzly.target.TARGETS")
    targets.return_value = "fake-target"
    fake_session = mocker.patch("grizzly.core.Session", autospec=True)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    fake_session.EXIT_ABORT = Session.EXIT_ABORT
    fake_session.EXIT_LAUNCH_FAILURE = Session.EXIT_LAUNCH_FAILURE
    args = FakeArgs(str(tmp_path))
    args.adapter = "fake"
    args.input = "fake"
    fake_session.return_value.run.side_effect = KeyboardInterrupt
    assert main(args) == Session.EXIT_ABORT
    fake_session.return_value.run.side_effect = LaunchError("test")
    assert main(args) == Session.EXIT_LAUNCH_FAILURE
