# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly main"""

from pytest import raises

from sapphire import Sapphire
from .common import Adapter, Report
from .main import main
from .session import Session
from .target import TargetLaunchError


class FakeArgs(object):
    def __init__(self):
        self.binary = None
        self.input = None
        self.adapter = None
        self.cache = 0
        self.coverage = False
        self.extension = None
        self.fuzzmanager = False
        self.ignore = list()
        self.launch_timeout = 300
        self.log_level = 10  # 10 = DEBUG, 20 = INFO
        self.log_limit = 0
        self.memory = 0
        self.platform = "test"
        self.prefs = None
        self.rr = False
        self.relaunch = 1000
        self.s3_fuzzmanager = False
        self.timeout = 60
        self.tool = None
        self.valgrind = False
        self.verbose = False
        self.xvfb = False

# TODO: these could use call_count checks

def test_main_01(mocker):
    """test main()"""
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.NAME = "fake"
    fake_adapter.RELAUNCH = 1
    fake_adapter.TEST_DURATION = 10
    mocker.patch("grizzly.main.get_adapter", return_value=lambda: fake_adapter)
    targets = mocker.patch("grizzly.target.TARGETS")
    targets.return_value = "fake-target"
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.server = mocker.Mock(spec=Sapphire)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    args = FakeArgs()
    args.adapter = "fake"
    args.coverage = True
    args.input = "fake"
    args.ignore = ["fake", "fake"]
    args.prefs = "fake"
    args.rr = True
    args.valgrind = True
    args.xvfb = True
    with raises(RuntimeError, match="Coverage must be run with --relaunch > 1"):
        main(args)
    fake_adapter.RELAUNCH = 0
    assert main(args) == Session.EXIT_SUCCESS
    fake_reporter = mocker.patch("grizzly.main.FuzzManagerReporter", autospec=True)
    fake_reporter.sanity_check.return_value = True
    args.input = None
    args.log_level = None
    args.fuzzmanager = True
    assert main(args) == Session.EXIT_SUCCESS
    fake_reporter = mocker.patch("grizzly.main.S3FuzzManagerReporter", autospec=True)
    fake_reporter.sanity_check.return_value = True
    args.fuzzmanager = False
    args.s3_fuzzmanager = True
    assert main(args) == Session.EXIT_SUCCESS

def test_main_02(mocker, tmp_path):
    """test main() exit codes"""
    fake_adapter = mocker.Mock(spec=Adapter)
    fake_adapter.TEST_DURATION = 10
    fake_adapter.RELAUNCH = 0
    mocker.patch("grizzly.main.get_adapter", return_value=lambda: fake_adapter)
    targets = mocker.patch("grizzly.target.TARGETS")
    targets.return_value = "fake-target"
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    fake_session.EXIT_ABORT = Session.EXIT_ABORT
    fake_session.EXIT_ARGS = Session.EXIT_ARGS
    fake_session.EXIT_LAUNCH_FAILURE = Session.EXIT_LAUNCH_FAILURE
    fake_session.return_value.server = mocker.Mock(spec=Sapphire)
    args = FakeArgs()
    args.adapter = "fake"
    args.input = "fake"
    fake_session.return_value.run.side_effect = KeyboardInterrupt
    assert main(args) == Session.EXIT_ABORT
    # test TargetLaunchError
    fake_tmp = (tmp_path / "grz_tmp")
    fake_tmp.mkdir()
    mocker.patch("grizzly.main.grz_tmp", return_value=str(fake_tmp))
    fake_logs = (tmp_path / "report")
    report = mocker.Mock(spec=Report, prefix="fake_report", path=str(fake_logs))
    fake_logs.mkdir()
    fake_session.return_value.run.side_effect = TargetLaunchError("test", report)
    assert main(args) == Session.EXIT_LAUNCH_FAILURE
    assert any(fake_tmp.glob("fake_report_logs"))
    assert not fake_logs.is_dir()
    # invalid timeout arg
    fake_adapter.TEST_DURATION = args.timeout + 10
    assert main(args) == Session.EXIT_ARGS
    fake_session.EXIT_ARGS = Session.EXIT_ARGS
