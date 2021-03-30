# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly main"""
from pytest import mark

from sapphire import Sapphire

from .adapter import Adapter
from .main import main
from .session import Session
from .target import Target, TargetLaunchError


class FakeArgs:
    def __init__(self):
        self.binary = None
        self.input = None
        self.adapter = None
        self.collect = 1
        self.coverage = False
        self.enable_profiling = False
        self.extension = None
        self.fuzzmanager = False
        self.ignore = list()
        self.launch_timeout = 300
        self.limit = 0
        self.log_level = 10  # 10 = DEBUG, 20 = INFO
        self.log_limit = 0
        self.memory = 0
        self.platform = "fake-target"
        self.prefs = None
        self.rr = False  # pylint: disable=invalid-name
        self.relaunch = 1000
        self.s3_fuzzmanager = False
        self.time_limit = None
        self.timeout = None
        self.tool = None
        self.valgrind = False
        self.verbose = False
        self.xvfb = False


@mark.parametrize(
    "cov, adpt_relaunch, limit, verbose",
    [
        # successful run
        (False, 0, 0, True),
        # successful run (with limit)
        (False, 0, 10, True),
        # successful run (with coverage)
        (True, 0, 0, False),
        # relaunch 1
        (False, 1, 0, False),
        # relaunch 10
        (False, 10, 0, False),
    ],
)
def test_main_01(mocker, cov, adpt_relaunch, limit, verbose):
    """test main()"""
    fake_adapter = mocker.NonCallableMock(spec_set=Adapter)
    fake_adapter.RELAUNCH = adpt_relaunch
    fake_adapter.TIME_LIMIT = 10
    fake_target = mocker.NonCallableMock(spec_set=Target)
    plugin_loader = mocker.patch("grizzly.main.load_plugin", autospec=True)
    plugin_loader.side_effect = (
        mocker.Mock(spec_set=Adapter, return_value=fake_adapter),
        mocker.Mock(spec_set=Target, return_value=fake_target),
    )
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    args = FakeArgs()
    args.adapter = "fake"
    args.ignore = ["fake", "fake"]
    args.limit = limit
    args.prefs = "fake"
    args.rr = True
    args.valgrind = True
    args.xvfb = True
    args.verbose = verbose
    if not verbose:
        args.log_level = 20
    args.coverage = cov
    assert main(args) == Session.EXIT_SUCCESS
    assert fake_session.mock_calls[0][-1]["coverage"] == cov
    if adpt_relaunch:
        assert fake_session.mock_calls[0][-1]["relaunch"] == adpt_relaunch
    else:
        # check default
        assert fake_session.mock_calls[0][-1]["relaunch"] == 1000
    assert fake_session.return_value.run.call_count == 1
    assert fake_target.cleanup.call_count == 1


@mark.parametrize(
    "reporter",
    [
        # Default reporter
        None,
        # FuzzManager Reporter
        "FuzzManager",
        # S3FuzzManager Reporter
        "S3FuzzManager",
    ],
)
def test_main_02(mocker, reporter):
    """test main() - test reporters"""
    fake_adapter = mocker.NonCallableMock(spec_set=Adapter)
    fake_adapter.RELAUNCH = 0
    fake_adapter.TIME_LIMIT = 10
    fake_target = mocker.NonCallableMock(spec_set=Target)
    plugin_loader = mocker.patch("grizzly.main.load_plugin", autospec=True)
    plugin_loader.side_effect = (
        mocker.Mock(spec_set=Adapter, return_value=fake_adapter),
        mocker.Mock(spec_set=Target, return_value=fake_target),
    )
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    args = FakeArgs()
    args.adapter = "fake"
    if reporter == "FuzzManager":
        fake_reporter = mocker.patch("grizzly.main.FuzzManagerReporter", autospec=True)
        fake_reporter.sanity_check.return_value = True
        args.fuzzmanager = True
    elif reporter == "S3FuzzManager":
        fake_reporter = mocker.patch(
            "grizzly.main.S3FuzzManagerReporter", autospec=True
        )
        fake_reporter.sanity_check.return_value = True
        args.s3_fuzzmanager = True
    assert main(args) == Session.EXIT_SUCCESS
    assert fake_target.cleanup.call_count == 1


@mark.parametrize(
    "exit_code, to_raise",
    [
        # test user abort
        (Session.EXIT_ABORT, KeyboardInterrupt()),
        # test launch failure
        (Session.EXIT_LAUNCH_FAILURE, TargetLaunchError("test", None)),
    ],
)
def test_main_03(mocker, exit_code, to_raise):
    """test main() - exit codes"""
    fake_adapter = mocker.NonCallableMock(spec_set=Adapter, name="fake")
    fake_adapter.RELAUNCH = 0
    fake_adapter.TIME_LIMIT = 10
    fake_target = mocker.NonCallableMock(spec_set=Target)
    plugin_loader = mocker.patch("grizzly.main.load_plugin", autospec=True)
    plugin_loader.side_effect = (
        mocker.Mock(spec_set=Adapter, return_value=fake_adapter),
        mocker.Mock(spec_set=Target, return_value=fake_target),
    )
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    fake_session.EXIT_ABORT = Session.EXIT_ABORT
    fake_session.EXIT_ARGS = fake_session.EXIT_ARGS = Session.EXIT_ARGS
    fake_session.EXIT_LAUNCH_FAILURE = Session.EXIT_LAUNCH_FAILURE
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)
    args = FakeArgs()
    args.adapter = "fake"
    args.input = "fake"
    fake_session.return_value.run.side_effect = to_raise
    assert main(args) == exit_code
    assert fake_target.cleanup.call_count == 1


@mark.parametrize(
    "arg_testlimit, arg_timeout, exit_code",
    [
        # use default test time limit and timeout values
        (None, None, Session.EXIT_SUCCESS),
        # set test time limit
        (10, None, Session.EXIT_SUCCESS),
        # set both test time limit and timeout to the same value
        (10, 10, Session.EXIT_SUCCESS),
        # set timeout greater than test time limit
        (10, 11, Session.EXIT_SUCCESS),
        # set test time limit greater than timeout
        (11, 10, Session.EXIT_ARGS),
    ],
)
def test_main_04(mocker, arg_testlimit, arg_timeout, exit_code):
    """test main() - time-limit and timeout"""
    fake_adapter = mocker.NonCallableMock(spec_set=Adapter, name="fake")
    fake_adapter.RELAUNCH = 1
    fake_adapter.TIME_LIMIT = 10
    fake_target = mocker.NonCallableMock(spec_set=Target)
    plugin_loader = mocker.patch("grizzly.main.load_plugin", autospec=True)
    plugin_loader.side_effect = (
        mocker.Mock(spec_set=Adapter, return_value=fake_adapter),
        mocker.Mock(spec_set=Target, return_value=fake_target),
    )
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)
    fake_session.EXIT_ARGS = Session.EXIT_ARGS
    fake_session.EXIT_SUCCESS = Session.EXIT_SUCCESS
    args = FakeArgs()
    args.adapter = "fake"
    args.time_limit = arg_testlimit
    args.timeout = arg_timeout
    assert main(args) == exit_code
