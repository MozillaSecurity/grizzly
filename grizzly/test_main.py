# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly main"""
from pathlib import Path

from pytest import mark

from sapphire import Sapphire

from .adapter import Adapter
from .common.utils import Exit
from .main import main
from .target import AssetManager, Target, TargetLaunchError


class FakeArgs:
    def __init__(self):
        self.binary = None
        self.input = None
        self.adapter = None
        self.asset = list()
        self.collect = 1
        self.coverage = False
        self.enable_profiling = False
        self.extension = None
        self.fuzzmanager = False
        self.headless = None
        self.ignore = list()
        self.launch_attempts = 3
        self.launch_timeout = 300
        self.limit = 0
        self.limit_reports = 0
        self.logs = Path.cwd()
        self.log_level = 10  # 10 = DEBUG, 20 = INFO
        self.log_limit = 0
        self.memory = 0
        self.pernosco = False
        self.platform = "fake-target"
        self.prefs = None
        self.rr = False  # pylint: disable=invalid-name
        self.relaunch = 1000
        self.runtime = 0
        self.s3_fuzzmanager = False
        self.smoke_test = False
        self.time_limit = None
        self.timeout = None
        self.tool = None
        self.valgrind = False
        self.verbose = False


@mark.parametrize(
    "cov, adpt_relaunch, limit, runtime, smoke_test, verbose",
    [
        # successful run
        (False, 0, 0, 0, False, True),
        # successful run (with iteration limit)
        (False, 0, 10, 0, False, True),
        # successful run (with runtime limit)
        (False, 0, 0, 10, False, True),
        # successful run (with coverage)
        (True, 0, 0, 0, False, False),
        # relaunch 1
        (False, 1, 0, 0, False, False),
        # relaunch 10
        (False, 10, 0, 0, False, False),
        # smoke test detects result
        (False, 0, 0, 0, True, False),
    ],
)
def test_main_01(mocker, cov, adpt_relaunch, limit, runtime, smoke_test, verbose):
    """test main()"""
    fake_adapter = mocker.NonCallableMock(spec_set=Adapter)
    fake_adapter.RELAUNCH = adpt_relaunch
    fake_adapter.TIME_LIMIT = 10
    fake_target = mocker.NonCallableMock(
        spec_set=Target, assets=mocker.Mock(spec_set=AssetManager)
    )
    plugin_loader = mocker.patch("grizzly.main.load_plugin", autospec=True)
    plugin_loader.side_effect = (
        mocker.Mock(spec_set=Adapter, return_value=fake_adapter),
        mocker.Mock(spec_set=Target, return_value=fake_target),
    )
    fake_session = mocker.patch("grizzly.main.Session", autospec_set=True)
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)
    fake_session.return_value.status.results.total = 1 if smoke_test else 0
    args = FakeArgs()
    args.asset = [
        ["fake", "fake"],
    ]
    args.adapter = "fake"
    args.headless = "xvfb"
    args.ignore = ["fake", "fake"]
    args.limit = limit
    args.runtime = runtime
    args.rr = True
    args.smoke_test = smoke_test
    args.valgrind = True
    args.verbose = verbose
    if not verbose:
        args.log_level = 20
    args.coverage = cov
    assert main(args) == (Exit.ERROR if smoke_test else Exit.SUCCESS)
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
    fake_session.return_value.status.results.total = 0
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
    assert main(args) == Exit.SUCCESS
    assert fake_target.cleanup.call_count == 1


@mark.parametrize(
    "exit_code, to_raise",
    [
        # test user abort
        (Exit.ABORT, KeyboardInterrupt()),
        # test launch failure
        (Exit.LAUNCH_FAILURE, TargetLaunchError("test", None)),
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
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)
    fake_session.return_value.status.results.total = 0
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
        (None, None, Exit.SUCCESS),
        # set test time limit
        (10, None, Exit.SUCCESS),
        # set both test time limit and timeout to the same value
        (10, 10, Exit.SUCCESS),
        # set timeout greater than test time limit
        (10, 11, Exit.SUCCESS),
        # set test time limit greater than timeout
        (11, 10, Exit.ARGS),
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
    fake_session.return_value.status.results.total = 0
    args = FakeArgs()
    args.adapter = "fake"
    args.time_limit = arg_testlimit
    args.timeout = arg_timeout
    assert main(args) == exit_code


@mark.parametrize(
    "pernosco, rr, valgrind",
    [
        # No debugger enabled
        (False, False, False),
        # Pernosco enabled
        (True, False, False),
        # rr enabled
        (False, True, False),
        # Valgrind enabled
        (False, False, True),
    ],  # pylint: disable=invalid-name
)
def test_main_05(mocker, pernosco, rr, valgrind):
    """test enabling debuggers"""
    fake_adapter = mocker.NonCallableMock(spec_set=Adapter)
    fake_adapter.RELAUNCH = 1
    fake_adapter.TIME_LIMIT = 10
    fake_target = mocker.Mock(spec_set=Target)
    plugin_loader = mocker.patch("grizzly.main.load_plugin", autospec=True)
    plugin_loader.side_effect = (
        mocker.Mock(spec_set=Adapter, return_value=fake_adapter),
        fake_target,
    )
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)
    fake_session.return_value.status.results.total = 0
    args = FakeArgs()
    args.adapter = "fake"
    # maximum one debugger allowed at a time
    assert sum((pernosco, rr, valgrind)) < 2, "test broken!"
    args.pernosco = pernosco
    args.rr = rr
    args.valgrind = valgrind
    assert main(args) == Exit.SUCCESS
    assert fake_target.call_args[-1]["pernosco"] == pernosco
    assert fake_target.call_args[-1]["rr"] == rr
    assert fake_target.call_args[-1]["valgrind"] == valgrind
