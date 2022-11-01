# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly main"""
from pytest import mark

from sapphire import Sapphire

from .adapter import Adapter
from .args import GrizzlyArgs
from .common.utils import Exit
from .main import main
from .target import Target, TargetLaunchError


class FakeAdapter(Adapter):
    def generate(self, testcase, server_map):
        pass


@mark.parametrize(
    "adpt_relaunch, extra_args",
    [
        # successful run
        (0, []),
        # successful run - no harness
        (0, ["--no-harness"]),
        # successful run (with iteration limit)
        (0, ["--limit", "10"]),
        # successful run (with runtime limit)
        (0, ["--runtime", "10"]),
        # successful run (with coverage)
        (0, ["--coverage"]),
        # adapter relaunch 1
        (1, []),
        # relaunch 10
        (0, ["--relaunch", "10"]),
        # smoke test detects result
        (0, ["--smoke-test"]),
        # ignore something
        (0, ["--ignore", "timeout"]),
        # headless
        (0, ["--headless"]),
        # FuzzManager reporter
        (0, ["--fuzzmanager"]),
        # verbose mode
        (0, ["--verbose"]),
    ],
)
def test_main_01(mocker, adpt_relaunch, extra_args):
    """test main()"""
    mocker.patch("grizzly.main.FuzzManagerReporter", autospec=True)
    mocker.patch(
        "grizzly.args.scan_plugins",
        autospec=True,
        side_effect=(["targ"], ["adpt"]),
    )
    fake_target = mocker.Mock(spec_set=Target)
    FakeAdapter.RELAUNCH = adpt_relaunch
    mocker.patch("grizzly.main.load_plugin", side_effect=(FakeAdapter, fake_target))
    fake_session = mocker.patch("grizzly.main.Session", autospec_set=True)
    fake_session.return_value.server = mocker.Mock(spec_set=Sapphire)

    # use __file__ as "binary" since it is not used
    cmd = [__file__, "adpt", "--platform", "targ"] + extra_args
    args = GrizzlyArgs().parse_args(cmd)
    fake_session.return_value.status.results.total = 1 if args.smoke_test else 0

    assert main(args) == (Exit.ERROR if args.smoke_test else Exit.SUCCESS)
    assert fake_session.mock_calls[0][-1]["coverage"] == args.coverage
    if adpt_relaunch:
        assert fake_session.mock_calls[0][-1]["relaunch"] == adpt_relaunch
    else:
        assert fake_session.mock_calls[0][-1]["relaunch"] == args.relaunch
    assert fake_session.return_value.run.call_count == 1
    assert fake_target.return_value.cleanup.call_count == 1


@mark.parametrize(
    "exit_code, to_raise",
    [
        # test user abort
        (Exit.ABORT, KeyboardInterrupt),
        # test launch failure
        (Exit.LAUNCH_FAILURE, TargetLaunchError),
    ],
)
def test_main_02(mocker, exit_code, to_raise):
    """test main() - exit codes"""
    mocker.patch("grizzly.main.FailedLaunchReporter", autospec=True)
    mocker.patch("grizzly.main.FuzzManagerReporter", autospec=True)
    fake_target = mocker.Mock(spec_set=Target)
    mocker.patch("grizzly.main.load_plugin", side_effect=(FakeAdapter, fake_target))
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.status.results.total = 0
    if to_raise == TargetLaunchError:
        fake_session.return_value.run.side_effect = TargetLaunchError(
            "test", mocker.Mock()
        )
    else:
        fake_session.return_value.run.side_effect = to_raise()

    args = mocker.MagicMock(adapter="fake", time_limit=1, timeout=1)
    assert main(args) == exit_code
    assert fake_target.return_value.cleanup.call_count == 1


@mark.parametrize(
    "test_limit, timeout",
    [
        # use default test time limit and timeout values
        (None, None),
        # set test time limit
        (10, None),
        # set both test time limit and timeout to the same value
        (10, 10),
        # set timeout greater than test time limit
        (10, 11),
        # use default test time limit and low timeout
        (None, 1),
    ],
)
def test_main_03(mocker, test_limit, timeout):
    """test main() - time-limit and timeout"""
    mocker.patch("grizzly.main.FuzzManagerReporter", autospec=True)
    mocker.patch(
        "grizzly.main.load_plugin",
        side_effect=(FakeAdapter, mocker.Mock(spec_set=Target)),
    )
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.status.results.total = 0
    args = mocker.MagicMock(
        adapter="fake",
        no_harness=False,
        time_limit=test_limit,
        timeout=timeout,
    )
    assert main(args) == Exit.SUCCESS


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
    ],
)  # pylint: disable=invalid-name
def test_main_04(mocker, pernosco, rr, valgrind):  # pylint: disable=invalid-name
    """test enabling debuggers"""
    mocker.patch("grizzly.main.FuzzManagerReporter", autospec=True)
    fake_target = mocker.Mock(spec_set=Target)
    mocker.patch("grizzly.main.load_plugin", side_effect=(FakeAdapter, fake_target))
    fake_session = mocker.patch("grizzly.main.Session", autospec=True)
    fake_session.return_value.status.results.total = 0
    # maximum one debugger allowed at a time
    assert sum((pernosco, rr, valgrind)) < 2, "test broken!"
    args = mocker.MagicMock(
        adapter="fake",
        pernosco=pernosco,
        rr=rr,
        time_limit=1,
        timeout=1,
        valgrind=valgrind,
    )
    assert main(args) == Exit.SUCCESS
    assert fake_target.call_args[-1]["pernosco"] == pernosco
    assert fake_target.call_args[-1]["rr"] == rr
    assert fake_target.call_args[-1]["valgrind"] == valgrind
