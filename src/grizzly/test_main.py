# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""test Grizzly main"""
from platform import system

from pytest import mark, skip

from .args import GrizzlyArgs
from .common.utils import Exit
from .main import main
from .target import TargetLaunchError


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
        # verbose mode
        (0, ["--verbose"]),
    ],
)
def test_main_01(mocker, session_setup, adpt_relaunch, extra_args):
    """test main()"""
    cov_support = system() == "Linux"
    if "--coverage" in extra_args and not cov_support:
        skip(f"--coverage not available on {system()}")
    mocker.patch(
        "grizzly.args.scan_plugins",
        autospec=True,
        side_effect=(["targ"], ["adpt"]),
    )
    adapter, session_cls, session_obj, target_cls = session_setup
    adapter.RELAUNCH = adpt_relaunch

    # use __file__ as "binary" since it is not used
    cmd = [__file__, "adpt", "--platform", "targ", *extra_args]
    args = GrizzlyArgs().parse_args(cmd)
    session_obj.status.results.total = 1 if args.smoke_test else 0

    assert main(args) == (Exit.ERROR if args.smoke_test else Exit.SUCCESS)
    if cov_support:
        assert session_cls.mock_calls[0][-1]["coverage"] == args.coverage
    if adpt_relaunch:
        assert session_cls.mock_calls[0][-1]["relaunch"] == adpt_relaunch
    else:
        assert session_cls.mock_calls[0][-1]["relaunch"] == args.relaunch
    assert session_obj.run.call_count == 1
    assert target_cls.return_value.cleanup.call_count == 1


@mark.parametrize(
    "exit_code, to_raise",
    [
        # test user abort
        (Exit.ABORT, KeyboardInterrupt),
        # test launch failure
        (Exit.LAUNCH_FAILURE, TargetLaunchError),
    ],
)
def test_main_02(mocker, session_setup, exit_code, to_raise):
    """test main() - exit codes"""
    mocker.patch("grizzly.main.FailedLaunchReporter", autospec=True)
    _, _, session_obj, target_cls = session_setup
    if to_raise == TargetLaunchError:
        session_obj.run.side_effect = TargetLaunchError("test", mocker.Mock())
    else:
        session_obj.run.side_effect = to_raise()
    args = mocker.MagicMock(adapter="fake", time_limit=1, timeout=1)
    assert main(args) == exit_code
    assert target_cls.return_value.cleanup.call_count == 1


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
def test_main_03(mocker, session_setup, test_limit, timeout):
    """test main() - time-limit and timeout"""
    # no_harness=False for code coverage
    args = mocker.MagicMock(
        adapter="fake",
        no_harness=False,
        time_limit=test_limit,
        timeout=timeout,
    )
    assert main(args) == Exit.SUCCESS
    target_cls = session_setup[3]
    assert target_cls.return_value.cleanup.call_count == 1


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
def test_main_04(
    mocker, session_setup, pernosco, rr, valgrind
):  # pylint: disable=invalid-name
    """test enabling debuggers"""
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
    target_cls = session_setup[3]
    assert target_cls.call_args[-1]["pernosco"] == pernosco
    assert target_cls.call_args[-1]["rr"] == rr
    assert target_cls.call_args[-1]["valgrind"] == valgrind


def test_main_05(mocker, session_setup):
    """test target does not support https"""
    target_cls = session_setup[3]
    target_cls.return_value.https.return_value = False
    args = mocker.MagicMock(
        adapter="fake",
        use_http=False,
        time_limit=1,
        timeout=1,
    )
    assert main(args) == Exit.SUCCESS
    assert target_cls.return_value.https.call_count == 1
