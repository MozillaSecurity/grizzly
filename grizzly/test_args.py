# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from platform import system

from pytest import mark, raises

from .args import CommonArgs, GrizzlyArgs


def test_common_args_01(mocker, tmp_path):
    """test CommonArgs.parse_args() - success"""
    mocker.patch("grizzly.args.scan_plugins", return_value=["targ"])
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    CommonArgs().parse_args(argv=[str(fake_bin), "--platform", "targ"])


@mark.parametrize(
    "args, msg, idx",
    [
        # test help
        (["-h"], "For addition help check out the wiki", 0),
        # test without args
        ([], "the following arguments are required: binary", -1),
        # test with missing bin
        (["missing-bin"], "error: file not found: 'missing-bin'", -1),
    ],
)
def test_common_args_02(capsys, mocker, args, msg, idx):
    """test CommonArgs.parse_args()"""
    mocker.patch("grizzly.args.scan_plugins", return_value=["x"])
    with raises(SystemExit):
        CommonArgs().parse_args(argv=args)
    assert msg in capsys.readouterr()[idx]


@mark.parametrize(
    "args, msg, targets",
    [
        # test no installed platforms
        ([], "error: No Platforms (Targets) are installed", []),
        # test invalid log limit
        (["--log-limit", "-1"], "error: --log-limit must be >= 0", ["targ1"]),
        # test invalid memory limit
        (["--memory", "-1"], "error: --memory must be >= 0", ["targ1"]),
        # test invalid relaunch value
        (["--relaunch", "0"], "error: --relaunch must be >= 1", ["targ1"]),
        # test invalid asset
        (
            ["--platform", "targ1", "--asset", "bad", "a"],
            "error: Asset 'bad' not supported by target",
            ["targ1"],
        ),
        # test invalid asset path
        (
            ["--platform", "targ1", "--asset", "a", "a"],
            "error: Failed to add asset 'a' cannot find 'a'",
            ["targ1"],
        ),
        # test invalid time-limit
        (
            ["--platform", "targ1", "--time-limit", "-1"],
            "error: --time-limit must be >= 1",
            ["targ1"],
        ),
        # test invalid timeout
        (
            ["--platform", "targ1", "--timeout", "-1"],
            "error: --timeout must be >= 1",
            ["targ1"],
        ),
        # test invalid tool usage
        (
            ["--platform", "targ1", "--tool", "x"],
            "error: --tool can only be given with --fuzzmanager",
            ["targ1"],
        ),
        # test invalid launch-attempts value
        (
            ["--launch-attempts", "0"],
            "error: --launch-attempts must be >= 1",
            ["targ1"],
        ),
    ],
)
def test_common_args_03(capsys, mocker, tmp_path, args, msg, targets):
    """test CommonArgs.parse_args()"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=targets)
    mocker.patch(
        "grizzly.args.scan_target_assets",
        autospec=True,
        return_value={"targ1": ["a", "b"]},
    )
    mocker.patch("grizzly.args.system", autospec=True, return_value="foo")
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    with raises(SystemExit):
        CommonArgs().parse_args(argv=[str(fake_bin)] + args)
    assert msg in capsys.readouterr()[-1]


def test_common_args_04(tmp_path):
    """test CommonArgs.parse_args() '--logs' must be dir"""
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    # test with file
    with raises(SystemExit):
        CommonArgs().parse_args([str(fake_bin), "--logs", str(fake_bin)])
    # test with dir
    CommonArgs().parse_args([str(fake_bin), "--logs", str(tmp_path)])


def test_grizzly_args_01(mocker, tmp_path):
    """test GrizzlyArgs.parse_args() - success"""
    mocker.patch(
        "grizzly.args.scan_plugins",
        autospec=True,
        side_effect=(["targ"], ["adpt"]),
    )
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    assert GrizzlyArgs().parse_args(argv=[str(fake_bin), "adpt", "--platform", "targ"])


@mark.parametrize(
    "args, msg, idx",
    [
        # test help
        (["-h"], "For addition help check out the wiki", 0),
        # test without args
        ([], "the following arguments are required: binary, adapter", -1),
        # test missing binary
        (["missing-bin", "x"], "error: file not found: 'missing-bin'", -1),
    ],
)
def test_grizzly_args_02(capsys, mocker, args, msg, idx):
    """test GrizzlyArgs.parse_args()"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=["x"])
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=args)
    assert msg in capsys.readouterr()[idx]


def test_grizzly_args_03(capsys, mocker):
    """test GrizzlyArgs.parse_args() - no adapters installed"""
    mocker.patch("grizzly.args.scan_plugins", side_effect=(["t"], []))
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=["b", "a"])
    assert "error: No Adapters are installed" in capsys.readouterr()[-1]


@mark.parametrize(
    "args, msg",
    [
        # test invalid collect value
        (["--collect", "0"], "error: --collect must be greater than 0"),
        # test enabling both fuzzmanager and s3-fuzzmanager reporters
        (
            ["--fuzzmanager", "--s3-fuzzmanager"],
            "error: --fuzzmanager and --s3-fuzzmanager are mutually exclusive",
        ),
        # test missing input
        (["--input", "missing"], "error: 'missing' does not exist"),
        # test invalid limit value
        (["--limit", "-1"], "error: --limit must be >= 0"),
        # test invalid limit value
        (["--limit-reports", "-1"], "error: --limit-reports must be >= 0"),
        # test runtime limit value
        (["--runtime", "-1"], "error: --runtime must be >= 0"),
        # test tool
        (
            ["--tool", "x"],
            "error: --tool can only be given with --fuzzmanager/--s3-fuzzmanager",
        ),
    ],
)
def test_grizzly_args_04(capsys, mocker, tmp_path, args, msg):
    """test CommonArgs.parse_args()"""
    mocker.patch(
        "grizzly.args.scan_plugins",
        autospec=True,
        side_effect=(["targ"], ["adpt"]),
    )
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    with raises(SystemExit):
        GrizzlyArgs().parse_args(
            argv=[str(fake_bin), "adpt", "--platform", "targ"] + args
        )
    assert msg in capsys.readouterr()[-1]


@mark.skipif(system() != "Linux", reason="Only supported on Linux")
@mark.parametrize(
    "args, msg",
    [
        # test checking perf_event_paranoid
        (
            ["--rr"],
            "error: rr needs /proc/sys/kernel/perf_event_paranoid <= 1, but it is 99",
        ),
    ],
)
def test_grizzly_args_05(capsys, mocker, tmp_path, args, msg):
    """test CommonArgs.parse_args() - debugger system checks"""
    mocker.patch(
        "grizzly.args.scan_plugins",
        autospec=True,
        side_effect=(["targ"], ["adpt"]),
    )
    mocker.patch("grizzly.args.Path.read_text", autospec=True, return_value="99")
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    with raises(SystemExit):
        GrizzlyArgs().parse_args(
            argv=[str(fake_bin), "adpt", "--platform", "targ"] + args
        )
    assert msg in capsys.readouterr()[-1]
