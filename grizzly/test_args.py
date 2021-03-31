# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from pytest import mark, raises

from .args import CommonArgs, GrizzlyArgs


def test_common_args_01(capsys, mocker):
    """test CommonArgs.parse_args()"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=[])
    # test help
    with raises(SystemExit):
        CommonArgs().parse_args(argv=["-h"])
    assert "For addition help check out the wiki" in capsys.readouterr()[0]
    # test empty args
    with raises(SystemExit):
        CommonArgs().parse_args(argv=[])
    assert "the following arguments are required: binary" in capsys.readouterr()[-1]


def test_common_args_01a(capsys, mocker, tmp_path):
    """test CommonArgs.parse_args()"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=["targ1"])
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    # test with missing bin
    with raises(SystemExit):
        CommonArgs().parse_args(argv=["missing-bin"])
    assert "error: file not found: 'missing-bin'" in capsys.readouterr()[-1]
    # test success
    CommonArgs().parse_args(argv=[str(fake_bin), "--platform", "targ1"])
    # test invalid extension
    with raises(SystemExit):
        CommonArgs().parse_args(argv=[str(fake_bin), "--extension", str(fake_bin)])
    assert "error: Extension must be a folder or .xpi" in capsys.readouterr()[-1]


@mark.parametrize(
    "args, msg, targets",
    [
        # test no installed platforms
        ([], "error: No Platforms (Targets) are installed", []),
        # test invalid ignore value
        (["--ignore", "bad"], "error: Unrecognized ignore value 'bad'", ["targ1"]),
        # test invalid log level
        (["--log-level", "bad"], "error: Invalid log-level 'bad'", ["targ1"]),
        # test invalid log limit
        (["--log-limit", "-1"], "error: --log-limit must be >= 0", ["targ1"]),
        # test invalid memory limit
        (["--memory", "-1"], "error: --memory must be >= 0", ["targ1"]),
        # test invalid relaunch value
        (["--relaunch", "0"], "error: --relaunch must be >= 1", ["targ1"]),
        # test missing extension
        (["--extension", "missing"], "error: 'missing' does not exist", ["targ1"]),
        # test invalid platform/target
        (["--platform", "bad"], "error: Platform 'bad' not installed", ["targ1"]),
        # test invalid prefs file
        (
            ["--platform", "targ1", "--prefs", "bad"],
            "error: --prefs file not found",
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
        # test enabling both rr and Valgrind
        (
            ["--platform", "targ1", "--rr", "--valgrind"],
            "error: --rr and --valgrind are mutually exclusive",
            ["targ1"],
        ),
    ],
)
def test_common_args_02(capsys, mocker, tmp_path, args, msg, targets):
    """test CommonArgs.parse_args()"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=targets)
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    with raises(SystemExit):
        CommonArgs().parse_args(argv=[str(fake_bin)] + args)
    assert msg in capsys.readouterr()[-1]


def test_grizzly_args_01(mocker, tmp_path):
    """test GrizzlyArgs.parse_args() - success"""
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    mocker.patch(
        "grizzly.args.scan_plugins",
        autospec=True,
        side_effect=(["targ1"], ["adpt1"], ["targ1"], ["adpt1"]),
    )
    assert GrizzlyArgs().parse_args(
        argv=[str(fake_bin), "adpt1", "--platform", "targ1"]
    )


def test_grizzly_args_02(capsys, mocker):
    """test GrizzlyArgs.parse_args() - handling binary"""
    mocker.patch("grizzly.args.scan_plugins", autospec=True, return_value=["blah"])
    # test missing required args
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=[])
    err = capsys.readouterr()[-1]
    assert "the following arguments are required: binary, adapter" in err
    # test missing binary
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=["missing_bin", "adapter"])
    assert "error: file not found: 'missing_bin'" in capsys.readouterr()[-1]


def test_grizzly_args_03(capsys, mocker, tmp_path):
    """test GrizzlyArgs.parse_args() - handling Adapter"""
    scan_plugins = mocker.patch("grizzly.args.scan_plugins", autospec=True)
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    # no adapters installed
    scan_plugins.side_effect = (["targ1"], [], ["targ1"], [])
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=[str(fake_bin), "adpt", "--platform", "targ1"])
    assert "error: No Adapters are installed" in capsys.readouterr()[-1]
    # invalid adapter name
    scan_plugins.side_effect = (["targ1"], ["a1", "a2"], ["targ1"], ["a1", "a2"])
    with raises(SystemExit):
        GrizzlyArgs().parse_args(argv=[str(fake_bin), "missing", "--platform", "targ1"])
    assert "error: Adapter 'missing' is not installed" in capsys.readouterr()[-1]


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
        (["--limit", "-1"], "error: --limit must be >= 0 (0 = no limit)"),
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
        side_effect=["targ1", "adpt", "targ1", "adpt"],
    )
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    with raises(SystemExit):
        GrizzlyArgs().parse_args(
            argv=[str(fake_bin), "adpt", "--platform", "targ1"] + args
        )
    assert msg in capsys.readouterr()[-1]
