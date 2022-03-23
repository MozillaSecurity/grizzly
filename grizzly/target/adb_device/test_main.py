# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from pytest import mark, raises

from .main import main, parse_args


@mark.parametrize(
    "args, msg",
    [
        ([], "error: No options selected"),
        (["--install", "missing"], "error: Invalid APK 'missing'"),
        (["--launch", "missing"], "error: Invalid APK 'missing'"),
        (["--prep", "missing"], "error: Invalid APK 'missing'"),
    ],
)
def test_parse_01(capsys, args, msg):
    """test parse_args()"""
    with raises(SystemExit):
        parse_args(argv=args)
    assert msg in capsys.readouterr()[1]


def test_parse_02(tmp_path):
    """test parse_args()"""
    apk = tmp_path / "fake.apk"
    apk.touch()
    assert parse_args(argv=["--prep", str(apk)])


def test_main_01(mocker):
    """test main() - create session failed"""
    session_cls = mocker.patch(
        "grizzly.target.adb_device.main.ADBSession", autospec=True
    )
    session_cls.create.return_value = None
    args = mocker.Mock(ip=None, non_root=False, prep=None, port=12345)
    assert main(args) == 1


def test_main_02(mocker):
    """test main() - airplane mode"""
    session_cls = mocker.patch(
        "grizzly.target.adb_device.main.ADBSession", autospec=True
    )
    args = mocker.Mock(
        airplane_mode=1,
        launch=None,
        install=None,
        ip=None,
        non_root=False,
        prep=None,
        port=12345,
    )
    assert main(args) == 0
    assert session_cls.create.call_count == 1
    session_obj = session_cls.create.return_value
    assert session_obj.airplane_mode == 1
    assert session_obj.disconnect.call_count == 1


@mark.parametrize(
    "pkg, install, result",
    [
        # success
        ("test", "test", 0),
        # bad apk, failed to lookup name
        (None, None, 1),
        # install failed
        ("test", None, 1),
    ],
)
def test_main_03(mocker, tmp_path, pkg, install, result):
    """test main() - install"""
    session_cls = mocker.patch(
        "grizzly.target.adb_device.main.ADBSession", autospec=True
    )
    session_cls.get_package_name.return_value = pkg
    session_obj = session_cls.create.return_value
    session_obj.install.return_value = install
    apk = tmp_path / "fake.apk"
    (tmp_path / "llvm-symbolizer").touch()
    args = mocker.Mock(
        airplane_mode=None,
        launch=None,
        install=str(apk),
        ip=None,
        non_root=False,
        prep=None,
        port=12345,
    )
    assert main(args) == result
    assert session_cls.create.call_count == 1
    assert session_obj.install.call_count == (1 if pkg else 0)
    assert session_obj.install_file.call_count == (0 if result else 1)
    assert session_obj.disconnect.call_count == 1


@mark.parametrize(
    "pkg, result",
    [
        # success
        ("test", 0),
        # bad apk, failed to lookup name
        (None, 1),
    ],
)
def test_main_04(mocker, pkg, result):
    """test main() - launch"""
    mocker.patch("grizzly.target.adb_device.main.ADBProcess", autospec=True)
    session_cls = mocker.patch(
        "grizzly.target.adb_device.main.ADBSession", autospec=True
    )
    session_cls.get_package_name.return_value = pkg
    session_obj = session_cls.create.return_value
    args = mocker.Mock(
        airplane_mode=None,
        launch="fake.apk",
        install=None,
        ip=None,
        non_root=False,
        prep=None,
        port=12345,
    )
    assert main(args) == result
    assert session_cls.create.call_count == 1
    assert session_obj.disconnect.call_count == 1


def test_main_05(mocker):
    """test main() - prep"""
    session_cls = mocker.patch(
        "grizzly.target.adb_device.main.ADBSession", autospec=True
    )
    args = mocker.Mock(
        airplane_mode=None,
        launch=None,
        install=None,
        ip=None,
        non_root=False,
        prep="fake.apk",
        port=12345,
    )
    assert main(args) == 0
    assert session_cls.create.call_count == 1
    session_obj = session_cls.create.return_value
    assert session_obj.airplane_mode == 1
    assert session_obj.install.call_count == 1
    assert session_obj.disconnect.call_count == 1
