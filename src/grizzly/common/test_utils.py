# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from importlib.metadata import PackageNotFoundError

from pytest import mark

from .utils import grz_tmp, package_version


def test_grz_tmp_01(mocker, tmp_path):
    """test grz_tmp()"""
    fake_tmp = tmp_path / "grizzly"
    mocker.patch("grizzly.common.utils.GRZ_TMP", new=fake_tmp)
    # create temp path
    assert not fake_tmp.is_dir()
    path = grz_tmp()
    assert path == fake_tmp
    assert path.is_dir()
    # create temp path (exists)
    assert grz_tmp() == fake_tmp
    # create temp path with sub directory
    path = grz_tmp("test1", "test2")
    assert path == fake_tmp / "test1" / "test2"
    assert path.is_dir()


@mark.parametrize(
    "version, expected",
    [
        # missing package
        (PackageNotFoundError(), "unknown"),
        # success
        (("1.2.3",), "1.2.3"),
    ],
)
def test_package_version_01(mocker, version, expected):
    """test package_version()"""
    mocker.patch("grizzly.common.utils.version", autospec=True, side_effect=version)
    assert package_version("foo", default="unknown") == expected
