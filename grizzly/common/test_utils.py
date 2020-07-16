# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .utils import grz_tmp

def test_testcase_01(mocker, tmp_path):
    """test grz_tmp()"""
    mocker.patch("grizzly.common.utils.gettempdir", autospec=True, return_value=str(tmp_path))
    # create temp path
    path = grz_tmp()
    assert path == str(tmp_path / "grizzly")
    assert (tmp_path / "grizzly").is_dir()
    # create temp path (exists)
    path = grz_tmp()
    assert path == str(tmp_path / "grizzly")
    # create temp path with sub directory
    path = grz_tmp("test1", "test2")
    assert path == str(tmp_path / "grizzly" / "test1" / "test2")
    assert (tmp_path / "grizzly" / "test1" / "test2").is_dir()
