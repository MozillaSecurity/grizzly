# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import DEBUG, INFO

from pytest import mark

from .utils import configure_logging, grz_tmp


def test_grz_tmp_01(mocker, tmp_path):
    """test grz_tmp()"""
    mocker.patch(
        "grizzly.common.utils.gettempdir", autospec=True, return_value=str(tmp_path)
    )
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


@mark.parametrize(
    "env, log_level",
    [
        # default log level
        ("0", INFO),
        # debug log level
        ("0", DEBUG),
        # enable debug log level via env
        ("1", INFO),
        # enable debug log level via env
        ("TRUE", INFO),
    ],
)
def test_configure_logging_01(mocker, env, log_level):
    """test configure_logging()"""
    config = mocker.patch("grizzly.common.utils.basicConfig", autospec=True)
    mocker.patch("grizzly.common.utils.getenv", autospec=True, return_value=env)
    configure_logging(log_level)
    assert config.call_count == 1
    if env != "0":
        assert config.call_args[-1]["level"] == DEBUG
    else:
        assert config.call_args[-1]["level"] == log_level
