# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import DEBUG, INFO

from pytest import mark

from .storage import TestCase
from .utils import (
    DEFAULT_TIME_LIMIT,
    TIMEOUT_DELAY,
    configure_logging,
    grz_tmp,
    time_limits,
)


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


@mark.parametrize(
    "time_limit, timeout, test_durations, expected",
    [
        # use defaults
        (None, None, [None], (DEFAULT_TIME_LIMIT, DEFAULT_TIME_LIMIT + TIMEOUT_DELAY)),
        # use defaults instead of low test values
        (None, None, [1], (DEFAULT_TIME_LIMIT, DEFAULT_TIME_LIMIT + TIMEOUT_DELAY)),
        # use duration from test case
        (None, None, [99.1], (100, 100 + TIMEOUT_DELAY)),
        # multiple tests
        (None, None, [99.9, 10, 25], (100, 100 + TIMEOUT_DELAY)),
        # specify time limit
        (100, None, [0], (100, 100 + TIMEOUT_DELAY)),
        # specify timeout (> DEFAULT_TIME_LIMIT)
        (None, 100, [0], (DEFAULT_TIME_LIMIT, 100)),
        # specify timeout (< DEFAULT_TIME_LIMIT)
        (None, 10, [0], (10, 10)),
        # specify time limit and timeout
        (50, 100, [0], (50, 100)),
    ],
)
def test_time_limits_01(mocker, time_limit, timeout, test_durations, expected):
    """test time_limits()"""
    tests = [mocker.Mock(spec_set=TestCase, duration=d) for d in test_durations]
    assert time_limits(time_limit, timeout, tests=tests) == expected
