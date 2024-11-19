# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from importlib.metadata import PackageNotFoundError
from logging import DEBUG, INFO

from pytest import mark

from .storage import TestCase
from .utils import (
    DEFAULT_TIME_LIMIT,
    TIMEOUT_DELAY,
    configure_logging,
    display_time_limits,
    grz_tmp,
    package_version,
    time_limits,
)


def test_grz_tmp_01(mocker, tmp_path):
    """test grz_tmp()"""
    fake_tmp = tmp_path / "grizzly"
    mocker.patch("grizzly.common.utils.GRZ_TMP", fake_tmp)
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
        (None, None, [90.1], (100, 100 + TIMEOUT_DELAY)),
        # multiple tests
        (None, None, [90.9, 10, 25], (100, 100 + TIMEOUT_DELAY)),
        # specify time limit
        (100, None, [0], (100, 100 + TIMEOUT_DELAY)),
        # specify timeout (> DEFAULT_TIME_LIMIT)
        (None, 100, [0], (DEFAULT_TIME_LIMIT, 100)),
        # specify timeout (< DEFAULT_TIME_LIMIT)
        (None, 10, [0], (10, 10)),
        # specify time limit and timeout
        (50, 100, [0], (50, 100)),
        # timeout disabled - use default time limit
        (None, 0, [None], (DEFAULT_TIME_LIMIT, 0)),
        # timeout disabled - with time limit
        (15, 0, [None], (15, 0)),
    ],
)
def test_time_limits_01(mocker, time_limit, timeout, test_durations, expected):
    """test time_limits()"""
    tests = [mocker.Mock(spec_set=TestCase, duration=d) for d in test_durations]
    assert time_limits(time_limit, timeout, tests=tests) == expected


@mark.parametrize(
    "time_limit, timeout, no_harness, msg",
    [
        # typical - harness
        (1, 2, False, "Using time limit: 1s, timeout: 2s"),
        # typical - without harness
        (1, 2, True, "Using timeout: 2s, harness: DISABLED"),
        # warn time limit and timeout match - harness
        (1, 1, False, "To avoid unnecessary relaunches set timeout > time limit"),
        # disabled timeout - harness
        (1, 0, False, "Using time limit: 1s, timeout: DISABLED"),
        # disable timeout - without harness
        (1, 0, True, "Using timeout: DISABLED, harness: DISABLED"),
    ],
)
def test_display_time_limits_01(caplog, time_limit, timeout, no_harness, msg):
    """test display_time_limits()"""
    display_time_limits(time_limit, timeout, no_harness)
    assert msg in caplog.text


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
