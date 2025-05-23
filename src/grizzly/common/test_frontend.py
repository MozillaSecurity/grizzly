# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import DEBUG, INFO

from pytest import mark

from .frontend import (
    DEFAULT_TIME_LIMIT,
    TIMEOUT_DELAY,
    configure_logging,
    display_time_limits,
    get_certs,
    time_limits,
)
from .storage import TestCase


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
    config = mocker.patch("grizzly.common.frontend.basicConfig", autospec=True)
    mocker.patch("grizzly.common.frontend.getenv", autospec=True, return_value=env)
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


def test_get_certs(mocker, tmp_path):
    """test get_certs()"""
    (tmp_path / "grz_tmp").mkdir()
    mocker.patch("grizzly.common.frontend.grz_tmp", return_value=tmp_path / "grz_tmp")
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "host.pem").touch()
    (certs / "host.key").touch()
    (certs / "root.pem").touch()
    mocker.patch(
        "grizzly.common.frontend.add_cached", autospec=True, return_value=tmp_path
    )
    mocker.patch(
        "grizzly.common.frontend.find_cached", autospec=True, return_value=None
    )
    bundle = get_certs()
    assert bundle.root.is_file()
    assert bundle.host.is_file()
    assert bundle.key.is_file()
