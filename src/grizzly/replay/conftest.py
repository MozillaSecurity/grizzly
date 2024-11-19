# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Common unit test fixtures for `grizzly.replay`.
"""

from pathlib import Path

from pytest import fixture

from sapphire import Sapphire


@fixture
def server(mocker):
    """Mock Sapphire server"""
    srv = mocker.Mock(spec_set=Sapphire, port=1337, timeout=10)
    srv_cls = mocker.patch("grizzly.replay.replay.Sapphire", autospec=True)
    srv_cls.return_value.__enter__.return_value = srv
    return srv


@fixture
def tmp_path_grz_tmp(tmp_path, mocker):
    """Provide an alternate working directory for testing."""

    def _grz_tmp(*subdir):
        path = Path(tmp_path, "grizzly", *subdir)
        path.mkdir(parents=True, exist_ok=True)
        return path

    mocker.patch("grizzly.replay.replay.grz_tmp", _grz_tmp)
