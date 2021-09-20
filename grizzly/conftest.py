# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Common unit test fixtures for `grizzly`.
"""

from pytest import fixture


@fixture
def tmp_path_status_db(tmp_path, mocker):
    """Use a temporary database file for testing."""
    mocker.patch("grizzly.session.Session.STATUS_DB", new=str(tmp_path / "tmp.db"))
