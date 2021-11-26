# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Common unit test fixtures for `grizzly`.
"""

from pytest import fixture

from grizzly.common.status import ReductionStatus, Status


@fixture
def patch_collector(mocker):
    """Provide a mock Collector to avoid scanning for signatures on disk."""
    collector = mocker.patch("grizzly.common.report.Collector", autospec=True)
    # don't search for signatures locally
    collector.return_value.sigCacheDir = None


@fixture
def tmp_path_status_db(tmp_path, mocker):
    """Use a temporary database file for testing."""
    mocker.patch.object(Status, "STATUS_DB", new=str(tmp_path / "status-tmp.db"))


@fixture
def tmp_path_reduce_status_db(tmp_path, mocker):
    """Use a temporary database file for testing."""
    mocker.patch.object(
        ReductionStatus, "STATUS_DB", new=str(tmp_path / "reduce-tmp.db")
    )


@fixture
def tmp_path_replay_status_db(tmp_path, mocker):
    """Use a temporary database file for testing."""
    mocker.patch(
        "grizzly.replay.replay.ReplayManager.STATUS_DB",
        new=str(tmp_path / "replay-tmp.db"),
    )
