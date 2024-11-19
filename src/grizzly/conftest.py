# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Common unit test fixtures for `grizzly`.
"""

from pytest import fixture

from .adapter import Adapter
from .target import Target


@fixture
def session_setup(mocker):
    mocker.patch("grizzly.main.FuzzManagerReporter", autospec=True)
    mocker.patch("grizzly.main.Sapphire", autospec_set=True)
    adapter_cls = mocker.Mock(spec_set=Adapter)
    adapter_cls.return_value.RELAUNCH = Adapter.RELAUNCH
    adapter_cls.return_value.TIME_LIMIT = Adapter.TIME_LIMIT
    target_cls = mocker.Mock(spec_set=Target)
    mocker.patch("grizzly.main.load_plugin", side_effect=(adapter_cls, target_cls))
    session_cls = mocker.patch("grizzly.main.Session", autospec_set=True)
    session_obj = session_cls.return_value.__enter__.return_value
    session_obj.status.results.total = 0
    yield adapter_cls.return_value, session_cls, session_obj, target_cls


@fixture
def patch_collector(mocker):
    """Provide a mock Collector to avoid scanning for signatures on disk."""
    collector = mocker.patch("grizzly.common.report.Collector", autospec=True)
    # don't search for signatures locally
    collector.return_value.sigCacheDir = None


@fixture
def tmp_path_status_db_fuzz(tmp_path, mocker):
    """Use a temporary status database file for testing."""
    mocker.patch("grizzly.common.status.STATUS_DB_FUZZ", tmp_path / "fuzzing-tmp.db")
    mocker.patch("grizzly.session.STATUS_DB_FUZZ", tmp_path / "fuzzing-tmp.db")


@fixture
def tmp_path_status_db_reduce(tmp_path, mocker):
    """Use a temporary status database file for testing."""
    mocker.patch("grizzly.common.status.STATUS_DB_REDUCE", tmp_path / "reduce-tmp.db")
    mocker.patch("grizzly.reduce.core.STATUS_DB_REDUCE", tmp_path / "fuzzing-tmp.db")
