# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Common unit test fixtures for `grizzly.reduce`.
"""

import pytest


@pytest.fixture
def tmp_path_fm_config(tmp_path, mocker):
    """Ensure fm config is always read from tmp_path so ~/.fuzzmanagerconf
    can't be used by accident.
    """
    mocker.patch(
        "grizzly.reduce.core.FuzzManagerReporter.FM_CONFIG",
        new=str(tmp_path / ".fuzzmanagerconf"),
    )
    (tmp_path / ".fuzzmanagerconf").touch()


@pytest.fixture
def reporter_sequential_strftime(mocker):
    """Make `strftime` in `FilesystemReporter` return sequential values.
    This ensures ever report gets a unique folder and won't overwrite another.
    """
    prefix = mocker.patch("grizzly.common.report.strftime")

    def report_prefix(_):
        return "%04d" % (prefix.call_count,)

    prefix.side_effect = report_prefix
