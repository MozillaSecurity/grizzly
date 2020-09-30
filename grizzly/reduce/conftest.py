# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""
common unit test fixtures for grizzly.reduce
"""

import pytest
from grizzly.common.reporter import FuzzManagerReporter


@pytest.fixture
def tmp_path_fm_config(tmp_path, mocker):
    """Ensure fm config is always read from tmp_path so ~/.fuzzmanagerconf
    can't be used by accident."""
    mocker.patch.object(
        FuzzManagerReporter,
        "FM_CONFIG",
        new=str(tmp_path / ".fuzzmanagerconf"),
    )
