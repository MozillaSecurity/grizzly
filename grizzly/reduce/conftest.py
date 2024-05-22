# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Common unit test fixtures for `grizzly.reduce`.
"""

import pytest


@pytest.fixture
def reporter_sequential_strftime(mocker):
    """Make `strftime` in `FilesystemReporter` return sequential values.
    This ensures ever report gets a unique folder and won't overwrite another.
    """
    prefix = mocker.patch("grizzly.common.report.strftime")

    def report_prefix(_):
        return f"{prefix.call_count:04d}"

    prefix.side_effect = report_prefix
