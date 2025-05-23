# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from .target_monitor import TargetMonitor


def test_target_monitor_01():
    """test a basic TargetMonitor"""

    class _BasicMonitor(TargetMonitor):
        def is_healthy(self):
            return True

        def is_idle(self, threshold):
            return False

        def is_running(self):
            return True

        @property
        def launches(self):
            return 1

        def log_length(self, log_id):
            return 100

    mon = _BasicMonitor()
    assert mon.is_healthy()
    assert not mon.is_idle(0)
    assert mon.is_running()
    assert mon.launches == 1
    assert mon.log_length("test_log") == 100
