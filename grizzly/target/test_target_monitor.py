# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os

from .target_monitor import TargetMonitor


def test_target_monitor_01(tmp_path):
    """test a basic TargetMonitor"""

    class _BasicMonitor(TargetMonitor):
        # pylint: disable=no-self-argument
        def clone_log(_, log_id, offset=0):
            log_file = tmp_path / "test_log.txt"
            log_file.write_bytes(b"test")
            return str(log_file)

        def is_healthy(_):
            return True

        def is_running(_):
            return True

        @property
        def launches(_):
            return 1

        def log_length(_, log_id):
            return 100

    mon = _BasicMonitor()
    test_log = mon.clone_log("test_log", offset=0)
    assert os.path.isfile(test_log)
    assert mon.is_healthy()
    assert mon.is_running()
    assert mon.launches == 1
    assert mon.log_data("test_log") == b"test"
    assert mon.log_length("test_log") == 100
