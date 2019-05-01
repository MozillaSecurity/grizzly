# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import tempfile
import unittest

from .target_monitor import TargetMonitor


class TargetMonitorTests(unittest.TestCase):

    def test_01(self):
        "test a basic monitor"
        class _BasicMonitor(TargetMonitor):
            # pylint: disable=no-self-argument,protected-access
            def clone_log(_, log_id, offset=0):
                tmp_fd, log_file = tempfile.mkstemp(
                    suffix="_log.txt",
                    prefix="test_")
                os.close(tmp_fd)
                with open(log_file, "wb") as log_fp:
                    log_fp.write(b"test")
                return log_file
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
        self.addCleanup(os.remove, test_log)
        self.assertTrue(os.path.isfile(test_log))
        self.assertTrue(mon.is_healthy())
        self.assertTrue(mon.is_running())
        self.assertEqual(mon.launches, 1)
        self.assertEqual(mon.log_data("test_log"), b"test")
        self.assertEqual(mon.log_length("test_log"), 100)
