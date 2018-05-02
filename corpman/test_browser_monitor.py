import logging
import os
import tempfile
import unittest

from .browser_monitor import BrowserMonitor


logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("browser_mon_test")


class TestPuppet(object):
    running = False
    _launches = 0

    def clone_log(self, log_id, offset=0):
        assert log_id is not None
        tmp_fd, log_file = tempfile.mkstemp(
            suffix="_log.txt",
            prefix="test_")
        os.close(tmp_fd)
        with open(log_file, "wb") as log_fp:
            log_fp.write(b"test")
        return log_file

    @property
    def launches(self):
        return self._launches

    def is_running(self):
        return self.running

    def log_length(self, log_id):
        return 4


class BrowserMonitorTests(unittest.TestCase):

    def test_1(self):
        "test a basic browser monitor"
        bm = BrowserMonitor()
        tp = TestPuppet()
        bm.monitor_instance(tp)

        test_log = bm.clone_log("test_log", offset=0)
        self.addCleanup(os.remove, test_log)
        self.assertTrue(os.path.isfile(test_log))
        tp._launches += 1
        self.assertEqual(bm.launch_count(), 1)
        tp.running = True
        self.assertTrue(bm.is_running())
        self.assertEqual(bm.log_length("test_log"), 4)
        self.assertEqual(bm.log_data("test_log"), b"test")

    def test_2(self):
        "test an uninitialized browser monitor"
        bm = BrowserMonitor()
        self.assertIsNone(bm.clone_log("test_log", offset=0))
        self.assertEqual(bm.launch_count(), 0)
        self.assertFalse(bm.is_running())
        self.assertEqual(bm.log_length("test_log"), 0)
        self.assertIsNone(bm.log_data("test_log"))
