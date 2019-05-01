# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import tempfile
import unittest

from .adb_device import ADBSession
from .adb_target import ADBTarget
from .target import Target


class ADBTargetTests(unittest.TestCase):
    def setUp(self):
        bin_path = os.path.join(os.path.dirname(__file__), "adb_device")
        ADBSession.BIN_AAPT = os.path.join(bin_path, "fake_aapt.py")
        ADBSession.BIN_ADB = os.path.join(bin_path, "fake_adb.py")
        _fd, self.tmpfn = tempfile.mkstemp(prefix="grz_test_")
        os.close(_fd)

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test creating a simple ADBTarget"
        target = ADBTarget(self.tmpfn, None, 300, 25, 5000, None, 25)
        self.addCleanup(target.cleanup)
        self.assertTrue(target.closed)
        self.assertTrue(target.forced_close)
        self.assertIsNotNone(target.monitor)
        self.assertEqual(target.detect_failure([], None), Target.RESULT_NONE)
        self.assertEqual(target.log_size(), 0)
        target.check_relaunch()
