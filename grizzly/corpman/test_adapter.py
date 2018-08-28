# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import shutil
import tempfile
import unittest

from .adapter import Adapter


class SimpleAdapter(Adapter):
    NAME = "simple"

    def generate(self, testcase, input_file, server_map):
        pass


class AdapterTests(unittest.TestCase):

    def test_01(self):
        "test a simple adapter"
        adpt = SimpleAdapter()
        self.assertTrue(isinstance(adpt.fuzz, dict))
        self.assertFalse(adpt.fuzz)
        self.assertIsNone(adpt.monitor)
        self.assertIsNone(adpt.get_harness())
        adpt.setup(None)
        adpt.generate(None, None, None)
        adpt.on_served(None, None)
        adpt.on_timeout(None, None)
        adpt.cleanup()


    def test_02(self):
        "test harnesses"
        tdir = tempfile.mkdtemp(prefix="adpt_tests")
        self.addCleanup(shutil.rmtree, tdir)
        _fd, h_file = tempfile.mkstemp(prefix="adpt_tst_")
        os.close(_fd)
        self.addCleanup(os.remove, h_file)
        adpt = SimpleAdapter()
        adpt.HARNESS_FILE = h_file

        test_data = b"fake_harness_data"
        with open(h_file, "wb") as h_fp:
            h_fp.write(test_data)
        self.assertIsNone(adpt.get_harness())
        adpt.enable_harness()
        harness = adpt.get_harness()
        self.assertIsNotNone(harness)
        harness.dump(tdir)
        self.assertIn("grizzly_fuzz_harness.html", os.listdir(tdir))
        with open(os.path.join(tdir, "grizzly_fuzz_harness.html"), "rb") as h_fp:
            self.assertEqual(h_fp.read(), test_data)
        os.remove(os.path.join(tdir, "grizzly_fuzz_harness.html"))

        test_data = b"fake_harness_2nd_pass"
        with open(h_file, "wb") as h_fp:
            h_fp.write(test_data)
        adpt.enable_harness(h_file)
        harness = adpt.get_harness()
        harness.dump(tdir)
        self.assertIsNotNone(harness)
        self.assertIn("grizzly_fuzz_harness.html", os.listdir(tdir))
        with open(os.path.join(tdir, "grizzly_fuzz_harness.html"), "rb") as h_fp:
            self.assertEqual(h_fp.read(), test_data)
