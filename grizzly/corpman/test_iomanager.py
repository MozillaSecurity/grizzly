# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import shutil
import tempfile
import unittest

from .iomanager import IOManager, ServerMap
from .storage import TestFile


class IOManagerTests(unittest.TestCase):
    def setUp(self):
        self.tdir = tempfile.mkdtemp(prefix="iom_tests")

    def tearDown(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def test_01(self):
        "test a simple IOManager"
        iom = IOManager()
        self.addCleanup(iom.cleanup)
        self.assertEqual(iom.size(), 0)
        self.assertIsNone(iom.active_input)  # pylint: disable=protected-access
        self.assertIsNotNone(iom.server_map)
        self.assertFalse(iom.input_files)
        self.assertFalse(iom._environ_files)  # pylint: disable=protected-access
        self.assertEqual(iom._generated, 0)  # pylint: disable=protected-access
        self.assertIsNone(iom._mime)  # pylint: disable=protected-access
        self.assertEqual(iom._report_size, 1)  # pylint: disable=protected-access

    def test_02(self):
        "test scan_input()"
        iom = IOManager()
        self.addCleanup(iom.cleanup)
        tempfile.mkdtemp(prefix="empty", dir=self.tdir)

        # pass empty directory path
        with self.assertRaises(IOError):
            iom.scan_input(self.tdir, None)

        # create a test corpus
        test_file = os.path.join(self.tdir, "input_test.bin")
        with open(test_file, "wb") as out_fp:
            out_fp.write(b"foo")
        with open(os.path.join(self.tdir, ".should_be_ignored"), "wb") as out_fp:
            out_fp.write(b"template_data")
        with open(os.path.join(self.tdir, "empty.BIN"), "wb") as out_fp:
            pass
        with open(os.path.join(self.tdir, "input_test.txt"), "wb") as out_fp:
            out_fp.write(b"bar")
        with open(os.path.join(self.tdir, "desktop.ini"), "wb") as out_fp:
            out_fp.write(b"also_ignored")
        nested = tempfile.mkdtemp(prefix="nested_", dir=self.tdir)
        with open(os.path.join(nested, "input_test.txt"), "wb") as out_fp:
            out_fp.write(b"test")

        # pass directory path
        iom.input_files = list()
        iom.scan_input(self.tdir, sort=True)
        self.assertEqual(iom.size(), 3)
        # pass directory path with filter
        iom.input_files = list()
        iom.scan_input(self.tdir, ["Bin"])
        self.assertEqual(iom.size(), 1)
        # pass file path
        iom.input_files = list()
        iom.scan_input(test_file)
        self.assertEqual(iom.size(), 1)

    def test_03(self):
        "test _rotation_required()"
        iom = IOManager()
        self.addCleanup(iom.cleanup)

        # don't pick a file because we don't have inputs
        self.assertFalse(iom._rotation_required(0))  # pylint: disable=protected-access
        self.assertFalse(iom._rotation_required(1))  # pylint: disable=protected-access

        tf = TestFile.from_data(b"data", "h.htm")
        self.addCleanup(tf.close)

        # create a test corpus
        test_file = os.path.join(self.tdir, "input_test.bin")
        with open(test_file, "wb") as out_fp:
            out_fp.write(b"foo")
        iom.scan_input(self.tdir)
        self.assertEqual(iom.size(), 1)
        # skip rotation because we only have one input file
        iom._generated = 1  # pylint: disable=protected-access
        iom.active_input = tf  # pylint: disable=protected-access
        self.assertFalse(iom._rotation_required(1))  # pylint: disable=protected-access

        with open(os.path.join(self.tdir, "input_test.txt"), "wb") as out_fp:
            out_fp.write(b"bar")
        iom.input_files = list()  # hack to enable rescan
        iom.scan_input(self.tdir)
        self.assertEqual(iom.size(), 2)

        # pick a file
        iom.active_input = None    # pylint: disable=protected-access
        self.assertTrue(iom._rotation_required(10))  # pylint: disable=protected-access
        # don't pick a file because of rotation
        iom._generated = 3  # pylint: disable=protected-access
        iom.active_input = tf  # pylint: disable=protected-access
        self.assertFalse(iom._rotation_required(10))  # pylint: disable=protected-access
        # pick a file because of rotation
        iom._generated = 2  # pylint: disable=protected-access
        iom.active_input = tf  # pylint: disable=protected-access
        self.assertTrue(iom._rotation_required(2))  # pylint: disable=protected-access
        # pick a file because of single pass
        iom._generated = 1  # pylint: disable=protected-access
        iom.active_input = tf  # pylint: disable=protected-access
        self.assertTrue(iom._rotation_required(0))  # pylint: disable=protected-access


    def test_04(self):
        "test page_name()"
        iom = IOManager()
        self.addCleanup(iom.cleanup)
        self.assertNotEqual(iom.page_name(), iom.page_name(offset=1))
        next_page = iom.page_name(offset=1)
        iom._generated += 1
        self.assertEqual(iom.page_name(), next_page)


    def test_05(self):
        "test landing_page()"
        iom = IOManager()
        self.addCleanup(iom.cleanup)
        self.assertEqual(iom.landing_page(), iom.page_name())
        iom.harness = TestFile.from_data(b"data", "h.htm")
        self.addCleanup(iom.harness.close)
        self.assertEqual(iom.landing_page(), "h.htm")

    def test_06(self):
        "test _add_suppressions()"
        supp_file = os.path.join(self.tdir, "supp_file.txt")
        with open(supp_file, "w") as out_fp:
            out_fp.write("# test\n")
        iom = IOManager()
        self.addCleanup(iom.cleanup)
        try:
            os.environ["ASAN_OPTIONS"] = "blah=1:suppressions=%s:foo=2" % supp_file
            self.assertFalse(iom._environ_files)  # pylint: disable=protected-access
            iom._add_suppressions()  # pylint: disable=protected-access
        finally:
            os.environ.pop("ASAN_OPTIONS", None)
        self.assertIn("asan.supp", [x.file_name for x in iom._environ_files])  # pylint: disable=protected-access

    def test_07(self):
        "test create_testcase()"

        iom = IOManager()
        self.addCleanup(iom.cleanup)
        self.assertEqual(iom._generated, 0)  # pylint: disable=protected-access
        self.assertEqual(iom._report_size, 1)  # pylint: disable=protected-access
        self.assertFalse(iom.tests)

        # without a harness
        tc = iom.create_testcase("test-adapter", rotation_period=1)
        self.assertIsNotNone(tc)
        self.addCleanup(tc.cleanup)
        self.assertEqual(iom._generated, 1)  # pylint: disable=protected-access
        self.assertEqual(len(iom.tests), 1)
        self.assertFalse(tc.get_optional())  # pylint: disable=protected-access

        # with a harness
        iom.harness = TestFile.from_data(b"data", "h.htm")
        self.addCleanup(iom.harness.close)
        tc = iom.create_testcase("test-adapter", rotation_period=3)
        self.assertIsNotNone(tc)
        self.addCleanup(tc.cleanup)
        self.assertEqual(len(iom.tests), 1)
        self.assertEqual(iom._generated, 2)  # pylint: disable=protected-access
        self.assertIn("h.htm", tc.get_optional())  # pylint: disable=protected-access
        tc.cleanup()

    def test_08(self):
        "test tracked_environ()"
        try:
            org_tracked = IOManager.TRACKED_ENVVARS
            IOManager.TRACKED_ENVVARS = ()
            os.environ["ASAN_OPTIONS"] = "blah=1:detect_leaks=1:foo=2"
            os.environ["TEST_GOOD"] = "PASS"
            os.environ["TEST_BAD"] = "FAIL"
            self.assertFalse(IOManager.tracked_environ())
            IOManager.TRACKED_ENVVARS = ("ASAN_OPTIONS", "TEST_GOOD")
            tracked = IOManager.tracked_environ()
            self.assertIn("ASAN_OPTIONS", tracked)
            self.assertEqual(tracked["ASAN_OPTIONS"], "detect_leaks=1")
            self.assertIn("TEST_GOOD", tracked)
            self.assertEqual(tracked["TEST_GOOD"], "PASS")
        finally:
            IOManager.TRACKED_ENVVARS = org_tracked
            os.environ.pop("ASAN_OPTIONS", None)
            os.environ.pop("TEST_GOOD", None)
            os.environ.pop("TEST_BAD", None)


class TestServerMap(unittest.TestCase):

    def test_01(self):
        "test empty ServerMap"
        srv_map = ServerMap()
        self.assertFalse(srv_map.dynamic_responses)
        self.assertFalse(srv_map.includes)
        self.assertFalse(srv_map.redirects)
        with self.assertRaisesRegexp(AssertionError, "At least one kwarg should be True"):
            srv_map.reset()

    def test_02(self):
        "test ServerMap dynamic responses"
        def test_cb():
            pass
        srv_map = ServerMap()
        srv_map.set_dynamic_response("test_url", test_cb, mime_type="test/type")
        self.assertEqual(srv_map.dynamic_responses[0]["url"], "test_url")
        self.assertEqual(srv_map.dynamic_responses[0]["mime"], "test/type")
        self.assertTrue(callable(srv_map.dynamic_responses[0]["callback"]))
        srv_map.reset(dynamic_response=True)
        self.assertFalse(srv_map.dynamic_responses)

    def test_03(self):
        "test ServerMap includes"
        srv_map = ServerMap()
        with self.assertRaisesRegexp(IOError, "'no_dir' does not exist"):
            srv_map.set_include("test_url", "no_dir")
        self.assertFalse(srv_map.includes)
        tdir = tempfile.mkdtemp(prefix="iom_tests")
        self.addCleanup(shutil.rmtree, tdir)
        srv_map.set_include("test_url", tdir)
        self.assertEqual(srv_map.includes[0][0], "test_url")
        self.assertEqual(srv_map.includes[0][1], tdir)
        srv_map.reset(include=True)
        self.assertFalse(srv_map.includes)

    def test_04(self):
        "test ServerMap redirects"
        srv_map = ServerMap()
        srv_map.set_redirect("test_url", "test_file", required=True)
        self.assertEqual(srv_map.redirects[0]["url"], "test_url")
        self.assertEqual(srv_map.redirects[0]["file_name"], "test_file")
        self.assertTrue(srv_map.redirects[0]["required"])
        srv_map.reset(redirect=True)
        self.assertFalse(srv_map.redirects)
