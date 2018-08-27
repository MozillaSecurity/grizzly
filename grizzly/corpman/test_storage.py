# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import shutil
import tempfile
import unittest

from .storage import InputFile, TestCase, TestFile


class TestCaseTests(unittest.TestCase):
    def setUp(self):
        self.tdir = tempfile.mkdtemp(prefix="tc_tests")

    def tearDown(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def test_01(self):
        "test empty TestCase"
        l_page = "land.html"
        r_page = "redirect.html"
        adpt_name = "test-adapter"
        tc = TestCase(l_page, r_page, adpt_name)
        self.addCleanup(tc.cleanup)
        self.assertEqual(tc.landing_page, l_page)
        self.assertEqual(tc.redirect_page, r_page)
        self.assertEqual(tc.adapter_name, adpt_name)
        self.assertIsNone(tc.input_fname)
        self.assertFalse(tc._files["meta"])  # pylint: disable=protected-access
        self.assertFalse(tc._files["optional"])  # pylint: disable=protected-access
        self.assertFalse(tc._files["required"])  # pylint: disable=protected-access
        self.assertFalse(tc._env_vars)  # pylint: disable=protected-access
        self.assertIsNone(tc._started)  # pylint: disable=protected-access
        self.assertFalse(tc.get_optional())
        tc.dump(self.tdir)
        self.assertFalse(os.listdir(self.tdir))
        tc.dump(self.tdir, include_details=True)
        self.assertIn("test_info.txt", os.listdir(self.tdir))

    def test_02(self):
        "test TestCase with TestFiles"
        tf1 = TestFile.from_data("test_req", "testfile1.bin")
        tf2 = TestFile.from_data("test_nreq", os.path.join("test_dir", "testfile2.bin"))
        tf3 = TestFile.from_data("test_blah", "/testfile3.bin")
        tc = TestCase("land_page.html", "redirect.html", "test-adapter", input_fname="testinput.bin")
        self.addCleanup(tc.cleanup)
        tc.add_file(tf1)
        tc.add_file(tf2, required=False)
        tc.add_file(tf3)
        opt_files = tc.get_optional()
        self.assertEqual(len(opt_files), 1)
        self.assertIn("test_dir/testfile2.bin", opt_files)
        tc.dump(self.tdir, include_details=True)
        self.assertTrue(os.path.isdir(os.path.join(self.tdir, "test_dir")))
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "test_info.txt")))
        with open(os.path.join(self.tdir, "test_info.txt"), "r") as test_fp:
            self.assertIn("testinput.bin", test_fp.read())
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "testfile1.bin")))
        with open(os.path.join(self.tdir, "testfile1.bin"), "r") as test_fp:
            self.assertEqual(test_fp.read(), "test_req")
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "test_dir", "testfile2.bin")))
        with open(os.path.join(self.tdir, "test_dir", "testfile2.bin"), "r") as test_fp:
            self.assertEqual(test_fp.read(), "test_nreq")
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "testfile3.bin")))
        with open(os.path.join(self.tdir, "testfile3.bin"), "r") as test_fp:
            self.assertEqual(test_fp.read(), "test_blah")

    def test_03(self):
        "test TestCase add_meta()"
        tc = TestCase("land_page.html", "redirect.html", "test-adapter")
        self.addCleanup(tc.cleanup)
        meta_data = b"foobar"
        meta_file = "metafile.bin"
        tc.add_meta(TestFile.from_data(meta_data, meta_file))
        dmp_dir = os.path.join(self.tdir, "dmp_test")
        os.mkdir(dmp_dir)
        tc.dump(dmp_dir, include_details=True)
        dmp_contents = os.listdir(dmp_dir)
        self.assertIn(meta_file, dmp_contents)
        with open(os.path.join(dmp_dir, meta_file), "rb") as test_fp:
            self.assertEqual(test_fp.read(), meta_data)

    def test_04(self):
        "test TestCase add_environ_var()"
        tc = TestCase("land_page.html", "redirect.html", "test-adapter")
        self.addCleanup(tc.cleanup)
        tc.add_environ_var("TEST_ENV_VAR", "1")
        dmp_dir = os.path.join(self.tdir, "dmp_test")
        os.mkdir(dmp_dir)
        tc.dump(dmp_dir, include_details=True)
        dmp_contents = os.listdir(dmp_dir)
        self.assertIn("env_vars.txt", dmp_contents)
        with open(os.path.join(dmp_dir, "env_vars.txt"), "r") as test_fp:
            self.assertIn("TEST_ENV_VAR=1\n", test_fp.read())


class InputFileTests(unittest.TestCase):
    def setUp(self):
        self.tdir = tempfile.mkdtemp(prefix="if_tests")

    def tearDown(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def test_01(self):
        "test InputFile object"
        # non-existing file
        with self.assertRaises(IOError):
            InputFile(os.path.join("foo", "bar", "none"))
        # existing file
        t_file = os.path.join(self.tdir, "testfile.bin")
        with open(t_file, "w") as test_fp:
            test_fp.write("test")
        in_file = InputFile(t_file)
        self.addCleanup(in_file.close)
        self.assertEqual(in_file.extension, "bin")
        self.assertEqual(in_file.file_name, t_file)
        self.assertIsNone(in_file._fp)  # pylint: disable=protected-access
        self.assertEqual(in_file.get_data(), b"test")
        self.assertIsNotNone(in_file._fp)  # pylint: disable=protected-access
        in_file.close()
        self.assertIsNone(in_file._fp)  # pylint: disable=protected-access
        self.assertEqual(in_file.get_fp().read(), b"test")
        self.assertIsNotNone(in_file._fp)  # pylint: disable=protected-access
        in_file.close()


class TestFileTests(unittest.TestCase):
    def setUp(self):
        self.tdir = tempfile.mkdtemp(prefix="tf_tests")

    def tearDown(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def test_01(self):
        "test simple TestFile"
        tf = TestFile("test_file.txt")
        self.addCleanup(tf.close)

        self.assertEqual(tf.file_name, "test_file.txt")
        self.assertFalse(tf._fp.closed)  # pylint: disable=protected-access
        tf.close()
        self.assertTrue(tf._fp.closed)  # pylint: disable=protected-access

    def test_02(self):
        "test write() and dump()"
        tf = TestFile("test_file.txt")
        self.addCleanup(tf.close)

        out_file = os.path.join(self.tdir, "test_file.txt")
        tf.write(b"foo")
        self.assertFalse(os.path.isfile(out_file))
        tf.dump(self.tdir)
        self.assertTrue(os.path.isfile(out_file))
        with open(out_file, "r") as in_fp:
            self.assertEqual(in_fp.read(), "foo")
        tf.write(b"bar")
        tf.dump(self.tdir)
        with open(out_file, "r") as in_fp:
            self.assertEqual(in_fp.read(), "foobar")

    def test_03(self):
        "test dump() file with nested path"
        file_path = "test/dir/path/file.txt"
        tf = TestFile(file_path)
        self.addCleanup(tf.close)

        out_file = os.path.join(self.tdir, file_path)
        tf.write(b"foo")
        self.assertFalse(os.path.isfile(out_file))
        tf.dump(self.tdir)
        self.assertTrue(os.path.isfile(out_file))

    def test_04(self):
        "test from_data()"
        # TODO: different encodings
        tf = TestFile.from_data("foo", "test_file.txt")
        self.addCleanup(tf.close)

        out_file = os.path.join(self.tdir, "test_file.txt")
        tf.dump(self.tdir)
        self.assertTrue(os.path.isfile(out_file))
        with open(out_file, "r") as in_fp:
            self.assertEqual(in_fp.read(), "foo")

    def test_05(self):
        "test from_file()"
        in_fp = tempfile.NamedTemporaryFile()
        self.addCleanup(in_fp.close)
        in_fp.write(b"foobar")
        in_fp.flush()
        tf = TestFile.from_file(in_fp.name, "test_file.txt")
        self.addCleanup(tf.close)

        out_file = os.path.join(self.tdir, "test_file.txt")
        tf.dump(self.tdir)
        self.assertTrue(os.path.isfile(out_file))
        with open(out_file, "r") as in_fp:
            self.assertEqual(in_fp.read(), "foobar")

    def test_06(self):
        "test clone()"
        tf1 = TestFile("test_file.txt")
        self.addCleanup(tf1.close)

        tf1.write(b"foobar")
        tf2 = tf1.clone()
        tf2.write(b"test")
        self.addCleanup(tf1.close)

        self.assertEqual(tf1.file_name, tf2.file_name)
        self.assertNotEqual(tf1._fp, tf2._fp)  # pylint: disable=protected-access

        out_file = os.path.join(self.tdir, "test_file.txt")
        tf1.dump(self.tdir)
        self.assertTrue(os.path.isfile(out_file))
        with open(out_file, "r") as in_fp:
            self.assertEqual(in_fp.read(), "foobar")

        tf2.dump(self.tdir)
        self.assertTrue(os.path.isfile(out_file))
        with open(out_file, "r") as in_fp:
            self.assertEqual(in_fp.read(), "foobartest")
