# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import random
import struct
import shutil
import sys
import tempfile
import unittest

from .loki import Loki

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class LokiTests(TestCase):

    def setUp(self):
        t_fd, self.tmpfn = tempfile.mkstemp(prefix="loki_")
        os.close(t_fd)
        self.tmpdir = tempfile.mkdtemp(prefix="loki_")


    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.unlink(self.tmpfn)
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)


    def test_01(self):
        "test a missing file"
        fuzzer = Loki(aggression=0.1, verbose=False)
        fuzzer.fuzz_file("nofile.test", 1, out_dir=self.tmpdir)
        self.assertFalse(os.listdir(self.tmpdir))


    def test_02(self):
        "test an empty file"
        fuzzer = Loki(aggression=0.1, verbose=False)
        fuzzer.fuzz_file(self.tmpfn, 1, out_dir=self.tmpdir)
        self.assertFalse(os.listdir(self.tmpdir))


    def test_03(self):
        "test a single byte file"
        in_data = b"A"
        with open(self.tmpfn, "wb") as out_fp:
            out_fp.write(in_data)

        fuzzer = Loki(aggression=0.1, verbose=False)
        for _ in range(100):
            fuzzer.fuzz_file(self.tmpfn, 1, out_dir=self.tmpdir)
            out_files = os.listdir(self.tmpdir)
            self.assertEqual(len(out_files), 1)
            with open(os.path.join(self.tmpdir, out_files[0]), "rb") as out_fp:
                out_data = out_fp.read()
            self.assertEqual(len(out_data), 1)
            if out_data != in_data:
                break
        self.assertNotEqual(out_data, in_data)


    def test_04(self):
        "test a two byte file"
        in_data = b"AB"
        with open(self.tmpfn, "wb") as out_fp:
            out_fp.write(in_data)

        fuzzer = Loki(aggression=0.1, verbose=False)
        for _ in range(100):
            fuzzer.fuzz_file(self.tmpfn, 1, out_dir=self.tmpdir)
            out_files = os.listdir(self.tmpdir)
            self.assertEqual(len(out_files), 1)
            with open(os.path.join(self.tmpdir, out_files[0]), "rb") as out_fp:
                out_data = out_fp.read()
            self.assertEqual(len(out_data), 2)
            if out_data != in_data:
                break
        self.assertNotEqual(out_data, in_data)


    def test_05(self):
        "test a multi byte file"
        in_size = 100
        in_byte = b"A"
        in_data = in_byte * in_size
        fuzz_found = False
        with open(self.tmpfn, "wb") as out_fp:
            out_fp.write(in_data)

        fuzzer = Loki(aggression=0.01, verbose=False)
        for _ in range(100):
            fuzzer.fuzz_file(self.tmpfn, 1, out_dir=self.tmpdir)
            out_files = os.listdir(self.tmpdir)
            self.assertEqual(len(out_files), 1)
            with open(os.path.join(self.tmpdir, out_files[0]), "rb") as out_fp:
                out_fp.seek(0, os.SEEK_END)
                self.assertEqual(out_fp.tell(), in_size)
                out_fp.seek(0)
                for out_byte in out_fp:
                    if out_byte != in_byte:
                        fuzz_found = True
                        break
            if fuzz_found:
                break
        self.assertTrue(fuzz_found)


    def test_06(self):
        "test fuzz_data()"
        in_data = b"This is test DATA!"
        in_size = len(in_data)

        fuzz_found = False
        fuzzer = Loki(aggression=0.1, verbose=False)
        for _ in range(100):
            out_data = fuzzer.fuzz_data(in_data)
            self.assertEqual(len(out_data), in_size)
            if in_data not in out_data:
                fuzz_found = True
                break
        self.assertTrue(fuzz_found)


    def test_07(self):
        "test invalid data sizes"
        with self.assertRaisesRegex(RuntimeError, r"Unsupported data size:"):
            Loki._fuzz_data(b"")  # pylint: disable=protected-access

        with self.assertRaisesRegex(RuntimeError, r"Unsupported data size:"):
            Loki._fuzz_data(b"123")  # pylint: disable=protected-access

        with self.assertRaisesRegex(RuntimeError, r"Unsupported data size:"):
            Loki._fuzz_data(b"12345")  # pylint: disable=protected-access


    def test_08(self):
        "test endian support"
        Loki._fuzz_data(b"1", ">")  # pylint: disable=protected-access
        Loki._fuzz_data(b"1", "<")  # pylint: disable=protected-access
        with self.assertRaisesRegex(RuntimeError, r"Unsupported byte order"):
            Loki._fuzz_data(b"1", "BAD")  # pylint: disable=protected-access


class LokiStressTests(TestCase):
    def test_01(self):
        "test with single byte"
        for _ in range(1000):
            in_data = struct.pack("B", random.getrandbits(8))
            self.assertEqual(len(Loki._fuzz_data(in_data)), 1)  # pylint: disable=protected-access


    def test_02(self):
        "test with two bytes"
        in_data = b"\xff\xff"
        for _ in range(1000):
            self.assertEqual(len(Loki._fuzz_data(in_data)), 2)  # pylint: disable=protected-access


    def test_03(self):
        "test with four bytes"
        in_data = b"TEST"
        for _ in range(1000):
            self.assertEqual(len(Loki._fuzz_data(in_data)), 4)  # pylint: disable=protected-access
