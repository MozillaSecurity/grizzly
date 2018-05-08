# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import sys
import tempfile
import unittest

from grizzly.status import Status

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class StatusTests(TestCase):
    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp(prefix="grz_test_")
        os.close(fd)

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test Status report()"
        status = Status(self.tmpfn)
        status.report()
        self.assertTrue(os.path.isfile(self.tmpfn))
        # write report when a previous report exists (update)
        status._last_report = 0
        status.report()
        self.assertTrue(os.path.isfile(self.tmpfn))
        os.remove(self.tmpfn)
        # verify report has not been written because report_freq has not elapsed
        status.report(report_freq=100)
        self.assertFalse(os.path.isfile(self.tmpfn))

    def test_02(self):
        "test Status cleanup()"
        status = Status(self.tmpfn)
        status.report()
        self.assertTrue(os.path.isfile(self.tmpfn))
        status.cleanup()
        self.assertFalse(os.path.isfile(self.tmpfn))

    def test_03(self):
        "test Status load()"
        self.assertIsNone(Status.load("no_file.json"))
        self.assertIsNone(Status.load(self.tmpfn))
        status = Status(self.tmpfn)
        self.assertIsNotNone(status)
        status.ignored = 1
        status.iteration = 10
        status.log_size = 1
        status.results = 2
        status.report()
        ld_status = Status.load(self.tmpfn)
        self.addCleanup(ld_status.cleanup)
        self.assertEqual(ld_status.ignored, 1)
        self.assertEqual(ld_status.iteration, 10)
        self.assertEqual(ld_status.log_size, 1)
        self.assertEqual(ld_status.results, 2)
