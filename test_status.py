import os
import sys
import tempfile
import unittest

from status import GrizzlyStatus

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class GrizzlyStatusTests(TestCase):
    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp(prefix="grz_test_")
        os.close(fd)

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test GrizzlyStatus report()"
        status = GrizzlyStatus(self.tmpfn)
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
        "test GrizzlyStatus clean_up()"
        status = GrizzlyStatus(self.tmpfn)
        status.report()
        self.assertTrue(os.path.isfile(self.tmpfn))
        status.clean_up()
        self.assertFalse(os.path.isfile(self.tmpfn))

    def test_03(self):
        "test GrizzlyStatus load()"
        self.assertIsNone(GrizzlyStatus.load("no_file.json"))
        self.assertIsNone(GrizzlyStatus.load(self.tmpfn))
        status = GrizzlyStatus(self.tmpfn)
        self.assertIsNotNone(status)
        status.ignored = 1
        status.iteration = 10
        status.log_size = 1
        status.results = 2
        status.report()
        ld_status = GrizzlyStatus.load(self.tmpfn)
        self.addCleanup(ld_status.clean_up)
        self.assertEqual(ld_status.ignored, 1)
        self.assertEqual(ld_status.iteration, 10)
        self.assertEqual(ld_status.log_size, 1)
        self.assertEqual(ld_status.results, 2)
