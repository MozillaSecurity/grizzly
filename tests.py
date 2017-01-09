from __future__ import absolute_import
import logging
import os
import sys
import tempfile
import unittest


# initialize logging early so import logs are captured
logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)


from grizzly import grizzly
from grizzly.reduce import FeedbackIter


class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class GrizzlyTests(TestCase):

    def test_0(self):
        fd, fn = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fp:
            fp.write("test")
        try:
            with self.assertRaisesRegex(IOError, "is not an executable"):
                grizzly.main(grizzly.parse_args([fn, fn, 'embed']))
        finally:
            os.unlink(fn)
