import logging
import os
import random
import shutil
import sys
import tempfile
import unittest

from reporter import FilesystemReporter, Reporter

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("grz_report_test")

class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRegex(self, *args, **kwds):
            return self.assertRegexpMatches(*args, **kwds)

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class GrizzlyReporterTests(TestCase):
    def setUp(self):
        fd, self.tmpfn = tempfile.mkstemp(prefix="grz_test_")
        os.close(fd)
        self.tmpdir = tempfile.mkdtemp(prefix="grz_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test creating a simple Reporter"
        reporter = Reporter()
        self.assertEqual(reporter.log_limit, 0)
        with self.assertRaisesRegexp(IOError, "No such directory 'fake_dir'"):
            reporter.report("fake_dir", [])

        reporter = Reporter(1024)
        self.assertEqual(reporter.log_limit, 1024)
        with self.assertRaisesRegexp(IOError, "No logs found in"):
            reporter.report(self.tmpdir, [])

        test_log = os.path.join(self.tmpdir, "test.log.txt")
        with open(test_log, "w") as log_fp:
            log_fp.write("test log...\n123\n\n")
        reporter = Reporter()
        with self.assertRaisesRegexp(NotImplementedError, "_report must be implemented in the subclass"):
            reporter.report(self.tmpdir, [])

    def test_02(self):
        "test Reporter.tail()"
        with open(self.tmpfn, "wb") as test_fp:
            test_fp.write(b"blah\ntest\n123\xEF\x00FOO")
            length = test_fp.tell()
        # no size limit
        self.assertEqual(os.stat(self.tmpfn).st_size, length)
        with self.assertRaises(AssertionError):
            Reporter.tail(self.tmpfn, 0)
        self.assertEqual(os.stat(self.tmpfn).st_size, length)
        Reporter.tail(self.tmpfn, 3)
        with open(self.tmpfn, "rb") as test_fp:
            log_data = test_fp.read()
        self.assertTrue(log_data.startswith(b"[LOG TAILED]\n"))
        self.assertEqual(log_data[13:], b"FOO")

    def test_03(self):
        "test Reporter.select_logs()"
        asan_prefix = "log_asan.txt"
        test_logs = list()
        for _ in range(3):
            test_logs.append(".".join([asan_prefix, str(random.randint(1000, 4000))]))
        # small log with nothing interesting
        with open(os.path.join(self.tmpdir, test_logs[0]), "w") as log_fp:
            log_fp.write("SHORT LOG\n")
            log_fp.write("filler line")
        # crash on another thread
        with open(os.path.join(self.tmpdir, test_logs[1]), "w") as log_fp:
            log_fp.write("GOOD LOG\n")
            log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x00000BADF00D")
            log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        # child log that should be ignored (created when parent crashes)
        with open(os.path.join(self.tmpdir, test_logs[2]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000")
            log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        with open(os.path.join(self.tmpdir, "log_mindump_blah.txt"), "w") as log_fp:
            log_fp.write("minidump log")
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        # should be ignored in favor of "GOOD LOG"
        with open(os.path.join(self.tmpdir, "log_ffp_worker_blah.txt"), "w") as log_fp:
            log_fp.write("worker log")
        log_map = Reporter.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("GOOD LOG", log_fp.read())
        with open(os.path.join(self.tmpdir, log_map["stderr"]), "r") as log_fp:
            self.assertIn("STDERR", log_fp.read())
        with open(os.path.join(self.tmpdir, log_map["stdout"]), "r") as log_fp:
            self.assertIn("STDOUT", log_fp.read())

    def test_04(self):
        "test Reporter._process_logs() with boring files (no stack)"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        reporter = Reporter()
        reporter._log_path = self.tmpdir  # pylint: disable=protected-access
        reporter._process_logs()  # pylint: disable=protected-access
        self.assertIsNone(reporter._map["aux"])  # pylint: disable=protected-access
        self.assertEqual(Reporter.DEFAULT_MAJOR, reporter._major)  # pylint: disable=protected-access
        self.assertEqual(Reporter.DEFAULT_MINOR, reporter._minor)  # pylint: disable=protected-access

    def test_05(self):
        "test Reporter._process_logs()"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(self.tmpdir, "log_asan_blah.txt"), "w") as log_fp:
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19")
        reporter = Reporter()
        reporter._log_path = self.tmpdir  # pylint: disable=protected-access
        reporter._process_logs()  # pylint: disable=protected-access
        self.assertNotEqual(Reporter.DEFAULT_MAJOR, reporter._major)  # pylint: disable=protected-access
        self.assertNotEqual(Reporter.DEFAULT_MINOR, reporter._minor)  # pylint: disable=protected-access

    def test_06(self):
        "test FilesystemReporter without testcases"
        logs = tempfile.mkdtemp(prefix="tst_logs", dir=self.tmpdir)
        with open(os.path.join(logs, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(logs, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(logs, "log_asan_blah.txt"), "w") as log_fp:
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19")
        report_dir = tempfile.mkdtemp(prefix="grz_fs_reporter", dir=self.tmpdir)
        reporter = FilesystemReporter(report_path=report_dir)
        reporter.report(logs, [])

    def test_07(self):
        "test FilesystemReporter with testcases"
        class DummyTest(object):
            def __init__(self):
                self.dump_called = False
            def dump(self, log_dir, include_details=False):  # pylint: disable=unused-argument
                assert not self.dump_called
                self.dump_called = True

        logs = tempfile.mkdtemp(prefix="tst_logs", dir=self.tmpdir)
        # write logs
        with open(os.path.join(logs, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(logs, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(logs, "log_asan_blah.txt"), "w") as log_fp:
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19")
        testcases = list()
        for _ in range(10):
            testcases.append(DummyTest())
        report_dir = tempfile.mkdtemp(prefix="grz_fs_reporter", dir=self.tmpdir)
        reporter = FilesystemReporter(report_path=report_dir)
        reporter.report(logs, testcases)
        # call report a 2nd time
        logs = tempfile.mkdtemp(prefix="tst_logs", dir=self.tmpdir)
        with open(os.path.join(logs, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(logs, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        testcases = list()
        for tc in testcases:
            self.assertTrue(tc.dump_called)
        for _ in range(10):
            testcases.append(DummyTest())
        reporter.report(logs, testcases)

    def test_08(self):
        "test selecting minidump"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(self.tmpdir, "log_ffp_worker_blah.txt"), "w") as log_fp:
            log_fp.write("worker log")
        with open(os.path.join(self.tmpdir, "log_minidump_01.txt"), "w") as log_fp:
            log_fp.write("GPU|||\n")
            log_fp.write("Crash|SIGSEGV|0x0|0\n")
            log_fp.write("minidump log\n")
        log_map = Reporter.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("minidump log", log_fp.read())

    def test_09(self):
        "test selecting preferred DUMP_REQUESTED minidump"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(self.tmpdir, "log_minidump_01.txt"), "w") as log_fp:
            log_fp.write("GPU|||\n")
            log_fp.write("Crash|DUMP_REQUESTED|0x7f9518665d18|0\n")
            log_fp.write("0|0|bar.so|sadf|a.cc:739484451a63|3066|0x0\n")
            log_fp.write("0|1|gar.so|fdsa|b.cc:739484451a63|1644|0x12\n")
        with open(os.path.join(self.tmpdir, "log_minidump_02.txt"), "w") as log_fp:
            log_fp.write("GPU|||\n")
            log_fp.write("Crash|DUMP_REQUESTED|0x7f57ac9e2e14|0\n")
            log_fp.write("0|0|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|bar.cc:234|674|0xc\n")
            log_fp.write("0|1|foo.so|google_breakpad::ExceptionHandler::WriteMinidump|bar.cc:4a2|645|0x8\n")
        with open(os.path.join(self.tmpdir, "log_minidump_03.txt"), "w") as log_fp:
            log_fp.write("GPU|||\n")
            log_fp.write("Crash|DUMP_REQUESTED|0x7f9518665d18|0\n")
            log_fp.write("0|0|bar.so|sadf|a.cc:1234|3066|0x0\n")
            log_fp.write("0|1|gar.so|fdsa|b.cc:4323|1644|0x12\n")
        log_map = Reporter.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("google_breakpad::ExceptionHandler::WriteMinidump", log_fp.read())

    def test_10(self):
        "test selecting worker logs"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(self.tmpdir, "log_ffp_worker_blah.txt"), "w") as log_fp:
            log_fp.write("worker log")
        log_map = Reporter.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("worker log", log_fp.read())

    def test_11(self):
        "test prioritizing *San logs"
        asan_prefix = "log_asan.txt"
        test_logs = list()
        for _ in range(3):
            test_logs.append(".".join([asan_prefix, str(random.randint(1000, 4000))]))
        # crash on another thread
        with open(os.path.join(self.tmpdir, test_logs[0]), "w") as log_fp:
            log_fp.write("GOOD LOG\n")
            log_fp.write("==1942==ERROR: AddressSanitizer: heap-use-after-free on ... blah\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        # child log that should be ignored (created when parent crashes)
        with open(os.path.join(self.tmpdir, test_logs[1]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==1184==ERROR: AddressSanitizer: BUS on ... blah\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        with open(os.path.join(self.tmpdir, test_logs[2]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==9482==ERROR: AddressSanitizer: stack-overflow on ...\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        log_map = Reporter.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("GOOD LOG", log_fp.read())
