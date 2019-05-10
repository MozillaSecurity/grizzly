# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import glob
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from .reporter import FilesystemReporter, Reporter, Report


class TestCase(unittest.TestCase):

    if sys.version_info.major == 2:

        def assertRaisesRegex(self, *args, **kwds):
            return self.assertRaisesRegexp(*args, **kwds)


class ReportTests(TestCase):
    def setUp(self):
        tmpfd, self.tmpfn = tempfile.mkstemp(prefix="grz_test_")
        os.close(tmpfd)
        self.tmpdir = tempfile.mkdtemp(prefix="grz_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test creating a simple Report"
        report = Report("no_dir", dict())
        self.assertEqual(report.path, "no_dir")
        self.assertIsNone(report.log_aux)
        self.assertIsNone(report.log_err)
        self.assertIsNone(report.log_out)
        self.assertIsNone(report.stack)
        self.assertIsNone(report.preferred)
        report.cleanup()

    def test_02(self):
        "test from_path() with boring logs (no stack)"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        report = Report.from_path(self.tmpdir)
        self.assertEqual(report.path, self.tmpdir)
        self.assertTrue(report.log_err.endswith("log_stderr.txt"))
        self.assertTrue(report.log_out.endswith("log_stdout.txt"))
        self.assertTrue(report.preferred.endswith("log_stderr.txt"))
        self.assertIsNone(report.log_aux)
        self.assertIsNone(report.stack)
        self.assertEqual(Report.DEFAULT_MAJOR, report.major)
        self.assertEqual(Report.DEFAULT_MINOR, report.minor)
        self.assertIsNotNone(report.prefix)
        report.cleanup()
        self.assertFalse(os.path.isdir(self.tmpdir))

    def test_03(self):
        "test from_path()"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(self.tmpdir, "log_asan_blah.txt"), "w") as log_fp:
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19")
        report = Report.from_path(self.tmpdir)
        self.assertEqual(report.path, self.tmpdir)
        self.assertTrue(report.log_aux.endswith("log_asan_blah.txt"))
        self.assertTrue(report.log_err.endswith("log_stderr.txt"))
        self.assertTrue(report.log_out.endswith("log_stdout.txt"))
        self.assertTrue(report.preferred.endswith("log_asan_blah.txt"))
        self.assertIsNotNone(report.stack)
        self.assertNotEqual(Report.DEFAULT_MAJOR, report.major)
        self.assertNotEqual(Report.DEFAULT_MINOR, report.minor)
        self.assertIsNotNone(report.prefix)
        report.cleanup()

    def test_04(self):
        "test Report.tail()"
        with open(self.tmpfn, "wb") as test_fp:
            test_fp.write(b"blah\ntest\n123\xEF\x00FOO")
            length = test_fp.tell()
        # no size limit
        self.assertEqual(os.stat(self.tmpfn).st_size, length)
        with self.assertRaises(AssertionError):
            Report.tail(self.tmpfn, 0)
        self.assertEqual(os.stat(self.tmpfn).st_size, length)
        Report.tail(self.tmpfn, 3)
        with open(self.tmpfn, "rb") as test_fp:
            log_data = test_fp.read()
        self.assertTrue(log_data.startswith(b"[LOG TAILED]\n"))
        self.assertEqual(log_data[13:], b"FOO")

    def test_05(self):
        "test Report.select_logs()"
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
            for l_no in range(4): # pad out to 6 lines
                log_fp.write("    #%d blah...\n" % l_no)
        # child log that should be ignored (created when parent crashes)
        with open(os.path.join(self.tmpdir, test_logs[2]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000")
            log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n") # must be 2nd line
            for l_no in range(4): # pad out to 6 lines
                log_fp.write("    #%d blah...\n" % l_no)
        with open(os.path.join(self.tmpdir, "log_mindump_blah.txt"), "w") as log_fp:
            log_fp.write("minidump log")
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        # should be ignored in favor of "GOOD LOG"
        with open(os.path.join(self.tmpdir, "log_ffp_worker_blah.txt"), "w") as log_fp:
            log_fp.write("worker log")
        log_map = Report.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("GOOD LOG", log_fp.read())
        with open(os.path.join(self.tmpdir, log_map["stderr"]), "r") as log_fp:
            self.assertIn("STDERR", log_fp.read())
        with open(os.path.join(self.tmpdir, log_map["stdout"]), "r") as log_fp:
            self.assertIn("STDOUT", log_fp.read())

    def test_06(self):
        "test minidump with Report.select_logs()"
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
        log_map = Report.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("minidump log", log_fp.read())

    def test_07(self):
        "test selecting preferred DUMP_REQUESTED minidump with Report.select_logs()"
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
        log_map = Report.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("google_breakpad::ExceptionHandler::WriteMinidump", log_fp.read())

    def test_08(self):
        "test selecting worker logs with Report.select_logs()"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(self.tmpdir, "log_ffp_worker_blah.txt"), "w") as log_fp:
            log_fp.write("worker log")
        log_map = Report.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stderr"])))
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["stdout"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("worker log", log_fp.read())

    def test_09(self):
        "test prioritizing *San logs with Report.select_logs()"
        asan_prefix = "log_asan.txt"
        test_logs = list()
        for _ in range(5):
            test_logs.append(".".join([asan_prefix, str(random.randint(1000, 4000))]))
        # crash
        with open(os.path.join(self.tmpdir, test_logs[0]), "w") as log_fp:
            log_fp.write("GOOD LOG\n")
            log_fp.write("==1942==ERROR: AddressSanitizer: heap-use-after-free on ... blah\n") # must be 2nd line
            for l_no in range(4): # pad out to 6 lines
                log_fp.write("    #%d blah...\n" % l_no)
        # crash missing trace
        with open(os.path.join(self.tmpdir, test_logs[1]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==1984==ERROR: AddressSanitizer: SEGV on ... blah\n") # must be 2nd line
            log_fp.write("missing trace...\n")
        # child log that should be ignored (created when parent crashes)
        with open(os.path.join(self.tmpdir, test_logs[2]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==1184==ERROR: AddressSanitizer: BUS on ... blah\n") # must be 2nd line
            for l_no in range(4): # pad out to 6 lines
                log_fp.write("    #%d blah...\n" % l_no)
        with open(os.path.join(self.tmpdir, test_logs[3]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==9482==ERROR: AddressSanitizer: stack-overflow on ...\n") # must be 2nd line
            for l_no in range(4): # pad out to 6 lines
                log_fp.write("    #%d blah...\n" % l_no)
        with open(os.path.join(self.tmpdir, test_logs[4]), "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("ERROR: Failed to mmap\n") # must be 2nd line
        log_map = Report.select_logs(self.tmpdir)
        self.assertTrue(os.path.isfile(os.path.join(self.tmpdir, log_map["aux"])))
        with open(os.path.join(self.tmpdir, log_map["aux"]), "r") as log_fp:
            self.assertIn("GOOD LOG", log_fp.read())

    def test_10(self):
        "test size_limit"
        with open(os.path.join(self.tmpdir, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log\n" * 200)
        with open(os.path.join(self.tmpdir, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log\n" * 200)
        with open(os.path.join(self.tmpdir, "unrelated.txt"), "w") as log_fp:
            log_fp.write("nothing burger\n" * 200)
        os.mkdir(os.path.join(self.tmpdir, "rr-trace"))
        size_limit = len("STDERR log\n")
        report = Report.from_path(self.tmpdir, size_limit=size_limit)
        self.assertEqual(report.path, self.tmpdir)
        self.assertTrue(report.log_err.endswith("log_stderr.txt"))
        self.assertTrue(report.log_out.endswith("log_stdout.txt"))
        self.assertTrue(report.preferred.endswith("log_stderr.txt"))
        self.assertIsNone(report.log_aux)
        self.assertIsNone(report.stack)
        size_limit += len("[LOG TAILED]\n")
        self.assertEqual(os.stat(os.path.join(report.path, report.log_err)).st_size, size_limit)
        self.assertEqual(os.stat(os.path.join(report.path, report.log_out)).st_size, size_limit)
        self.assertEqual(os.stat(os.path.join(report.path, "unrelated.txt")).st_size, size_limit)
        report.cleanup()
        self.assertFalse(os.path.isdir(self.tmpdir))


class ReporterTests(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="grz_test")

    def tearDown(self):
        if os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_01(self):
        "test creating a simple Reporter"
        class SimpleReporter(Reporter):
            def _pre_submit(self, report):
                pass
            def _reset(self):
                pass
            def _submit(self, report, test_cases):
                pass
        reporter = SimpleReporter()
        with self.assertRaisesRegex(IOError, "No such directory 'fake_dir'"):
            reporter.submit("fake_dir", [])
        with self.assertRaisesRegex(IOError, "No logs found in"):
            reporter.submit(self.tmpdir, [])

    def test_02(self):
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
        reporter.submit(logs, [])

    def test_03(self):
        "test FilesystemReporter with testcases"
        class DummyTest(object):  # pylint: disable=too-few-public-methods
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
        report_dir = os.path.join(report_dir, "nested", "dir")
        reporter = FilesystemReporter(report_path=report_dir)
        reporter.submit(logs, testcases)
        # call report a 2nd time
        logs = tempfile.mkdtemp(prefix="tst_logs", dir=self.tmpdir)
        with open(os.path.join(logs, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(logs, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        testcases = list()
        for tstc in testcases:
            self.assertTrue(tstc.dump_called)
        for _ in range(10):
            testcases.append(DummyTest())
        reporter.submit(logs, testcases)

    @unittest.skipIf(not sys.platform.startswith("linux"), "RR only supported on Linux")
    def test_04(self):
        "test packaging rr traces"
        rr_dir = tempfile.mkdtemp(prefix="tst_rr", dir=self.tmpdir)
        try:
            subprocess.check_output(["rr", "record", "/bin/echo", "hello world"], env={"_RR_TRACE_DIR": rr_dir})
        except OSError as exc:
            self.skipTest("calling rr: %s" % (exc,))
        self.assertTrue(os.path.islink(os.path.join(rr_dir, "latest-trace")))
        self.assertTrue(os.path.isdir(os.path.realpath(os.path.join(rr_dir, "latest-trace"))))
        logs = tempfile.mkdtemp(prefix="tst_logs", dir=self.tmpdir)
        # write logs
        os.symlink(os.path.realpath(os.path.join(rr_dir, "latest-trace")),
                   os.path.join(logs, "rr-trace"))
        with open(os.path.join(logs, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR log")
        with open(os.path.join(logs, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT log")
        with open(os.path.join(logs, "log_asan_blah.txt"), "w") as log_fp:
            log_fp.write("    #0 0xbad000 in foo /file1.c:123:234\n")
            log_fp.write("    #1 0x1337dd in bar /file2.c:1806:19")
        report_dir = tempfile.mkdtemp(prefix="grz_fs_reporter", dir=self.tmpdir)
        reporter = FilesystemReporter(report_path=report_dir)
        reporter.submit(logs, [])
        report_log_dirs = glob.glob(report_dir + "/*/*_logs/")
        self.assertEqual(len(report_log_dirs), 1)
        report_log_dir = report_log_dirs[0]
        self.assertFalse(os.path.islink(os.path.join(report_log_dir, "rr-trace")))
        self.assertTrue(os.path.isfile(os.path.join(report_log_dir, "rr.tar.xz")))
