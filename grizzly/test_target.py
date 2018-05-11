# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import signal
import tempfile
import threading
import time
import unittest

from ffpuppet import FFPuppet
from grizzly.target import Target

logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("grz_target_test")


class StubTestPuppet(object):
    def __init__(self, use_rr, use_valgrind, use_xvfb):  # pylint: disable=unused-argument
        self.reason = FFPuppet.RC_CLOSED
        self.test_crashed = False  # used to control testing
        self.test_running = False  # used to control testing
        self.test_available_logs = list()  # used to control testing
        self.test_received_signal = False


    def available_logs(self):
        return self.test_available_logs


    def clean_up(self):
        self.close()


    def close(self):
        # the reason code is dependent on the state of test_crashed and test_running
        # this MUST model FFPuppet.close()
        if self.test_crashed:
            self.reason = FFPuppet.RC_ALERT
        elif self.test_running:
            self.reason = FFPuppet.RC_CLOSED
        elif self.reason != FFPuppet.RC_WORKER:
            self.reason = FFPuppet.RC_EXITED
        self.test_crashed = False
        self.test_running = False


    def get_pid(self):  # pylint: disable=no-self-use
        return os.getpid()


    def is_healthy(self):
        return (not self.test_crashed) and self.test_running


    def is_running(self):
        return self.test_running


    def launch(self, binary, launch_timeout=0, location=None, log_limit=0, memory_limit=0,  # pylint: disable=unused-argument,too-many-arguments
               prefs_js=None, extension=None, env_mod=None):  # pylint: disable=unused-argument,too-many-arguments
        self.reason = None
        self.test_crashed = False
        self.test_running = True


    def log_length(self, log_id):  # pylint: disable=no-self-use
        if log_id == "stderr":
            return 1024
        elif log_id == "stdout":
            return 100


class TargetTests(unittest.TestCase):
    def setUp(self):
        Target.PUPPET = StubTestPuppet
        _fd, self.tmpfn = tempfile.mkstemp(prefix="grz_test_")
        os.close(_fd)

    def tearDown(self):
        if os.path.isfile(self.tmpfn):
            os.remove(self.tmpfn)

    def test_01(self):
        "test creating a simple Target"
        target = Target(self.tmpfn, None, 300, 25, 5000, None, 25, False, False, False)
        self.addCleanup(target.cleanup)
        self.assertTrue(target.closed)
        self.assertEqual(target.detect_failure([], None), Target.RESULT_NONE)
        self.assertEqual(target.log_size(), 1124)
        target.check_relaunch()

    def test_02(self):
        "test creating and launching a simple Target"
        relaunch = 25
        target = Target(self.tmpfn, None, 300, 25, 5000, None, relaunch, False, False, False)
        self.addCleanup(target.cleanup)
        target.launch("launch_target_page")
        self.assertEqual(target.detect_failure([], None), Target.RESULT_NONE)
        self.assertFalse(target.closed)
        target.close()
        self.assertTrue(target.closed)

    def test_03(self):
        "test check_relaunch()"
        relaunch = 25
        target = Target(self.tmpfn, None, 300, 25, 5000, None, relaunch, False, False, False)
        self.addCleanup(target.cleanup)
        target.launch("launch_target_page")
        # test skipping relaunch
        self.assertEqual(target.rl_countdown, relaunch)
        target.check_relaunch(wait=60)
        self.assertEqual(target.rl_countdown, relaunch - 1)
        self.assertFalse(target.closed)
        # test triggering relaunch
        target.rl_countdown = 0
        target.check_relaunch(wait=0)
        self.assertEqual(target.rl_countdown, -1)
        self.assertTrue(target.closed)
        # test with "crashed" process
        target.launch("launch_target_page")
        self.assertFalse(target.closed)
        target._puppet.test_crashed = True  # pylint: disable=protected-access
        target.rl_countdown = 0
        target.check_relaunch(wait=5)  # should not block
        self.assertTrue(target.closed)

    def test_04(self):
        "test detect_failure()"
        relaunch = 25
        target = Target(self.tmpfn, None, 300, 25, 5000, None, relaunch, False, False, False)
        self.addCleanup(target.cleanup)
        target.launch("launch_target_page")
        # no failures
        self.assertEqual(target.detect_failure(["memory"], False), Target.RESULT_NONE)

        # test single process crash
        target._puppet.test_crashed = True  # pylint: disable=protected-access
        target._puppet.test_running = False  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure([], False), Target.RESULT_FAILURE)
        self.assertTrue(target.closed)

        # test multiprocess crash
        target.launch("launch_page")
        target._puppet.test_crashed = True  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure([], False), Target.RESULT_FAILURE)
        self.assertTrue(target.closed)

        # test exit with no crash logs
        target.launch("launch_page")
        target._puppet.test_running = False  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure([], False), Target.RESULT_NONE)
        self.assertTrue(target.closed)

        # test timeout
        target.launch("launch_page")
        target._puppet.test_running = True  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure([], True), Target.RESULT_FAILURE)
        self.assertTrue(target.closed)

        # test timeout ignored
        target.launch("launch_page")
        target._puppet.test_running = True  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure(["timeout"], True), Target.RESULT_IGNORED)
        self.assertTrue(target.closed)

        # test worker
        target.launch("launch_page")
        target._puppet.reason = FFPuppet.RC_WORKER  # pylint: disable=protected-access
        target._puppet.test_running = False  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure([], False), Target.RESULT_FAILURE)
        self.assertTrue(target.closed)

        # test memory ignored
        target.launch("launch_page")
        target._puppet.reason = FFPuppet.RC_WORKER  # pylint: disable=protected-access
        target._puppet.test_running = False  # pylint: disable=protected-access
        target._puppet.test_available_logs = ["ffp_worker_memory_limiter"]  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure(["memory"], False), Target.RESULT_IGNORED)
        self.assertTrue(target.closed)

        # test log-limit ignored
        target.launch("launch_page")
        target._puppet.reason = FFPuppet.RC_WORKER  # pylint: disable=protected-access
        target._puppet.test_running = False  # pylint: disable=protected-access
        target._puppet.test_available_logs = ["ffp_worker_log_size_limiter"]  # pylint: disable=protected-access
        self.assertEqual(target.detect_failure(["log-limit"], False), Target.RESULT_IGNORED)
        self.assertTrue(target.closed)

    def test_05(self):
        "test dump_coverage()"
        class SigCatcher(object):  # pylint: disable=too-few-public-methods
            CAUGHT = False
            @staticmethod
            def signal_handler(*args):  # pylint: disable=unused-argument
                SigCatcher.CAUGHT = True

        sig_catcher = SigCatcher()
        signal.signal(signal.SIGUSR1, sig_catcher.signal_handler)
        target = Target(self.tmpfn, None, 300, 25, 5000, None, 10, False, False, False)
        target.dump_coverage()
        self.assertFalse(sig_catcher.CAUGHT)
        target.launch("launch_page")
        target.dump_coverage()
        self.assertTrue(sig_catcher.CAUGHT)  # not sure if there is a race here...

    def test_06(self):
        "test poll_for_idle()"
        target = Target(self.tmpfn, None, 300, 25, 5000, None, 10, False, False, False)
        assert target.poll_for_idle(90, 0.2), "the test process should be mostly idle"
        evt = threading.Event()
        def busy_wait():
            while not evt.is_set():
                pass
        waiter = threading.Thread(target=busy_wait)
        try:
            waiter.start()
            time.sleep(0.1)
            assert not target.poll_for_idle(10, 0.2), "the test process should be busy"
        finally:
            evt.set()
            waiter.join()
