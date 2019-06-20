# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Interesting script to use FFPuppet/Sapphire for fast reduction using lithium.
"""
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import time
import threading

import ffpuppet
import sapphire
from ..common import FuzzManagerReporter, Report, TestCase, TestFile
from ..target import Target
from . import testcase_contents


__author__ = "Jesse Schwartzentruber"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber", "Jason Kratzer"]


LOG = logging.getLogger("grizzly.reduce.interesting")


class Interesting(object):

    def __init__(self, ignore, target, iter_timeout, no_harness, any_crash, skip, min_crashes,
                 repeat, idle_poll, idle_threshold, idle_timeout, status, testcase_cache=True):
        self.ignore = ignore  # things to ignore
        self.target = target  # a Puppet to run with
        self.status = status  # ReduceStatus to track progress
        self.server = None  # a server to serve with
        self.orig_sig = None  # signature to reduce to (if specified)
        # alt_crash_cb (if set) will be called with args=(temp_prefix) for any crashes which do
        # not match the original signature (assuming --any-crash is not set)
        self.alt_crash_cb = None
        # interesting_cb (if set) is called with args=(temp_prefix) for any interesting crash
        self.interesting_cb = None
        self.iter_timeout = iter_timeout
        self.no_harness = no_harness
        self.skip = skip
        self.skipped = None
        self.min_crashes = min_crashes
        self.repeat = repeat
        self.idle_poll = idle_poll
        self.any_crash = any_crash
        self.idle_threshold = idle_threshold
        self.idle_timeout = idle_timeout
        self.input_fname = None
        # testcase cache remembers if we have seen this reduce_file before and if so return the same
        # interesting result
        self.use_result_cache = testcase_cache
        self.result_cache = {}
        # environment if specified in the testcase
        self.env_mod = None
        self._landing_page = None  # the file to point the target at
        self._reduce_file = None  # the file to reduce

    def config_environ(self, environ):
        with open(environ) as in_fp:
            try:
                self.env_mod = json.load(in_fp).get('env', {})
            except ValueError:
                # TODO: remove this once switched to 'test_info.json'
                # legacy support for 'env_vars.txt'
                self.env_mod = {}
                in_fp.seek(0)
                for line in in_fp:
                    line = line.rstrip()
                    if not line:
                        continue
                    key, value = line.split('=', 1)
                    if not value:
                        value = None
                    self.env_mod[key] = value
        # known sanitizer suppression files
        known_suppressions = ('lsan.supp', 'ubsan.supp')
        working_dir = os.path.dirname(environ)
        for file_name in os.listdir(working_dir):
            if file_name in known_suppressions:
                self._add_san_suppressions(os.path.join(working_dir, file_name))

    @property
    def wwwdir(self):
        return os.path.dirname(os.path.realpath(self._landing_page))

    @property
    def landing_page(self):
        return os.path.basename(self._landing_page)

    @landing_page.setter
    def landing_page(self, value):
        self._landing_page = value

    @property
    def reduce_file(self):
        return self._reduce_file

    @reduce_file.setter
    def reduce_file(self, value):
        self._reduce_file = value
        # landing page should default to same value as reduce file
        if self._landing_page is None:
            self._landing_page = value

    def init(self, _):
        """Lithium initialization entrypoint

        Args:
            _args (unused): Command line arguments from Lithium (N/A)

        Returns:
            None
        """
        self.skipped = None
        self.best_testcase = None
        self.result_cache = {}

    def _add_san_suppressions(self, supp_file):
        # Update the sanitizer *SAN_OPTIONS environment variable to use provided
        # suppressions file
        opt_key = '%s_OPTIONS' % os.path.basename(supp_file).split('.')[0].upper()
        # the value matching *SAN_OPTIONS can be set to None
        san_opts = self.env_mod.get(opt_key, None)
        if san_opts is None:
            san_opts = ''
        updated = list()
        for opt in re.split(r":(?![\\|/])", san_opts):
            if opt and opt != 'suppressions':
                updated.append(opt)
        updated.append('suppressions=\'%s\'' % supp_file)
        self.env_mod[opt_key] = ':'.join(updated)

    def monitor_process(self, iteration_done_event, idle_timeout_event):
        # Wait until timeout is hit before polling
        LOG.debug('Waiting %r before polling', self.idle_timeout)
        exp_time = time.time() + self.idle_timeout
        while exp_time >= time.time() and not iteration_done_event.is_set():
            time.sleep(0.1)

        while not iteration_done_event.is_set():
            result = self.target.poll_for_idle(self.idle_threshold, self.idle_poll)
            if result != Target.POLL_BUSY:
                if result == Target.POLL_IDLE:
                    idle_timeout_event.set()
                break
            time.sleep(0.1)

    def update_timeout(self, run_time):
        # If run_time is less than poll-time, update it
        LOG.debug('Run took %r', run_time)
        new_poll_timeout = max(10, min(run_time * 1.5, self.idle_timeout))
        if new_poll_timeout < self.idle_timeout:
            LOG.info("Updating poll timeout to: %r", new_poll_timeout)
            self.idle_timeout = new_poll_timeout
        # If run_time * 2 is less than iter_timeout, update it
        # in other words, decrease the timeout if this ran in less than half the timeout
        # (floored at 10s)
        new_iter_timeout = max(10, min(run_time * 2, self.iter_timeout))
        if new_iter_timeout < self.iter_timeout:
            LOG.info("Updating max timeout to: %r", new_iter_timeout)
            self.iter_timeout = new_iter_timeout
            if self.server is not None:
                self.server.close()
                self.server = None
                # trigger relaunch with new timeout

    @property
    def location(self):
        if self.no_harness:
            return "http://127.0.0.1:%d/%s" % (self.server.get_port(), self.landing_page)
        return "".join((
            "http://127.0.0.1:%d/harness" % self.server.get_port(),
            "?timeout=%d" % (self.iter_timeout * 1000,),
            "&close_after=%d" % self.target.rl_reset,
            "&forced_close=0" if not self.target.forced_close else ""))

    def interesting(self, _, temp_prefix):
        """Lithium main iteration entrypoint.

        This should try the reduction and return True or False based on whether the reduction was
        good or bad.  This is subject to a number of options (skip, repeat, cache) and so may
        result in 0 or more actual runs of the target.

        Args:
            _args (unused): Command line arguments from Lithium (N/A)
            temp_prefix (str): A unique prefix for any files written during this iteration.

        Returns:
            bool: True if reduced testcase is still interesting.
        """
        # ensure the target is closed so "repeat" and "relaunch" never get out of sync
        if not self.target.closed:
            self.target.close()
        if self.skip:
            if self.skipped is None:
                self.skipped = 0
            elif self.skipped < self.skip:
                self.skipped += 1
                return False
        n_crashes = 0
        n_tries = max(self.repeat, self.min_crashes)
        if self.use_result_cache:
            with open(self.reduce_file, "rb") as test_fp:
                cache_key = hashlib.sha1(test_fp.read()).hexdigest()
            if cache_key in self.result_cache:
                result = self.result_cache[cache_key]['result']
                if result:
                    LOG.info("Interesting (cached)")
                    cached_prefix = self.result_cache[cache_key]['prefix']
                    for filename in glob.glob(r"%s_*" % cached_prefix):
                        suffix = os.path.basename(filename).split("_", 1)
                        if os.path.isfile(filename):
                            shutil.copy(filename, "%s_%s" % (temp_prefix, suffix[1]))
                        elif os.path.isdir(filename):
                            shutil.copytree(filename, "%s_%s" % (temp_prefix, suffix[1]))
                        else:
                            raise RuntimeError("Cannot copy non-file/non-directory: %s"
                                               % (filename,))
                else:
                    LOG.info("Uninteresting (cached)")
                return result

        # create the TestCase to try
        testcase = TestCase(self.landing_page, None, "grizzly.reduce", input_fname=self.input_fname)

        # add testcase contents
        for file_name in testcase_contents(self.wwwdir):
            testcase.add_from_file(os.path.join(self.wwwdir, file_name), file_name,
                                   required=bool(file_name == self.landing_page))

        # add prefs
        if self.target.prefs is not None:
            testcase.add_meta(TestFile.from_file(self.target.prefs, "prefs.js"))

        # add environment variables
        if self.env_mod is not None:
            for name, value in self.env_mod.items():
                testcase.add_environ_var(name, value)

        if self.no_harness:
            # create a tmp file that will never be served
            # this will keep sapphire serving until timeout or ffpuppet exits
            testcase.add_from_data("", ".lithium-garbage.bin", required=True)

        run_prefix = None
        for try_num in range(n_tries):
            if (n_tries - try_num) < (self.min_crashes - n_crashes):
                break  # no longer possible to get min_crashes, so stop
            self.status.report()
            self.status.iteration += 1
            run_prefix = "%s(%d)" % (temp_prefix, try_num)
            if self._run(testcase, run_prefix):
                n_crashes += 1
                if n_crashes >= self.min_crashes:
                    if self.interesting_cb is not None:
                        self.interesting_cb(run_prefix)  # pylint: disable=not-callable
                    if self.use_result_cache:
                        self.result_cache[cache_key] = {
                            'result': True,
                            'prefix': run_prefix
                        }
                    self.best_testcase = testcase
                    return True
        if self.use_result_cache:
            # No need to save the temp_prefix on uninteresting testcases
            # But let's do it anyway to stay consistent
            self.result_cache[cache_key] = {
                'result': False,
                'prefix': run_prefix
            }
        return False

    def _run(self, testcase, temp_prefix):
        """Run a single iteration against the target and determine if it is interesting. This is the
        low-level iteration function used by `interesting`.

        Args:
            testcase (TestCase): The testcase to serve
            temp_prefix (str): A unique prefix for any files written during this iteration.

        Returns:
            bool: True if reduced testcase is still interesting.
        """
        result = False

        # if target is closed and server is alive, we should restart it or else the first request
        #   against /first_test will 404
        if self.target.closed and self.server is not None:
            self.server.close()
            self.server = None

        # launch sapphire if needed
        if self.server is None:
            if self.no_harness:
                serve_timeout = self.iter_timeout
            else:
                # wait a few extra seconds to avoid races between the harness & sapphire timing out
                serve_timeout = self.iter_timeout + 10
            # have client error pages (code 4XX) call window.close() after a few seconds
            sapphire.Sapphire.CLOSE_CLIENT_ERROR = 2
            self.server = sapphire.Sapphire(timeout=serve_timeout)

            if not self.no_harness:
                harness = os.path.join(os.path.dirname(__file__), '..', 'common', 'harness.html')
                with open(harness, 'rb') as harness_fp:
                    harness = harness_fp.read()

                def _dyn_resp_close():
                    self.target.close()
                    return b"<h1>Close Browser</h1>"
                self.server.add_dynamic_response("/close_browser", _dyn_resp_close, mime_type="text/html")
                self.server.add_dynamic_response("/harness", lambda: harness, mime_type="text/html")
                self.server.set_redirect("/first_test", str(self.landing_page), required=True)

        # (re)launch Target
        if self.target.closed:
            # Try to launch the browser at most, 4 times
            for retries in reversed(range(4)):
                try:
                    self.target.launch(self.location, env_mod=self.env_mod)
                    break
                except ffpuppet.LaunchError as exc:
                    if retries:
                        LOG.warning(str(exc))
                        time.sleep(15)
                    else:
                        raise
            self.target.step()

        try:
            start_time = time.time()
            idle_timeout_event = threading.Event()
            iteration_done_event = threading.Event()
            if self.idle_poll:
                poll = threading.Thread(target=self.monitor_process,
                                        args=(iteration_done_event, idle_timeout_event))
                poll.start()

            def keep_waiting():
                return self.target.monitor.is_healthy() and not idle_timeout_event.is_set()

            if not self.no_harness:
                self.server.set_redirect("/next_test", str(self.landing_page), required=True)

            # serve the testcase
            server_status, files_served = self.server.serve_testcase(testcase, continue_cb=keep_waiting)

            end_time = time.time()

            # attempt to detect a failure
            failure_detected = self.target.detect_failure(
                self.ignore,
                server_status == sapphire.SERVED_TIMEOUT)

            # handle failure if detected
            if failure_detected == Target.RESULT_FAILURE:
                self.target.close()
                testcase.remove_files_not_served(files_served)

                # save logs
                result_logs = temp_prefix + "_logs"
                if not os.path.exists(result_logs):
                    os.mkdir(result_logs)
                self.target.save_logs(result_logs, meta=True)

                # create a CrashInfo
                crash = FuzzManagerReporter.create_crash_info(
                    Report.from_path(result_logs),
                    self.target.binary)

                short_sig = crash.createShortSignature()
                if short_sig == "No crash detected":
                    # XXX: need to change this to support reducing timeouts?
                    LOG.info("Uninteresting: no crash detected")
                elif self.orig_sig is None or self.orig_sig.matches(crash):
                    result = True
                    LOG.info("Interesting: %s", short_sig)
                    if self.orig_sig is None and not self.any_crash:
                        max_frames = FuzzManagerReporter.signature_max_frames(crash, 5)
                        self.orig_sig = crash.createCrashSignature(maxFrames=max_frames)
                    # the amount of time it can take to replay a test case can vary
                    # when under Valgrind so do not update the timeout in that case
                    if not getattr(self.target, "use_valgrind", False):
                        self.update_timeout(end_time - start_time)
                else:
                    LOG.info("Uninteresting: different signature: %s", short_sig)
                    if self.alt_crash_cb is not None:
                        self.alt_crash_cb(testcase, temp_prefix)  # pylint: disable=not-callable

            elif failure_detected == Target.RESULT_IGNORED:
                LOG.info("Uninteresting: ignored")
                self.target.close()

                # save logs
                result_logs = temp_prefix + "_logs"
                os.mkdir(result_logs)
                self.target.save_logs(result_logs, meta=True)

            else:
                LOG.info("Uninteresting: no failure detected")

            # trigger relaunch by closing the browser if needed
            self.target.check_relaunch()

        finally:
            iteration_done_event.set()
            if self.idle_poll:
                poll.join()

        return result

    def cleanup(self, _):
        """Lithium cleanup entrypoint

        Args:
            _args (unused): Command line arguments from Lithium (N/A)

        Returns:
            None
        """
        try:
            if self.server is not None:
                self.server.close()
                self.server = None
        finally:
            if self.target is not None:
                self.target.close()
