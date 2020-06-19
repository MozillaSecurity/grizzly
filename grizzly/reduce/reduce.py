# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Given a build and testcase, try to reproduce it using a set of strategies.
"""
from __future__ import absolute_import
import glob
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import time
import zipfile
import zlib

import lithium
import sapphire
from FTB.Signatures.CrashInfo import CrashSignature

from . import strategies as strategies_module, testcase_contents
from .exceptions import CorruptTestcaseError, NoTestcaseError, ReducerError
from ..common.reporter import FilesystemReporter, FuzzManagerReporter, Report
from ..common.runner import Runner
from ..common.status import ReducerStats, Status
from ..common.storage import TestCase, TestFile
from ..common.utils import grz_tmp
from ..main import configure_logging
from ..session import Session
from ..target import load as load_target, sanitizer_opts, TargetLaunchError, \
    TargetLaunchTimeout


__author__ = "Jesse Schwartzentruber"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber", "Jason Kratzer"]


LOG = logging.getLogger("grizzly.reduce")


class LithiumInterestingProxy(object):
    """Proxy to use a ReductionJob object as a Lithium interestingness script object.
    """
    __slots__ = ['_job']

    def __init__(self, job):
        self._job = job

    def init(self, _args):
        """Lithium initialization entrypoint.

        Do any per-reduction loop setup needed.

        Args:
            _args (unused): Command line arguments from Lithium (N/A)

        Returns:
            None
        """
        self._job.lithium_init()

    def interesting(self, _args, temp_prefix):
        """Lithium main iteration entrypoint.

        This should try the reduction and return True or False based on whether the reduction was
        good or bad.

        Args:
            _args (unused): Command line arguments from Lithium (N/A)
            temp_prefix (str): A unique prefix for any files written during this iteration.

        Returns:
            bool: True if reduced testcase is still interesting.
        """
        return self._job.lithium_interesting(temp_prefix)

    def cleanup(self, _args):
        """Lithium cleanup entrypoint.

        Do any per-reduction loop cleanup needed.

        Args:
            _args (unused): Command line arguments from Lithium (N/A)

        Returns:
            None
        """
        self._job.lithium_cleanup()


class IterationParamsProxy(object):
    __slots__ = ['_fixed_timeout', '_job', '_use_result_cache']

    def __init__(self, job):
        self._job = job
        self._use_result_cache = None
        self._fixed_timeout = None

    def __enter__(self):
        # disable result cache setting
        self._use_result_cache = self._job._use_result_cache
        self._job._use_result_cache = False

        # do not update the iteration timeout during analysis
        self._fixed_timeout = self._job._fixed_timeout
        self._job._fixed_timeout = True

        return self

    def __exit__(self, *_args):
        # restore saved values
        self._job._use_result_cache = self._use_result_cache
        self._job._fixed_timeout = self._fixed_timeout

    @property
    def force_no_harness(self):
        return self._job._force_no_harness

    @property
    def min_crashes(self):
        return self._job._min_crashes

    @min_crashes.setter
    def min_crashes(self, value):
        self._job._min_crashes = value

    @property
    def no_harness(self):
        return self._job._no_harness

    @no_harness.setter
    def no_harness(self, value):
        self._job._no_harness = value

    @property
    def relaunch(self):
        return self._job._target.rl_reset

    @relaunch.setter
    def relaunch(self, value):
        self._job._target.rl_reset = min(self._job._original_relaunch, value)

    @property
    def repeat(self):
        return self._job._repeat

    @repeat.setter
    def repeat(self, value):
        self._job._repeat = value

    def commit(self):
        # close target so new parameters take effect
        self._job.close_target()


class TimeoutsUpdateProxy(object):
    __slots__ = ['_job']

    def __init__(self, job):
        self._job = job

    @property
    def idle(self):
        return self._job._idle_timeout

    @idle.setter
    def idle(self, value):
        self._job._idle_timeout = value

    @property
    def iteration(self):
        return self._job._iter_timeout

    @iteration.setter
    def iteration(self, value):
        self._job._iter_timeout = value


class RunState(object):
    __slots__ = ['files_to_reduce', 'original_size']

    def __init__(self, files_to_reduce):
        self.files_to_reduce = files_to_reduce
        self.original_size = -1

    def total_size(self):
        return sum(os.stat(fn).st_size for fn in self.files_to_reduce)


class TestcaseUpdateProxy(object):
    __slots__ = ['_job', '_run_state']

    def __init__(self, job, run_state):
        self._job = job
        self._run_state = run_state

    @property
    def cache_iter_harness_created(self):
        return self._job._cache_iter_harness_created

    @property
    def root(self):
        return self._job._tcroot

    @root.setter
    def root(self, value):
        self._job._tcroot = value

    @property
    def entry(self):
        return self._job._testcase

    @entry.setter
    def entry(self, value):
        self._job._testcase = value

    @property
    def landing_page(self):
        return self._job.landing_page

    @landing_page.setter
    def landing_page(self, value):
        self._job.landing_page = value

    @property
    def files_to_reduce(self):
        return self._run_state.files_to_reduce

    @property
    def original_size(self):
        return self._run_state.original_size

    @original_size.setter
    def original_size(self, value):
        self._run_state.original_size = value

    def total_size(self):
        return self._run_state.total_size()


class ReductionJob(object):
    LOGGERS_TO_WATCH = ("ffpuppet", "grizzly", "lithium", "sapphire")
    DEFAULT_STRATEGIES = ("line", "cssbeautify", "jsbeautify", "collapsebraces", "jschar")
    __slots__ = [
        '_any_crash', '_best_testcase', '_cache_iter_harness_created', '_env_mod',
        '_fixed_timeout', '_force_no_harness', '_idle_threshold', '_idle_timeout', '_ignore',
        '_input_fname', '_interesting_prefix', '_iter_timeout', '_landing_page', '_log_handler',
        '_min_crashes', '_no_harness', '_orig_sig', '_original_relaunch', '_other_crashes',
        '_reduce_file', '_repeat', '_reporter', '_result_cache', '_result_code', '_server', '_server_map',
        '_signature', '_skip', '_skip_analysis', '_skipped', '_status', '_target', '_tcroot', '_testcase',
        '_tmpdir', '_use_result_cache',
    ]

    def __init__(self, ignore, target, iter_timeout, no_harness, any_crash, skip, min_crashes,
                 repeat, idle_threshold, idle_timeout, status, testcase_cache=True, skip_analysis=False):
        """Use lithium to reduce a testcase.

        Args:
            target (grizzly.target.Target): Target object to use for reduction.
        """
        self._any_crash = any_crash
        self._best_testcase = None
        self._cache_iter_harness_created = None
        self._env_mod = None  # environment if specified in the testcase
        self._fixed_timeout = False  # if True iter_timeout will not be changed
        self._force_no_harness = no_harness
        self._idle_threshold = idle_threshold
        self._idle_timeout = idle_timeout
        self._ignore = ignore  # things to ignore
        self._input_fname = None
        self._interesting_prefix = None
        self._iter_timeout = iter_timeout
        self._landing_page = None  # the file to point the target at
        self._min_crashes = min_crashes
        self._no_harness = no_harness
        self._orig_sig = None  # signature to reduce to (if specified)
        self._original_relaunch = target.rl_reset
        self._other_crashes = {}
        self._reduce_file = None  # the file to reduce
        self._repeat = repeat
        self._reporter = None
        self._result_cache = {}
        self._result_code = None
        self._server = None  # a server to serve with
        self._server_map = sapphire.ServerMap()  # manage dynamic requests, includes and redirects
        self._signature = None
        self._skip = skip
        self._skip_analysis = skip_analysis
        self._skipped = None
        self._status = status  # ReduceStatus to track progress
        self._target = target  # a Puppet to run with
        self._testcase = None
        # testcase cache remembers if we have seen this reduce_file before and if so return the same
        # interesting result
        self._use_result_cache = testcase_cache
        self._tmpdir = tempfile.mkdtemp(prefix="grzreduce", dir=grz_tmp("reduce"))
        self._tcroot = os.path.join(self._tmpdir, "tc")
        self._log_handler = self._start_log_capture()
        if not self._skip_analysis:
            # see if any of the args tweaked by analysis were overridden
            # --relaunch is regarded as a maximum, so overriding the default is not a deal-breaker for this
            if self._min_crashes != 1:
                LOG.warning("--min-crashes=%d was given, skipping analysis", self._min_crashes)
                self._skip_analysis = True
            elif self._repeat != 1:
                LOG.warning("--repeat=%d was given, skipping analysis", self._repeat)
                self._skip_analysis = True

    @property
    def landing_page(self):
        return os.path.basename(self._landing_page)

    @landing_page.setter
    def landing_page(self, value):
        # this looks pointless, but it isn't since it affects both landing_page and wwwdir getters
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

    @property
    def result_code(self):
        return self._result_code

    @property
    def server(self):
        return self._server

    @property
    def target(self):
        return self._target

    @property
    def wwwdir(self):
        return os.path.dirname(os.path.realpath(self._landing_page))

    def timeouts_proxy(self):
        """Return a proxy for modifying the job timeouts.

        Returns:
            (object): an object used to modify the timeouts for this job
                      attributes:
                          - iteration (iteration timeout)
                          - idle (idle timeout)
        """
        return TimeoutsUpdateProxy(self)

    def testcase_proxy(self, run_state):
        """Return a proxy for modifying the testcase.

        Returns:
            (object): an object used to modify the testcase for this job
                      attributes:
                          - iteration (iteration timeout)
                          - idle (idle timeout)
        """
        return TestcaseUpdateProxy(self, run_state)

    def analysis_mode(self, min_crashes=1, relaunch=1, repeat=1):
        """Set parameters for testcase analysis. This has side-effects besides being a proxy:

            - min_crashes/repeat/relaunch are preset according to the function parameters
            - result cache is disabled (so every iteration runs fully) if used as a with-statement context
            - times are not dynamically adjusted if used as a with-statement context

        Args:
            min_crashes (int): How many crashes are needed for a success.
            relaunch (int): How many iterations between relaunch.
            repeat (int): How many times to repeat the testcase per iteration.

        Returns:
            (context manager): an object that can be used to set new parameters
                               as a result of analysis:
                               attributes:
                                   - min_crashes
                                   - no_harness
                                   - relaunch
                                   - repeat
        """
        # pylint: disable=no-self-argument,no-self-use,protected-access

        proxy = IterationParamsProxy(self)

        # Set parameters for analysis
        proxy.min_crashes = min_crashes
        proxy.repeat = repeat
        proxy.relaunch = relaunch

        return proxy

    def close_target(self):
        if not self._target.closed:
            self._target.close()

    def lithium_init(self):
        """Lithium initialization entrypoint. Do any per-reduction loop setup needed.

        Args:
            None

        Returns:
            None
        """
        self._skipped = None
        self._best_testcase = None
        self._result_cache = {}

    def lithium_interesting(self, temp_prefix):
        """Lithium main iteration entrypoint.

        This should try the reduction and return True or False based on whether the reduction was
        good or bad.  This is subject to a number of options (skip, repeat, cache) and so may
        result in 0 or more actual runs of the target.

        Args:
            temp_prefix (str): A unique prefix for any files written during this iteration.

        Returns:
            bool: True if reduced testcase is still interesting.
        """
        # ensure the target is closed so "repeat" and "relaunch" never get out of sync
        self.close_target()
        if self._skip:
            if self._skipped is None:
                self._skipped = 0
            elif self._skipped < self._skip:
                self._skipped += 1
                return False
        n_crashes = 0
        n_tries = max(self._repeat, self._min_crashes)
        if self._use_result_cache:
            with open(self.reduce_file, "rb") as test_fp:
                cache_key = hashlib.sha1(test_fp.read()).hexdigest()
            if cache_key in self._result_cache:
                result = self._result_cache[cache_key]['result']
                if result:
                    LOG.info("Interesting (cached)")
                    cached_prefix = self._result_cache[cache_key]['prefix']
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
        testcase = TestCase(self.landing_page, None, "grizzly.reduce", input_fname=self._input_fname)

        # add testcase contents
        for file_name in testcase_contents(self.wwwdir):
            testcase.add_from_file(os.path.join(self.wwwdir, file_name), file_name,
                                   required=bool(file_name == self.landing_page))

        # add prefs
        if self._target.prefs is not None:
            testcase.add_meta(TestFile.from_file(self._target.prefs, "prefs.js"))

        # add environment variables
        if self._env_mod is not None:
            for name, value in self._env_mod.items():
                testcase.add_environ_var(name, value)

        max_duration = 0
        run_prefix = None
        for try_num in range(n_tries):
            if (n_tries - try_num) < (self._min_crashes - n_crashes):
                break  # no longer possible to get min_crashes, so stop
            self._status.report()
            self._status.iteration += 1
            run_prefix = "%s(%d)" % (temp_prefix, try_num)
            if self._run(testcase, run_prefix):
                # track the maximum duration of the successful reduction attempts
                if testcase.duration > max_duration:
                    max_duration = testcase.duration
                n_crashes += 1
                if n_crashes >= self._min_crashes:
                    self.on_interesting_crash(run_prefix)
                    if self._use_result_cache:
                        self._result_cache[cache_key] = {
                            'result': True,
                            'prefix': run_prefix
                        }
                    self._best_testcase = testcase
                    # the amount of time it can take to replay a test case can vary
                    # when under Valgrind so do not update the timeout in that case
                    if not self._fixed_timeout and not getattr(self._target, "use_valgrind", False):
                        self.update_timeout(max_duration)
                    return True
        if self._use_result_cache:
            # No need to save the temp_prefix on uninteresting testcases
            # But let's do it anyway to stay consistent
            self._result_cache[cache_key] = {
                'result': False,
                'prefix': run_prefix
            }
        return False

    def lithium_cleanup(self):
        """Lithium cleanup entrypoint. Do any per-reduction loop cleanup needed.

        Args:
            None

        Returns:
            None
        """
        try:
            if self._server is not None:
                self._server.close()
                self._server = None
        finally:
            if self._target is not None:
                self._target.close()

    def _add_san_suppressions(self, supp_file):
        # Update the sanitizer *SAN_OPTIONS environment variable to use provided
        # suppressions file
        opt_key = '%s_OPTIONS' % os.path.basename(supp_file).split('.')[0].upper()
        opts_data = self._env_mod.get(opt_key, '')
        # the value matching *SAN_OPTIONS can be set to None
        if opts_data is None:
            opts_data = ''
        opts = sanitizer_opts(opts_data)
        opts['suppressions'] = '\'%s\'' % (supp_file,)
        self._env_mod[opt_key] = ':'.join('='.join((k, v)) for k, v in opts.items())

    def _start_log_capture(self):
        """Add a log handler for grizzly and lithium messages generated during this job.
        The handler is removed again by close()

        Args:
            None

        Returns:
            logging.Handler: The log handler to be removed later.
        """
        formatter = logging.Formatter("%(levelname).1s %(name)s [%(asctime)s] %(message)s")
        handler = logging.FileHandler(os.path.join(self._tmpdir, "reducelog.txt"))
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        for logname in self.LOGGERS_TO_WATCH:
            logging.getLogger(logname).addHandler(handler)

        # check that DEBUG messages will actually get through
        # if the root logger level is > DEBUG, messages will not get through to our log handler
        # set root to DEBUG, and propagate the old root level to each root handler
        root_logger = logging.getLogger()
        root_level = root_logger.getEffectiveLevel()
        if root_level > logging.DEBUG:
            root_logger.setLevel(logging.DEBUG)
            for root_handler in root_logger.handlers:
                if root_handler.level < root_level:
                    root_handler.setLevel(root_level)

        return handler

    def update_timeout(self, run_time):
        # If run_time is less than poll-time, update it
        LOG.debug('Run time %r', run_time)
        new_poll_timeout = max(10, min(run_time * 1.5, self._idle_timeout))
        if new_poll_timeout < self._idle_timeout:
            LOG.info("Updating poll timeout to: %r", new_poll_timeout)
            self._idle_timeout = new_poll_timeout
        # If run_time * 2 is less than iter_timeout, update it
        # in other words, decrease the timeout if this ran in less than half the timeout
        # (floored at 10s)
        new_iter_timeout = max(10, min(run_time * 2, self._iter_timeout))
        if new_iter_timeout < self._iter_timeout:
            LOG.info("Updating max timeout to: %r", new_iter_timeout)
            self._iter_timeout = new_iter_timeout

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
        if self._target.closed and self._server is not None:
            self._server.close()
            self._server = None
        self._server_map.dynamic.clear()
        self._server_map.redirect.clear()

        # launch sapphire if needed
        if self._server is None:
            # have client error pages (code 4XX) call window.close() after a few seconds
            self._server = sapphire.Sapphire(auto_close=2)

            if not self._no_harness:
                harness = os.path.join(os.path.dirname(__file__), '..', 'common', 'harness.html')
                with open(harness, 'rb') as harness_fp:
                    harness = harness_fp.read()
                self._server_map.set_dynamic_response("grz_harness", lambda: harness, mime_type="text/html")
            self._server_map.set_redirect("grz_current_test", str(self.landing_page), required=False)

        runner = Runner(self._server, self._target, self._idle_threshold, self._idle_timeout)
        if self._no_harness:
            self._server.timeout = self._iter_timeout
        else:
            # wait a few extra seconds to avoid races between the harness & sapphire timing out
            self._server.timeout = self._iter_timeout + 10

        # (re)launch Target
        if self._target.closed:
            if self._no_harness:
                location = runner.location(
                    "/grz_current_test",
                    self._server.port)
            else:
                location = runner.location(
                    "/grz_harness",
                    self._server.port,
                    close_after=self._target.rl_reset,
                    forced_close=self._target.forced_close,
                    timeout=self._iter_timeout)
            # Try to launch the browser, retry 4 times at most
            runner.launch(location, env_mod=self._env_mod, max_retries=4, retry_delay=15)
            self._target.step()

        if not self._no_harness:
            def _dyn_resp_close():  # pragma: no cover
                if self.target.monitor.is_healthy():
                    # delay to help catch window close/shutdown related crashes
                    time.sleep(0.1)
                    self.target.close()
                return b"<h1>Close Browser</h1>"
            self._server_map.set_dynamic_response("grz_close_browser", _dyn_resp_close, mime_type="text/html")
            self._server_map.set_redirect("grz_next_test", str(self.landing_page), required=True)

        # run test case
        runner.run(self._ignore, self._server_map, testcase, wait_for_callback=self._no_harness)

        # handle failure if detected
        if runner.result == Runner.FAILED:
            self._target.close()
            testcase.purge_optional(runner.served)

            # save logs
            result_logs = temp_prefix + "_logs"
            if not os.path.exists(result_logs):
                os.mkdir(result_logs)
            self._target.save_logs(result_logs)

            # create a CrashInfo
            crash = FuzzManagerReporter.create_crash_info(
                Report.from_path(result_logs),
                self._target.binary)

            short_sig = crash.createShortSignature()
            if short_sig == "No crash detected":
                # XXX: need to change this to support reducing timeouts?
                LOG.info("Uninteresting: no crash detected")
            elif self._orig_sig is None or self._orig_sig.matches(crash):
                result = True
                LOG.info("Interesting: %s", short_sig)
                if self._orig_sig is None and not self._any_crash:
                    self._orig_sig = Report.crash_signature(crash)
            else:
                LOG.info("Uninteresting: different signature: %s", short_sig)
                self.on_other_crash_found(testcase, temp_prefix)

        elif runner.result == Runner.IGNORED:
            LOG.info("Uninteresting: ignored")
            self._target.close()

        else:
            LOG.info("Uninteresting: no failure detected")

        # trigger relaunch by closing the browser if needed
        self._target.check_relaunch()

        return result

    def _stop_log_capture(self):
        """Stop handling reduce logs.

        Args:
            None

        Returns:
            None
        """
        if self._log_handler is None:
            return
        for logname in self.LOGGERS_TO_WATCH:
            logging.getLogger(logname).removeHandler(self._log_handler)
        self._log_handler.flush()
        self._log_handler.close()
        self._log_handler = None

    def config_environ(self, environ):
        with open(environ) as in_fp:
            try:
                self._env_mod = json.load(in_fp).get('env', {})
            except ValueError:
                # TODO: remove this once switched to 'test_info.json'
                # legacy support for 'env_vars.txt'
                self._env_mod = {}
                in_fp.seek(0)
                for line in in_fp:
                    line = line.rstrip()
                    if not line:
                        continue
                    key, value = line.split('=', 1)
                    if not value:
                        value = None
                    self._env_mod[key] = value
        # known sanitizer suppression files
        known_suppressions = ('lsan.supp', 'ubsan.supp')
        working_dir = os.path.dirname(environ)
        for file_name in os.listdir(working_dir):
            if file_name in known_suppressions:
                self._add_san_suppressions(os.path.join(working_dir, file_name))

    def config_signature(self, signature):
        """Configure a signature to use for reduction.  If none is given, an automatic signature is
        created based on the initial repro.

        Args:
            signature (str): A JSON signature to match for reduction.

        Returns:
            None
        """
        self._signature = CrashSignature(signature)

    @staticmethod
    def _get_landing_page(testpath):
        """Parse test_info.json for landing page

        Args:
            testpath (str): Path to a testcase folder (containing a test_info.json from Grizzly).

        Returns:
            str: Path to the landing page within testpath
        """
        info_file = os.path.join(testpath, "test_info.json")
        if os.path.isfile(info_file):
            with open(info_file) as info:
                landing_page = json.load(info).get("target", None)
            if landing_page is None:
                raise ReducerError("Could not find landing page in %s!" % (os.path.abspath(info_file),))
            landing_page = os.path.join(testpath, landing_page)
        else:
            LOG.warning("Using deprecated test_info.txt")
            with io.open(os.path.join(testpath, "test_info.txt"), encoding="utf-8") as info:
                for line in info:
                    if line.lower().startswith("landing page: "):
                        landing_page = os.path.join(testpath,
                                                    line.split(": ", 1)[1].strip())
                        break
                else:
                    raise ReducerError("Could not find landing page in %s!"
                                       % (os.path.abspath(info.name),))
        if not os.path.isfile(landing_page):
            raise ReducerError("Landing page %s does not exist in %s!"
                               % (landing_page, os.path.abspath(info.name)))
        return landing_page

    def _http_abspath(self, path):
        """Return an absolute HTTP path to `path` relative to tcroot"""
        path = os.path.relpath(path, self._tcroot)
        return '/' + '/'.join(path.split(os.sep))

    def config_testcase(self, testcase):
        """Prepare a user provided testcase for reduction.

        Args:
            testcase (str): Path to a testcase. This should be a Grizzly testcase (zip or folder) or html
                            file.

        Returns:
            None
        """
        try:
            # extract the testcase if necessary
            if os.path.exists(self._tcroot):
                raise ReducerError("Testcase already configured?")
            if os.path.isfile(testcase):
                if testcase.lower().endswith(".html"):
                    os.mkdir(self._tcroot)
                    shutil.copy(testcase, self._tcroot)
                    info = {"target": os.path.basename(testcase)}
                    with open(os.path.join(self._tcroot, "test_info.json"), "w") as info_fp:
                        json.dump(info, info_fp, indent=2, sort_keys=True)
                elif testcase.lower().endswith(".zip"):
                    os.mkdir(self._tcroot)
                    try:
                        with zipfile.ZipFile(testcase) as zip_fp:
                            zip_fp.extractall(path=self._tcroot)
                    except (zlib.error, zipfile.BadZipfile):
                        raise CorruptTestcaseError("Testcase is corrupted")
                else:
                    raise ReducerError("Testcase must be zip, html, or directory")
            elif os.path.isdir(testcase):
                shutil.copytree(testcase, self._tcroot)
            else:
                raise ReducerError("Testcase must be zip, html or directory")

            self._input_fname = os.path.basename(testcase)

            # get a list of all directories containing testcases (1-n, depending on how much history
            # grizzly saved)
            entries = set(os.listdir(self._tcroot))
            if "test_info.json" in entries:
                dirs = [self._tcroot]
            elif "test_info.txt" in entries:
                dirs = [self._tcroot]
            else:
                dirs = sorted([os.path.join(self._tcroot, entry) for entry in entries
                               if os.path.exists(os.path.join(self._tcroot, entry, "test_info.json"))
                               or os.path.exists(os.path.join(self._tcroot, entry, "test_info.txt"))],
                              key=lambda x: -int(x.rsplit('-', 1)[1]))
                if not dirs:
                    raise NoTestcaseError("No testcase recognized at %r" % (testcase,))

            # check for included prefs and environment
            if "prefs.js" in os.listdir(dirs[0]):
                # move the file out of tcroot because we prune these non-testcase files later
                os.rename(os.path.join(dirs[0], "prefs.js"), os.path.join(self._tmpdir, "prefs.js"))
                self._target.prefs = os.path.abspath(os.path.join(self._tmpdir, "prefs.js"))
                LOG.warning("Using prefs included in testcase: %r", self._target.prefs)
            if "test_info.json" in os.listdir(dirs[0]):
                self.config_environ(os.path.join(dirs[0], "test_info.json"))
            elif "env_vars.txt" in os.listdir(dirs[0]):
                # TODO: remove this block once move to 'test_info.json' is complete
                self.config_environ(os.path.join(dirs[0], "env_vars.txt"))
            if self._env_mod:
                LOG.warning("Using environment included in testcase")
                self._target.forced_close = self._env_mod.get("GRZ_FORCED_CLOSE") != "0"

            # if dirs is singular, we can use the testcase directly, otherwise we need to iterate over
            # them all in order
            pages = [self._get_landing_page(d) for d in dirs]
            if len(pages) == 1:
                self._testcase = pages[0]
                self._cache_iter_harness_created = False

            else:
                # create a harness to iterate over the whole history
                harness_path = os.path.join(os.path.dirname(__file__), '..', 'common', 'harness.html')
                with io.open(harness_path, encoding="utf-8") as harness_fp:
                    harness = harness_fp.read()
                # change dump string so that logs can be told apart
                harness = harness.replace("[grz harness]", "[cache iter]")
                # change the window name so that window.open doesn't clobber self
                harness = harness.replace("'GrizzlyFuzz'", "'CacheIterator'")
                # insert the iteration timeout. insert it directly because we can't set a hash value
                new_harness = re.sub(r"^(\s*let\s.*\btime_limit\b)",
                                     r"\1 = %d" % (self._iter_timeout * 1000),
                                     harness,
                                     flags=re.MULTILINE)
                if new_harness == harness:
                    raise ReducerError("Unable to set time_limit in harness, please update pattern "
                                       "to match harness!")
                harness = new_harness
                # make first test and next test grab from the array
                harness = harness.replace("'/grz_current_test'", "_reduce_next()")
                harness = harness.replace("'/grz_next_test'", "_reduce_next()")
                # insert the close condition. we are iterating over the array of landing pages,
                # undefined means we hit the end and the harness should close
                # newer harness uses conditional operator in open() call
                if re.search(r'open\(.*_reduce_next\(\)\s*:\s*_reduce_next\(\)', harness) is None:
                    raise ReducerError("Unable to insert finish condition, please update pattern "
                                       "to match harness!")
                # insert the landing page loop
                harness = harness.replace("<script>", "\n".join([
                    "<script>",
                    "let _reduce_tests = [",
                    "//DDBEGIN",
                    "'" + "',\n'".join(self._http_abspath(p) for p in pages) + "',",
                    "//DDEND",
                    "]",
                    "let _reduce_next = () => {",
                    "  if (!_reduce_tests.length) window.close()",
                    "  return _reduce_tests.shift()",
                    "}"
                ]))

                harness_fp, harness_path = \
                    tempfile.mkstemp(prefix="harness_", suffix=".html", dir=self._tcroot)
                os.close(harness_fp)
                with io.open(harness_path, "w", encoding="utf-8") as harness_fp:
                    harness_fp.write(harness)
                self._testcase = harness_path
                self._cache_iter_harness_created = True

            # prune unnecessary files from the testcase
            prune = {"env_vars.txt", "grizzly_fuzz_harness.html",
                     "log_metadata.json", "prefs.js", "reducelog.txt",
                     "screenlog.txt", "test_info.json", "test_info.txt"}
            for root, _, files in os.walk(self._tcroot):
                for file_ in files:
                    if file_ in prune or (file_.startswith("log_") and file_.endswith(".txt")):
                        os.unlink(os.path.join(root, file_))
        except NoTestcaseError as exc:
            LOG.warning("Could not set-up testcase: %s", exc)
            self._result_code = FuzzManagerReporter.QUAL_NO_TESTCASE
            raise
        except Exception as exc:
            LOG.warning("Could not set-up testcase: %s", exc)
            self._result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self, keep_temp=False):
        """Clean up any resources used for this job.

        Args:
            None

        Returns:
            None
        """
        self._stop_log_capture()
        if self._tmpdir is not None and os.path.isdir(self._tmpdir):
            if keep_temp:
                LOG.warning("Leaving working files at %r for inspection.", self._tmpdir)
            else:
                shutil.rmtree(self._tmpdir)
                self._tmpdir = None
        if self._target is not None:
            self._target.cleanup()

    def _report_result(self, testcase, temp_prefix, quality_value, force=False):
        self._reporter.quality = quality_value
        self._reporter.force_report = force
        self._reporter.submit([testcase], log_path=temp_prefix + "_logs")

    def on_interesting_crash(self, temp_prefix):
        # called for any interesting crash
        self._interesting_prefix = temp_prefix

    def on_result(self, result_code):
        pass

    def on_other_crash_found(self, testcase, temp_prefix):
        """
        If we hit an alternate crash, store the testcase in a tmp folder.
        If the same crash is encountered again, only keep the newest one.
        """
        crash_info = FuzzManagerReporter.create_crash_info(
            Report.from_path(temp_prefix + "_logs"),
            self._target.binary)
        crash_hash = Report.crash_hash(crash_info)
        if crash_hash in self._other_crashes:
            LOG.info("Found alternate crash (newer): %s", crash_info.createShortSignature())
            # already counted when initially found
            self._status.ignored += 1
        else:
            LOG.info("Found alternate crash: %s", crash_info.createShortSignature())
            self._status.results += 1
        self._other_crashes[crash_hash] = {"tc": testcase, "prefix": temp_prefix}

    def _report_other_crashes(self):
        """
        After reduce is finished, report any alternate results (if they don't match the collector cache).
        """
        for entry in self._other_crashes.values():
            self._report_result(entry["tc"], entry["prefix"], FuzzManagerReporter.QUAL_UNREDUCED)

    def run(self, strategies=None):
        """Run reduction.
        """
        assert self._testcase is not None
        assert self._reporter is not None

        try:
            # set up lithium
            reducer = lithium.Lithium()
            self._orig_sig = self._signature
            self.landing_page = self._testcase
            reducer.conditionScript = LithiumInterestingProxy(self)

            # if we created a harness to iterate over history, files_to_reduce is initially just
            #   that harness
            # otherwise, the first stage will be skipped and we will scan for all testcases to
            #   reduce in the second stage

            run_state = RunState([self._testcase])

            # resolve list of strategies to apply
            reduce_stages = [strategies_module.MinimizeCacheIterHarness, strategies_module.ScanFilesToReduce]
            if not self._skip_analysis:
                if self._cache_iter_harness_created:
                    # if we created a cache iterator harness analyze that first
                    reduce_stages.insert(0, strategies_module.AnalyzeTestcase)
                reduce_stages.append(strategies_module.AnalyzeTestcase)
            if strategies is None:
                strategies = self.DEFAULT_STRATEGIES
            strategies_lut = strategies_module.strategies_by_name()
            for strat in strategies:
                try:
                    strat = strategies_lut[strat]
                except KeyError:
                    raise ReducerError("Unknown strategy given: %r" % (strat,))
                reduce_stages.append(strat)

            # run lithium reduce with strategies

            files_reduced = 0
            for strategy_num, strategy_type in enumerate(reduce_stages):

                result = -1
                strategy = strategy_type(self, run_state, reducer)

                for testcase_path in run_state.files_to_reduce:

                    strategy.read_testcase(testcase_path)
                    if strategy.should_skip():
                        result = 0
                        continue

                    self.reduce_file = testcase_path
                    # set up tempdir manually so it doesn't go in cwd
                    reducer.tempDir = tempfile.mkdtemp(
                        prefix="lith-%d-%s" % (strategy_num, strategy_type.name),
                        dir=self._tmpdir)

                    reducer.testCount = reducer.testTotal = 0
                    result = reducer.run()

                    try:
                        if result == 0:
                            strategy.on_success()
                            files_reduced += 1

                        else:
                            strategy.on_failure()
                            result = 0  # if we passed on failure, don't fail below

                    except StopIteration:
                        break

                if result != 0:
                    # reducer failed to repro the crash
                    if files_reduced == 0:
                        # first stage, couldn't repro at all
                        LOG.warning("Could not reduce: The testcase was not reproducible")
                        self._result_code = FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE

                    else:
                        # subsequent stage, reducing broke the testcase?
                        # unclear how to recover from this.
                        # just report failure and hopefully we have another to try
                        LOG.warning("%s failed to reproduce. Previous stage broke the testcase?",
                                    strategy_type.__name__)
                        self._result_code = FuzzManagerReporter.QUAL_REDUCER_BROKE

                    return False

            # all stages succeeded
            reduced_size = run_state.total_size()
            if reduced_size == run_state.original_size:
                raise ReducerError("Reducer succeeded but nothing was reduced!")

            self._report_result(self._best_testcase,
                                self._interesting_prefix,
                                FuzzManagerReporter.QUAL_REDUCED_RESULT,
                                force=True)

            # change original quality so unbucketed crashes don't reduce again
            self._result_code = FuzzManagerReporter.QUAL_REDUCED_ORIGINAL
            return True

        except ReducerError as exc:
            LOG.warning("Could not reduce: %s", exc)
            self._result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            return False

        except Exception:  # pylint: disable=broad-except
            LOG.exception("Exception during reduce")
            self._result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            return False

        finally:
            self._report_other_crashes()

    def set_reporter(self, reporter):
        self._reporter = reporter

    @classmethod
    def from_args(cls, args, target, status):
        job = cls(
            args.ignore,
            target,
            args.timeout,
            args.no_harness,
            args.any_crash,
            args.skip,
            args.min_crashes,
            args.repeat,
            args.idle_threshold,
            args.idle_timeout,
            status,
            not args.no_cache,
            args.no_analysis)

        job.config_testcase(args.input)

        # arguments for environ and prefs should override the testcase
        if args.environ:
            LOG.warning("Overriding environment with %r", args.environ)
            job.config_environ(args.environ)
        if args.prefs:
            LOG.warning("Overriding prefs with %r", args.prefs)
            job.target.prefs = os.path.abspath(args.prefs)

        if args.sig is not None:
            with io.open(args.sig, encoding="utf-8") as sig_fp:
                job.config_signature(sig_fp.read())

        LOG.debug("initializing the Reporter")
        if args.fuzzmanager:
            LOG.info("Reporting issues via FuzzManager")
            job.set_reporter(FuzzManagerReporter(args.binary, tool=args.tool))
        else:
            reporter = FilesystemReporter()
            job.set_reporter(reporter)
            LOG.info("Results will be stored in %r", reporter.report_path)

        if args.fixed_timeout:
            LOG.info("Using a fixed iteration timeout")
        job._fixed_timeout = args.fixed_timeout

        return job

    @classmethod
    def main(cls, args):
        # NOTE: this mirrors grizzly.core.main pretty closely
        #       please check if updates here should go there too
        configure_logging(args.log_level)
        LOG.info("Starting Grizzly Reducer")
        if args.fuzzmanager:
            FuzzManagerReporter.sanity_check(args.binary)

        if args.ignore:
            LOG.info("Ignoring: %s", ", ".join(args.ignore))
        if args.xvfb:
            LOG.info("Running with Xvfb")
        if args.valgrind:
            LOG.info("Running with Valgrind. This will be SLOW!")

        target = None
        job = None

        status = Status.start()
        job_cancelled = False
        try:
            LOG.debug("initializing the Target")

            target = load_target(args.platform)(
                args.binary,
                args.extension,
                args.launch_timeout,
                args.log_limit,
                args.memory,
                None,  # prefs
                args.relaunch,
                valgrind=args.valgrind,
                xvfb=args.xvfb)

            job = cls.from_args(args, target, status)

            result = job.run(strategies=args.strategies)

            # report result out if callback requested
            job.on_result(job.result_code)

            # update stats
            with ReducerStats() as stats:
                if result:
                    stats.passed += 1
                elif job.result_code in (6, 10):
                    stats.failed += 1
                elif job.result_code in (7, 8, 9):
                    stats.error += 1

            if result:
                LOG.info("Reduction succeeded: %s", FuzzManagerReporter.quality_name(job.result_code))
                return Session.EXIT_SUCCESS

            LOG.warning("Reduction failed: %s", FuzzManagerReporter.quality_name(job.result_code))
            return Session.EXIT_ERROR

        except NoTestcaseError:
            with ReducerStats() as stats:
                stats.error += 1
            # TODO: test should be marked as Q7
            return Session.EXIT_ERROR

        except KeyboardInterrupt:
            job_cancelled = True
            return Session.EXIT_ABORT

        except (TargetLaunchError, TargetLaunchTimeout) as exc:
            LOG.error("Error launching target: %s", exc)
            with ReducerStats() as stats:
                stats.error += 1
            return Session.EXIT_LAUNCH_FAILURE

        finally:
            LOG.warning("Shutting down...")
            if job is not None and not job_cancelled:
                job_cancelled = job.result_code in {FuzzManagerReporter.QUAL_REDUCER_BROKE,
                                                    FuzzManagerReporter.QUAL_REDUCER_ERROR}
            if job is not None:
                job.close(keep_temp=job_cancelled)
            elif target is not None:
                # job handles calling cleanup if it was created
                target.cleanup()
            # call cleanup if we are unlikely to be using status again
            status.cleanup()
