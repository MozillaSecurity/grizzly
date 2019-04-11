# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Given a build and testcase, try to reproduce it using a set of strategies.
"""
from __future__ import absolute_import
import hashlib
import io
import logging
import math
import os
import re
import shutil
import tempfile
import zipfile
import zlib

import ffpuppet
import lithium
from FTB.Signatures.CrashInfo import CrashSignature

from . import strategies as strategies_module
from .interesting import Interesting
from ..core import Session
from ..corpman.storage import TestFile, TestCase
from ..reporter import FilesystemReporter, FuzzManagerReporter, Report
from ..target import Target


__author__ = "Jesse Schwartzentruber"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber", "Jason Kratzer"]


LOG = logging.getLogger("grizzly.reduce")


class ReducerError(Exception):
    pass


class NoTestcaseError(ReducerError):
    pass


def _testcase_contents(path="."):
    for dir_name, _, dir_files in os.walk(path):
        arc_path = os.path.relpath(dir_name, path)
        # skip tmp folders
        if re.match(r"^tmp.+$", arc_path.split(os.sep, 1)[0]) is not None:
            continue
        for file_name in dir_files:
            # skip core files
            if re.match(r"^core.\d+$", file_name) is not None:
                continue
            if arc_path == ".":
                yield file_name
            else:
                yield os.path.join(arc_path, file_name)


class ReductionJob(object):
    LOGGERS_TO_WATCH = ("ffpuppet", "grizzly", "lithium", "sapphire")
    DEFAULT_STRATEGIES = ("line", "jsbeautify", "collapsebraces", "jschar")

    def __init__(self, ignore, target, iter_timeout, no_harness, any_crash, skip, min_crashes,
                 repeat, idle_poll, idle_threshold, idle_timeout, working_path=None,
                 testcase_cache=True, skip_analysis=False):
        """Use lithium to reduce a testcase.

        Args:
            target (grizzly.target.Target): Target object to use for reduction.
        """
        self.reporter = None
        self.result_code = None
        self.signature = None
        self.interesting = Interesting(
            ignore,
            target,
            iter_timeout,
            no_harness,
            any_crash,
            skip,
            min_crashes,
            repeat,
            idle_poll,
            idle_threshold,
            idle_timeout,
            testcase_cache)
        self.interesting.alt_crash_cb = self._other_crash_found
        self.interesting.interesting_cb = self._interesting_crash
        self.testcase = None
        self.tmpdir = tempfile.mkdtemp(prefix="grzreduce", dir=working_path)
        self.tcroot = os.path.join(self.tmpdir, "tc")
        self.other_crashes = {}
        self.input_fname = None
        self.interesting_prefix = None
        self.log_handler = self._start_log_capture()
        self.cache_iter_harness_created = None
        self.skip_analysis = skip_analysis
        if not self.skip_analysis:
            # see if any of the args tweaked by analysis were overridden
            # --relaunch is regarded as a maximum, so overriding the default is not a deal-breaker for analysis
            if self.interesting.min_crashes != 1:
                LOG.warning("--min-crashes=%d was given, skipping analysis", self.interesting.min_crashes)
                self.skip_analysis = True
            elif self.interesting.repeat != 1:
                LOG.warning("--repeat=%d was given, skipping analysis", self.interesting.repeat)
                self.skip_analysis = True
        self.original_relaunch = target.rl_reset
        self.force_no_harness = self.interesting.no_harness

    def _start_log_capture(self):
        """Add a log handler for grizzly and lithium messages generated during this job.
        The handler is removed again by close()

        Args:
            None

        Returns:
            logging.Handler: The log handler to be removed later.
        """
        formatter = logging.Formatter("%(levelname).1s %(name)s [%(asctime)s] %(message)s")
        handler = logging.FileHandler(os.path.join(self.tmpdir, "reducelog.txt"))
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        for logname in self.LOGGERS_TO_WATCH:
            logging.getLogger(logname).addHandler(handler)

        # check that DEBUG messages will actually get through
        # if the root logger level is > DEBUG, messages will not get through to our log handler
        # set root to DEBUG, and propogate the old root level to each root handler
        root_logger = logging.getLogger()
        root_level = root_logger.getEffectiveLevel()
        if root_level > logging.DEBUG:
            root_logger.setLevel(logging.DEBUG)
            for root_handler in root_logger.handlers:
                if root_handler.level < root_level:
                    root_handler.setLevel(root_level)

        return handler

    def _stop_log_capture(self):
        """Stop handling reduce logs.

        Args:
            None

        Returns:
            None
        """
        if self.log_handler is None:
            return
        for logname in self.LOGGERS_TO_WATCH:
            logging.getLogger(logname).removeHandler(self.log_handler)
        self.log_handler.flush()
        self.log_handler.close()
        self.log_handler = None

    def config_signature(self, signature):
        """Configure a signature to use for reduction.  If none is given, an automatic signature is
        created based on the initial repro.

        Args:
            signature (str): A JSON signature to match for reduction.

        Returns:
            None
        """
        self.signature = CrashSignature(signature)

    @staticmethod
    def _get_landing_page(testpath):
        """Parse test_info.txt for landing page

        Args:
            testpath (str): Path to a testcase folder (containing a test_info.txt from Grizzly).

        Returns:
            str: Path to the landing page within testpath
        """
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
        path = os.path.relpath(path, self.tcroot)
        return '/' + '/'.join(path.split(os.sep))

    def config_testcase(self, testcase):
        """Prepare a user provided testcase for reduction.

        Args:
            testcase (str): Path to a testcase. This should be a Grizzly testcase (zip or folder) or html file.

        Returns:
            None
        """
        try:
            # extract the testcase if necessary
            if os.path.exists(self.tcroot):
                raise ReducerError("Testcase already configured?")
            if os.path.isfile(testcase):
                if testcase.lower().endswith(".html"):
                    os.mkdir(self.tcroot)
                    shutil.copy(testcase, self.tcroot)
                    with open(os.path.join(self.tcroot, "test_info.txt"), "w") as info_fp:
                        info_fp.write("landing page: %s\n" % (os.path.basename(testcase),))
                elif testcase.lower().endswith(".zip"):
                    os.mkdir(self.tcroot)
                    try:
                        with zipfile.ZipFile(testcase) as zip_fp:
                            zip_fp.extractall(path=self.tcroot)
                    except zlib.error:
                        raise ReducerError("Testcase is corrupted")
                else:
                    raise ReducerError("Testcase must be zip, html, or directory")
            elif os.path.isdir(testcase):
                shutil.copytree(testcase, self.tcroot)
            else:
                raise ReducerError("Testcase must be zip, html or directory")

            self.input_fname = os.path.basename(testcase)

            # get a list of all directories containing testcases (1-n, depending on how much history
            # grizzly saved)
            entries = set(os.listdir(self.tcroot))
            if "test_info.txt" in entries:
                dirs = [self.tcroot]
            else:
                dirs = sorted([os.path.join(self.tcroot, entry) for entry in entries
                               if os.path.exists(os.path.join(self.tcroot, entry, "test_info.txt"))],
                              key=lambda x: -int(x.rsplit('-', 1)[1]))
                if not dirs:
                    raise NoTestcaseError("No testcase recognized at %r" % (testcase,))

            # check for included prefs and environment
            if "prefs.js" in os.listdir(dirs[0]):
                # move the file out of tcroot because we prune these non-testcase files later
                os.rename(os.path.join(dirs[0], "prefs.js"), os.path.join(self.tmpdir, "prefs.js"))
                self.interesting.target.prefs = os.path.abspath(os.path.join(self.tmpdir, "prefs.js"))
                LOG.warning("Using prefs included in testcase: %r", self.interesting.target.prefs)
            if "env_vars.txt" in os.listdir(dirs[0]):
                self.interesting.config_environ(os.path.join(dirs[0], "env_vars.txt"))
                LOG.warning("Using environment included in testcase: %s",
                            os.path.abspath(os.path.join(dirs[0], "env_vars.txt")))

            # if dirs is singular, we can use the testcase directly, otherwise we need to iterate over
            # them all in order
            pages = [self._get_landing_page(d) for d in dirs]
            if len(pages) == 1:
                self.testcase = pages[0]
                self.cache_iter_harness_created = False

            else:
                # create a harness to iterate over the whole history
                harness_path = os.path.join(os.path.dirname(__file__), '..', 'corpman', 'harness.html')
                with io.open(harness_path, encoding="utf-8") as harness_fp:
                    harness = harness_fp.read()
                # change dump string so that logs can be told apart
                harness = harness.replace("[grz harness]", "[cache iter]")
                # change the window name so that window.open doesn't clobber self
                harness = harness.replace("'GrizzlyFuzz'", "'CacheIterator'")
                # insert the iteration timeout. insert it directly because we can't set a hash value
                new_harness = re.sub(r"^(\s*let\s.*\btime_limit\b)",
                                     r"\1 = %d" % (self.interesting.iter_timeout * 1000),
                                     harness,
                                     flags=re.MULTILINE)
                if new_harness == harness:
                    raise ReducerError("Unable to set time_limit in harness, please update pattern "
                                       "to match harness!")
                harness = new_harness
                # make first test and next test grab from the array
                harness = harness.replace("'/first_test'", "_reduce_next()")
                harness = harness.replace("'/next_test'", "_reduce_next()")
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
                    tempfile.mkstemp(prefix="harness_", suffix=".html", dir=self.tcroot)
                os.close(harness_fp)
                with io.open(harness_path, "w", encoding="utf-8") as harness_fp:
                    harness_fp.write(harness)
                self.testcase = harness_path
                self.cache_iter_harness_created = True

            # prune unnecessary files from the testcase
            for root, _, files in os.walk(self.tcroot):
                for file_ in files:
                    if file_ in {"env_vars.txt", "grizzly_fuzz_harness.html", "log_metadata.json",
                                 "prefs.js", "screenlog.txt", "test_info.txt"} or \
                            (file_.startswith("log_") and file_.endswith(".txt")):
                        os.unlink(os.path.join(root, file_))
        except NoTestcaseError as exc:
            LOG.warning("Could not set-up testcase: %s", exc)
            self.result_code = FuzzManagerReporter.QUAL_NO_TESTCASE
            raise
        except Exception as exc:
            LOG.warning("Could not set-up testcase: %s", exc)
            self.result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            raise

    def close(self, keep_temp=False):
        """Clean up any resources used for this job.

        Args:
            None

        Returns:
            None
        """
        self._stop_log_capture()
        if self.tmpdir is not None and os.path.isdir(self.tmpdir):
            if keep_temp:
                LOG.warning("Leaving working files at %r for inspection.", self.tmpdir)
            else:
                shutil.rmtree(self.tmpdir)
                self.tmpdir = None
        if self.interesting.target is not None:
            self.interesting.target.cleanup()

    def _report_result(self, tcroot, temp_prefix, quality_value, force=False, include_logs=False):
        self.reporter.quality = quality_value
        self.reporter.force_report = force

        landing_page = os.path.relpath(self.testcase, self.tcroot)
        testcase = TestCase(landing_page, None, "grizzly.reduce", input_fname=self.input_fname)

        # add testcase contents
        for file_name in _testcase_contents(tcroot):
            testcase.add_file(TestFile.from_file(os.path.join(tcroot, file_name), file_name))

        # add reduce log
        if include_logs:
            LOG.info("Closing reduce log for report submission")
            self._stop_log_capture()
            testcase.add_meta(TestFile.from_file(os.path.join(self.tmpdir, "reducelog.txt"), "reducelog.txt"))

        # add prefs
        if self.interesting.target.prefs is not None:
            testcase.add_meta(TestFile.from_file(self.interesting.target.prefs, "prefs.js"))

        # add environment variables
        if self.interesting.env_mod is not None:
            for name, value in self.interesting.env_mod.items():
                testcase.add_environ_var(name, value)

        self.reporter.submit(temp_prefix + "_logs", [testcase])

    def _interesting_crash(self, temp_prefix):
        self.interesting_prefix = temp_prefix

    def _other_crash_found(self, temp_prefix):
        """
        If we hit an alternate crash, store the testcase in a tmp folder.
        If the same crash is encountered again, only keep the newest one.
        """
        crash_info = FuzzManagerReporter.create_crash_info(
            Report.from_path(temp_prefix + "_logs"),
            self.interesting.target.binary)
        max_frames = FuzzManagerReporter.signature_max_frames(crash_info, 5)
        this_sig = crash_info.createCrashSignature(maxFrames=max_frames)
        crash_hash = hashlib.sha256(this_sig.rawSignature.encode("utf-8")).hexdigest()[:10]
        tmpd = os.path.join(self.tmpdir, "alt", crash_hash)
        if crash_hash in self.other_crashes:
            shutil.rmtree(self.other_crashes[crash_hash]["tcroot"])
            LOG.info("Found alternate crash (newer): %s", crash_info.createShortSignature())
        else:
            LOG.info("Found alternate crash: %s", crash_info.createShortSignature())
        os.makedirs(tmpd)
        for file_name in _testcase_contents(self.tcroot):
            out = os.path.join(tmpd, file_name)
            out_dir = os.path.dirname(out)
            if not os.path.isdir(out_dir):
                os.makedirs(out_dir)
            shutil.copyfile(os.path.join(self.tcroot, file_name), out)
        self.other_crashes[crash_hash] = {"tcroot": os.path.realpath(tmpd), "prefix": temp_prefix}

    def _report_other_crashes(self):
        """
        After reduce is finished, report any alternate results (if they don't match the collector cache).
        """
        for entry in self.other_crashes.values():
            self._report_result(entry["tcroot"], entry["prefix"], FuzzManagerReporter.QUAL_UNREDUCED)

    def run(self, strategies=None):
        """Run reduction.
        """
        assert self.testcase is not None
        assert self.reporter is not None

        try:
            # set up lithium
            reducer = lithium.Lithium()
            self.interesting.orig_sig = self.signature
            self.interesting.landing_page = self.testcase
            reducer.conditionScript = self.interesting

            class _AnalyzeReliability(lithium.Strategy):
                name = "reliability-analysis"
                ITERATIONS = 11  # number of iterations to analyze
                MIN_CRASHES = 2  # --min-crashes value when analysis is used
                TARGET_PROBABILITY = 0.95  # probability that successful reduction will observe the crash
                # to see the worst case, run the `self.interesting.repeat` calculation below using
                # crashes_percent = 1.0/ITERATIONS

                def main(sub, testcase, interesting, tempFilename):

                    assert sub.ITERATIONS > 0

                    # disable result cache setting
                    use_result_cache = self.interesting.use_result_cache
                    self.interesting.use_result_cache = False

                    # reset parameters
                    # use repeat=1 & relaunch=ITERATIONS because this is closer to how we will run post-analysis
                    # we're only using repeat=1 instead of repeat=ITERATIONS so we can get feedback on every
                    # call to interesting
                    self.interesting.repeat = 1
                    self.interesting.min_crashes = 1
                    self.interesting.target.rl_reset = min(self.original_relaunch, sub.ITERATIONS)

                    harness_crashes = 0
                    non_harness_crashes = 0

                    # close target so new parameters take effect
                    if not self.interesting.target.closed:
                        self.interesting.target.close()

                    if not self.force_no_harness:
                        LOG.info("Running for %d iterations to assess reliability using harness.", sub.ITERATIONS)
                        for _ in range(sub.ITERATIONS):
                            result = interesting(testcase, writeIt=False)  # pylint: disable=invalid-name
                            LOG.info("Lithium result: %s", "interesting." if result else "not interesting.")
                            if result:
                                harness_crashes += 1
                        LOG.info("Testcase was interesting %0.1f%% of %d attempts using harness for iteration.",
                                 100.0 * harness_crashes / sub.ITERATIONS, sub.ITERATIONS)

                        # close target so new parameters take effect
                        if not self.interesting.target.closed:
                            self.interesting.target.close()

                    if harness_crashes != sub.ITERATIONS:
                        # try without harness
                        self.interesting.no_harness = True

                        LOG.info("Running for %d iterations to assess reliability without harness.", sub.ITERATIONS)
                        for _ in range(sub.ITERATIONS):
                            result = interesting(testcase, writeIt=False)  # pylint: disable=invalid-name
                            LOG.info("Lithium result: %s", "interesting." if result else "not interesting.")
                            if result:
                                non_harness_crashes += 1
                        LOG.info("Testcase was interesting %0.1f%% of %d attempts without harness.",
                                 100.0 * non_harness_crashes / sub.ITERATIONS, sub.ITERATIONS)

                        # close target so new parameters take effect
                        if not self.interesting.target.closed:
                            self.interesting.target.close()

                    # restore result cache setting
                    self.interesting.use_result_cache = use_result_cache

                    if harness_crashes == 0 and non_harness_crashes == 0:
                        return 1  # no crashes ever?

                    # should we use the harness? go with whichever crashed more
                    self.interesting.no_harness = non_harness_crashes > harness_crashes
                    # this is max 99% to avoid domain errors in the calculation below
                    crashes_percent = min(1.0 * max(non_harness_crashes, harness_crashes) / sub.ITERATIONS, 0.99)

                    # adjust repeat/min-crashes depending on how reliable the testcase was
                    self.interesting.min_crashes = sub.MIN_CRASHES
                    self.interesting.repeat = int(math.log(1 - sub.TARGET_PROBABILITY, 1 - crashes_percent) + 0.5) \
                        * sub.MIN_CRASHES

                    # set relaunch to min(relaunch, repeat)
                    self.interesting.target.rl_reset = min(self.original_relaunch, self.interesting.repeat)

                    LOG.info("Analysis results:")
                    if harness_crashes == sub.ITERATIONS:
                        LOG.info("* testcase was perfectly reliable with the harness (--no-harness not assessed)")
                    elif harness_crashes == non_harness_crashes:
                        LOG.info("* testcase was equally reliable with/without the harness")
                    elif self.force_no_harness:
                        LOG.info("* --no-harness was already set")
                    else:
                        LOG.info("* testcase was %s reliable with the harness",
                                 "less" if self.interesting.no_harness else "more")
                    LOG.info("* adjusted parameters: --min-crashes=%d --repeat=%d --relaunch=%d",
                             self.interesting.min_crashes, self.interesting.repeat, self.interesting.target.rl_reset)

                    return 0

            class AnalyzeTestcase(strategies_module.ReduceStage):
                name = "analyze"
                strategy_type = _AnalyzeReliability
                testcase_type = lithium.TestcaseLine

                def on_success(sub):  # pylint: disable=no-self-argument
                    super(AnalyzeTestcase, sub).on_success()
                    raise StopIteration()  # only run this strategy once, not once per reducible file in the testcase

            class MinimizeCacheIterHarness(strategies_module.MinimizeLines):

                def should_skip(sub):  # pylint: disable=no-self-argument
                    return not self.cache_iter_harness_created

                def read_testcase(sub, reducer, testcase_path):  # pylint: disable=no-self-argument
                    if sub.should_skip():
                        return

                    strategies_module.MinimizeLines.read_testcase(sub, reducer, testcase_path)

                    # we are running multiple testcases in a single "iteration", so we need to
                    #   fix the timeout values

                    # start polling for idle after n-1 testcases have finished
                    self.interesting.idle_timeout += \
                        self.interesting.idle_timeout * (len(reducer.testcase) - 1)

                    # iteration timeout is * n testcases, but add 10 seconds for overhead from the
                    #   outer harness
                    self.interesting.iter_timeout = \
                        (self.interesting.iter_timeout + 10) * len(reducer.testcase)

                def on_success(sub):  # pylint: disable=no-self-argument
                    while files_to_reduce:
                        files_to_reduce.pop()
                    lines = lithium.TestcaseLine()
                    lines.readTestcase(self.testcase)
                    if len(lines) == 1:
                        # we reduced this down to a single testcase, remove the harness
                        testcase_rel = lines.parts[0].strip().decode("utf-8")
                        assert testcase_rel.startswith("'/")
                        assert testcase_rel.endswith("',")
                        testcase_rel = testcase_rel[2:-2]  # trim chars asserted above
                        testcase_path = testcase_rel.split('/')
                        assert len(testcase_path) == 2
                        self.tcroot = os.path.join(self.tcroot, testcase_path[0])
                        self.testcase = os.path.join(self.tcroot, testcase_path[1])
                        self.interesting.landing_page = self.testcase
                        files_to_reduce.append(self.testcase)
                        LOG.info("Reduced history to a single file: %s", testcase_path[1])
                    else:
                        # don't bother trying to reduce the harness further,
                        #   leave harness out of files_to_reduce
                        LOG.info("Reduced history down to %d testcases", len(reducer.testcase))

            class ScanFilesToReduce(strategies_module.ReduceStage):

                def __init__(sub):  # pylint: disable=no-self-argument
                    # find all files for reduction
                    for file_name in _testcase_contents(self.tcroot):
                        file_name = os.path.join(self.tcroot, file_name)
                        if file_name == self.testcase:
                            continue
                        with open(file_name, "rb") as tc_fp:
                            for line in tc_fp:
                                if b"DDBEGIN" in line:
                                    files_to_reduce.append(file_name)
                                    break
                    if len(files_to_reduce) > 1:
                        # sort by descending size
                        files_to_reduce.sort(key=lambda fn: os.stat(fn).st_size, reverse=True)
                    original_size[0] = sum(os.stat(fn).st_size for fn in files_to_reduce)

                def read_testcase(sub, reducer, testcase_path):  # pylint: disable=no-self-argument
                    pass

                def should_skip(sub):  # pylint: disable=no-self-argument
                    # no real reduce strategy, just used to scan for files
                    return True

            # if we created a harness to iterate over history, files_to_reduce is initially just
            #   that harness
            # otherwise, the first stage will be skipped and we will scan for all testcases to
            #   reduce in the second stage
            files_to_reduce = [self.testcase]
            original_size = [None]

            # resolve list of strategies to apply
            reduce_stages = [MinimizeCacheIterHarness, ScanFilesToReduce]
            if not self.skip_analysis:
                if self.cache_iter_harness_created:
                    # if we created a cache iterator harness analyze that first
                    reduce_stages.insert(0, AnalyzeTestcase)
                reduce_stages.append(AnalyzeTestcase)
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
                strategy = strategy_type()

                for testcase_path in files_to_reduce:

                    strategy.read_testcase(reducer, testcase_path)
                    if strategy.should_skip():
                        result = 0
                        continue

                    self.interesting.reduce_file = testcase_path
                    # set up tempdir manually so it doesn't go in cwd
                    reducer.tempDir = tempfile.mkdtemp(
                        prefix="lith-%d-%s" % (strategy_num, strategy_type.name),
                        dir=self.tmpdir)

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
                        self.result_code = FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE

                    else:
                        # subsequent stage, reducing broke the testcase?
                        # unclear how to recover from this.
                        # just report failure and hopefully we have another to try
                        LOG.warning("%s failed to reproduce. Previous stage broke the testcase?",
                                    strategy_type.__name__)
                        self.result_code = FuzzManagerReporter.QUAL_REDUCER_BROKE

                    return False

            # all stages succeeded
            reduced_size = sum(os.stat(fn).st_size for fn in files_to_reduce)
            if reduced_size == original_size[0]:
                raise ReducerError("Reducer succeeded but nothing was reduced!")

            self._report_result(self.tcroot,
                                self.interesting_prefix,
                                FuzzManagerReporter.QUAL_REDUCED_RESULT,
                                force=True,
                                include_logs=True)

            # change original quality so unbucketed crashes don't reduce again
            self.result_code = FuzzManagerReporter.QUAL_REDUCED_ORIGINAL
            return True

        except ReducerError as exc:
            LOG.warning("Could not reduce: %s", exc)
            self.result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            return False

        except Exception:  # pylint: disable=broad-except
            LOG.exception("Exception during reduce")
            self.result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            return False

        finally:
            self._report_other_crashes()


def main(args, interesting_cb=None, result_cb=None):
    # NOTE: this mirrors grizzly.core.main pretty closely
    #       please check if updates here should go there too
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

    job_cancelled = False
    try:
        LOG.debug("initializing the Target")
        target = Target(
            args.binary,
            args.extension,
            args.launch_timeout,
            args.log_limit,
            args.memory,
            None,
            args.relaunch,
            False,  # rr
            args.valgrind,
            args.xvfb)

        job = ReductionJob(
            args.ignore,
            target,
            args.timeout,
            args.no_harness,
            args.any_crash,
            args.skip,
            args.min_crashes,
            args.repeat,
            args.idle_poll,
            args.idle_threshold,
            args.idle_timeout,
            args.working_path,
            not args.no_cache,
            args.no_analysis)

        job.config_testcase(args.input)

        # arguments for environ and prefs should override the testcase
        if args.environ:
            LOG.warning("Overriding environment with %r", args.environ)
            job.interesting.config_environ(args.environ)
        if args.prefs:
            LOG.warning("Overriding prefs with %r", args.prefs)
            job.interesting.target.prefs = os.path.abspath(args.prefs)

        if args.sig is not None:
            with io.open(args.sig, encoding="utf-8") as sig_fp:
                job.config_signature(sig_fp.read())

        LOG.debug("initializing the Reporter")
        if args.fuzzmanager:
            LOG.info("Reporting issues via FuzzManager")
            job.reporter = FuzzManagerReporter(
                args.binary,
                log_limit=Session.FM_LOG_SIZE_LIMIT,
                tool=args.tool)
        else:
            job.reporter = FilesystemReporter()
            LOG.info("Results will be stored in %r", job.reporter.report_path)

        # detect soft assertions
        if args.soft_asserts:
            job.interesting.target._puppet.add_abort_token("###!!! ASSERTION:")

        # setup interesting callback if requested
        if interesting_cb is not None:
            orig_interesting_cb = job.interesting.interesting_cb
            def _on_interesting(*args, **kwds):
                if orig_interesting_cb is not None:
                    orig_interesting_cb(*args, **kwds)
                interesting_cb()
            job.interesting.interesting_cb = _on_interesting

        result = job.run(strategies=args.strategies)

        # report result out if callback requested
        if result_cb is not None:
            result_cb(job.result_code)

        if result:
            LOG.info("Reduction succeeded: %s", FuzzManagerReporter.quality_name(job.result_code))
            return Session.EXIT_SUCCESS

        LOG.warning("Reduction failed: %s", FuzzManagerReporter.quality_name(job.result_code))
        return Session.EXIT_ERROR

    except NoTestcaseError:
        return Session.EXIT_ERROR

    except KeyboardInterrupt:
        job_cancelled = True
        return Session.EXIT_ABORT

    except ffpuppet.LaunchError as exc:
        LOG.error("Error launching target: %s", exc)
        return Session.EXIT_LAUNCH_FAILURE

    finally:
        LOG.warning("Shutting down...")
        if job is not None and not job_cancelled:
            job_cancelled = job.result_code in {FuzzManagerReporter.QUAL_REDUCER_BROKE,
                                                FuzzManagerReporter.QUAL_REDUCER_ERROR}
        if job is not None:
            job.close(keep_temp=job_cancelled)
        # job handles calling cleanup if it was created
        if job is None and target is not None:
            target.cleanup()
