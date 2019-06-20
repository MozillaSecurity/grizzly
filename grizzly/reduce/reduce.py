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
import json
import logging
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
from .exceptions import CorruptTestcaseError, NoTestcaseError, ReducerError
from ..session import Session
from ..common import FilesystemReporter, FuzzManagerReporter, Report
from ..common import ReduceStatus
from ..target import load as load_target


__author__ = "Jesse Schwartzentruber"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber", "Jason Kratzer"]


LOG = logging.getLogger("grizzly.reduce")


class ReductionJob(object):
    LOGGERS_TO_WATCH = ("ffpuppet", "grizzly", "lithium", "sapphire")
    DEFAULT_STRATEGIES = ("line", "jsbeautify", "collapsebraces", "jschar")

    def __init__(self, ignore, target, iter_timeout, no_harness, any_crash, skip, min_crashes,
                 repeat, idle_poll, idle_threshold, idle_timeout, status, working_path=None,
                 testcase_cache=True, skip_analysis=False):
        """Use lithium to reduce a testcase.

        Args:
            target (grizzly.target.Target): Target object to use for reduction.
        """
        self.reporter = None
        self.result_code = None
        self.signature = None
        self.status = status
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
            status,
            testcase_cache)
        self.interesting.alt_crash_cb = self._other_crash_found
        self.interesting.interesting_cb = self._interesting_crash
        self.testcase = None
        self.tmpdir = tempfile.mkdtemp(prefix="grzreduce", dir=working_path)
        self.tcroot = os.path.join(self.tmpdir, "tc")
        self.other_crashes = {}
        self.interesting_prefix = None
        self.log_handler = self._start_log_capture()
        self.cache_iter_harness_created = None
        self.skip_analysis = skip_analysis
        if not self.skip_analysis:
            # see if any of the args tweaked by analysis were overridden
            # --relaunch is regarded as a maximum, so overriding the default is not a deal-breaker for this
            if self.interesting.min_crashes != 1:
                LOG.warning("--min-crashes=%d was given, skipping analysis", self.interesting.min_crashes)
                self.skip_analysis = True
            elif self.interesting.repeat != 1:
                LOG.warning("--repeat=%d was given, skipping analysis", self.interesting.repeat)
                self.skip_analysis = True
        self.original_relaunch = target.rl_reset
        self.force_no_harness = self.interesting.no_harness
        self.files_to_reduce = None
        self.original_size = None

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
        # set root to DEBUG, and propagate the old root level to each root handler
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
        path = os.path.relpath(path, self.tcroot)
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
            if os.path.exists(self.tcroot):
                raise ReducerError("Testcase already configured?")
            if os.path.isfile(testcase):
                if testcase.lower().endswith(".html"):
                    os.mkdir(self.tcroot)
                    shutil.copy(testcase, self.tcroot)
                    info = {"target": os.path.basename(testcase)}
                    with open(os.path.join(self.tcroot, "test_info.json"), "w") as info_fp:
                        json.dump(info, info_fp, indent=2, sort_keys=True)
                elif testcase.lower().endswith(".zip"):
                    os.mkdir(self.tcroot)
                    try:
                        with zipfile.ZipFile(testcase) as zip_fp:
                            zip_fp.extractall(path=self.tcroot)
                    except (zlib.error, zipfile.BadZipfile):
                        raise CorruptTestcaseError("Testcase is corrupted")
                else:
                    raise ReducerError("Testcase must be zip, html, or directory")
            elif os.path.isdir(testcase):
                shutil.copytree(testcase, self.tcroot)
            else:
                raise ReducerError("Testcase must be zip, html or directory")

            self.interesting.input_fname = os.path.basename(testcase)

            # get a list of all directories containing testcases (1-n, depending on how much history
            # grizzly saved)
            entries = set(os.listdir(self.tcroot))
            if "test_info.json" in entries:
                dirs = [self.tcroot]
            elif "test_info.txt" in entries:
                dirs = [self.tcroot]
            else:
                dirs = sorted([os.path.join(self.tcroot, entry) for entry in entries
                               if os.path.exists(os.path.join(self.tcroot, entry, "test_info.json"))
                               or os.path.exists(os.path.join(self.tcroot, entry, "test_info.txt"))],
                              key=lambda x: -int(x.rsplit('-', 1)[1]))
                if not dirs:
                    raise NoTestcaseError("No testcase recognized at %r" % (testcase,))

            # check for included prefs and environment
            if "prefs.js" in os.listdir(dirs[0]):
                # move the file out of tcroot because we prune these non-testcase files later
                os.rename(os.path.join(dirs[0], "prefs.js"), os.path.join(self.tmpdir, "prefs.js"))
                self.interesting.target.prefs = os.path.abspath(os.path.join(self.tmpdir, "prefs.js"))
                LOG.warning("Using prefs included in testcase: %r", self.interesting.target.prefs)
            if "test_info.json" in os.listdir(dirs[0]):
                self.interesting.config_environ(os.path.join(dirs[0], "test_info.json"))
                if self.interesting.env_mod:
                    LOG.warning("Using environment included in testcase: %s",
                                os.path.abspath(os.path.join(dirs[0], "test_info.json")))
                    self.interesting.target.forced_close = \
                        self.interesting.env_mod.get("GRZ_FORCED_CLOSE", "1").lower() not in ("0", "false")
            elif "env_vars.txt" in os.listdir(dirs[0]):
                # TODO: remove this block once move to 'test_info.json' is complete
                self.interesting.config_environ(os.path.join(dirs[0], "env_vars.txt"))
                LOG.warning("Using environment included in testcase: %s",
                            os.path.abspath(os.path.join(dirs[0], "env_vars.txt")))
                self.interesting.target.forced_close = \
                    self.interesting.env_mod.get("GRZ_FORCED_CLOSE", "1").lower() not in ("0", "false")

            # if dirs is singular, we can use the testcase directly, otherwise we need to iterate over
            # them all in order
            pages = [self._get_landing_page(d) for d in dirs]
            if len(pages) == 1:
                self.testcase = pages[0]
                self.cache_iter_harness_created = False

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
            prune = {"env_vars.txt", "grizzly_fuzz_harness.html",
                     "log_metadata.json", "prefs.js", "reducelog.txt",
                     "screenlog.txt", "test_info.json", "test_info.txt"}
            for root, _, files in os.walk(self.tcroot):
                for file_ in files:
                    if file_ in prune or (file_.startswith("log_") and file_.endswith(".txt")):
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

    def _report_result(self, testcase, temp_prefix, quality_value, force=False):
        self.reporter.quality = quality_value
        self.reporter.force_report = force
        self.reporter.submit(temp_prefix + "_logs", [testcase])

    def _interesting_crash(self, temp_prefix):
        self.interesting_prefix = temp_prefix

    def _other_crash_found(self, testcase, temp_prefix):
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
        if crash_hash in self.other_crashes:
            LOG.info("Found alternate crash (newer): %s", crash_info.createShortSignature())
            # already counted when initially found
            self.status.ignored += 1
        else:
            LOG.info("Found alternate crash: %s", crash_info.createShortSignature())
            self.status.results += 1
        self.other_crashes[crash_hash] = {"tc": testcase, "prefix": temp_prefix}

    def _report_other_crashes(self):
        """
        After reduce is finished, report any alternate results (if they don't match the collector cache).
        """
        for entry in self.other_crashes.values():
            self._report_result(entry["tc"], entry["prefix"], FuzzManagerReporter.QUAL_UNREDUCED)

    def run(self, strategies=None):
        """Run reduction.
        """
        assert self.testcase is not None
        assert self.reporter is not None
        assert self.files_to_reduce is None
        assert self.original_size is None

        try:
            # set up lithium
            reducer = lithium.Lithium()
            self.interesting.orig_sig = self.signature
            self.interesting.landing_page = self.testcase
            reducer.conditionScript = self.interesting

            # if we created a harness to iterate over history, files_to_reduce is initially just
            #   that harness
            # otherwise, the first stage will be skipped and we will scan for all testcases to
            #   reduce in the second stage
            self.files_to_reduce = [self.testcase]
            self.original_size = [None]

            # resolve list of strategies to apply
            reduce_stages = [strategies_module.MinimizeCacheIterHarness, strategies_module.ScanFilesToReduce]
            if not self.skip_analysis:
                if self.cache_iter_harness_created:
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
                strategy = strategy_type(self, reducer)

                for testcase_path in self.files_to_reduce:

                    strategy.read_testcase(testcase_path)
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
            reduced_size = sum(os.stat(fn).st_size for fn in self.files_to_reduce)
            if reduced_size == self.original_size[0]:
                raise ReducerError("Reducer succeeded but nothing was reduced!")

            self._report_result(self.interesting.best_testcase,
                                self.interesting_prefix,
                                FuzzManagerReporter.QUAL_REDUCED_RESULT,
                                force=True)

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
            self.files_to_reduce = None
            self.original_size = None


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

    # attempt to load status (used by automation)
    status_uid = os.getenv("GRZ_STATUS_UID")
    if status_uid is not None:
        status_uid = int(status_uid)
        status = ReduceStatus.load(status_uid)
    else:
        status = None
    if status is None:
        # create new status object
        status = ReduceStatus.start(uid=status_uid)

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
            status,
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
            job.reporter = FuzzManagerReporter(args.binary, tool=args.tool)
        else:
            job.reporter = FilesystemReporter()
            LOG.info("Results will be stored in %r", job.reporter.report_path)

        # detect soft assertions
        if args.soft_asserts:
            job.interesting.target.add_abort_token("###!!! ASSERTION:")

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

        # update status
        if result:
            status.reduce_pass += 1
        elif job.result_code in (6, 10):
            status.reduce_fail += 1
        elif job.result_code in (7, 8, 9):
            status.reduce_error += 1

        if result:
            LOG.info("Reduction succeeded: %s", FuzzManagerReporter.quality_name(job.result_code))
            return Session.EXIT_SUCCESS

        LOG.warning("Reduction failed: %s", FuzzManagerReporter.quality_name(job.result_code))
        return Session.EXIT_ERROR

    except NoTestcaseError:
        status.reduce_error += 1
        # TODO: test should be marked as Q7
        return Session.EXIT_ERROR

    except KeyboardInterrupt:
        job_cancelled = True
        return Session.EXIT_ABORT

    except ffpuppet.LaunchError as exc:
        LOG.error("Error launching target: %s", exc)
        status.reduce_error += 1
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
        # call cleanup if we are unlikely to be using status again
        if "GRZ_STATUS_UID" not in os.environ:
            status.cleanup()
        else:
            status.report(reset_status=True)
