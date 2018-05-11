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
import os
import posixpath
import re
import shutil
import tempfile
import zipfile

try:
    import jsbeautifier
    HAVE_JSBEAUTIFIER = True
except ImportError:
    HAVE_JSBEAUTIFIER = False
import lithium
from FTB.Signatures.CrashInfo import CrashSignature

from .interesting import Interesting
from ..core import Session
from ..corpman import TestFile, TestCase
from ..reporter import FuzzManagerReporter, Report
from ..target import Target
from .. import reporter


__author__ = "Jesse Schwartzentruber"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber", "Jason Kratzer"]


log = logging.getLogger("grizzly.reduce")  # pylint: disable=invalid-name


class ReducerError(Exception):
    pass


def _testcase_contents(path="."):
    for dir_name, _, dir_files in os.walk(path):
        arc_path = os.path.relpath(dir_name, path)
        # skip tmp folders
        if re.match(r"^tmp.+$", arc_path.split(os.sep, 1)[0]) is not None:
            continue
        # skip core files
        if re.match(r"^core.\d+$", os.path.basename(arc_path)) is not None:
            continue
        for file_name in dir_files:
            if arc_path == path:
                yield file_name
            else:
                yield os.path.join(arc_path, file_name)


class ReductionJob(object):

    def __init__(self, ignore, target, iter_timeout, no_harness, any_crash, skip, min_crashes,
                 repeat, idle_poll, idle_threshold, idle_timeout, testcase_cache=True):
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
        self.tmpdir = tempfile.mkdtemp(prefix="grzreduce")
        self.tcroot = os.path.join(self.tmpdir, "tc")
        self.other_crashes = {}
        self.input_fname = None
        self.interesting_prefix = None

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
                                                line.split(": ", 1)[1].strip().encode("utf-8"))
                    break
            else:
                raise ReducerError("Couldn't find landing page in %s!"
                                   % (os.path.abspath(info.name),))
        assert os.path.isfile(landing_page)
        return landing_page

    def config_testcase(self, testcase):
        """Prepare a user provided testcase for reduction.

        Args:
            testcase (str): Path to a testcase. This should be a Grizzly testcase (zip or folder).

        Returns:
            None
        """
        # extract the testcase if necessary
        assert not os.path.exists(self.tcroot)
        if os.path.isfile(testcase):
            assert testcase.endswith(".zip")
            os.mkdir(self.tcroot)
            with zipfile.ZipFile(testcase) as zip_fp:
                zip_fp.extractall(path=self.tcroot)
        else:
            assert os.path.isdir(testcase)
            shutil.copytree(testcase, self.tcroot)

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

        # check for included prefs and environment
        if "prefs.js" in os.listdir(dirs[0]):
            # move the file out of tcroot because we prune these non-testcase files later
            os.rename(os.path.join(dirs[0], "prefs.js"), os.path.join(self.tmpdir, "prefs.js"))
            self.interesting.target.prefs = os.path.abspath(os.path.join(self.tmpdir, "prefs.js"))
            log.warning("Using prefs included in testcase: %s", self.interesting.target.prefs)
        if "env_vars.txt" in os.listdir(dirs[0]):
            self.interesting.config_environ(os.path.join(dirs[0], "environ.txt"))
            log.warning("Using environment included in testcase: %s",
                        os.path.abspath(os.path.join(dirs[0], "environ.txt")))

        # if dirs is singular, we can use the testcase directly, otherwise we need to iterate over
        # them all in order
        pages = ['/' + posixpath.relpath(self._get_landing_page(d), self.tcroot) for d in dirs]
        if len(pages) == 1:
            self.testcase = pages[0]
        else:
            # create a harness to iterate over the whole history
            harness_path = os.path.join(os.path.dirname(__file__), '..', 'corpman', 'harness.html')
            with io.open(harness_path, encoding="utf-8") as harness_fp:
                harness = harness_fp.read()
            # change dump string so that logs can be told apart
            harness = harness.replace("[grizzly harness]", "[reduce harness]")
            # change the window name so that window.open doesn't clobber self
            harness = harness.replace("'GrizzlyFuzz'", "'ReduceIter'")
            # insert the iteration timeout. insert it directly because we can't set a hash value
            new_harness = re.sub(r"^(\s*let\s.*\btime_limit\b)",
                                 r"\1 = %d" % (self.interesting.iter_timeout * 1000),
                                 harness,
                                 flags=re.MULTILINE)
            if new_harness == harness:
                raise ReducerError("Unable to set time_limit in harness, please update pattern "
                                   "to match harness!")
            harness = new_harness
            # insert the landing page loop
            harness = harness.replace("<script>", "\n".join([
                "<script>",
                "let _reduce_tests = [",
                "//DDBEGIN",
                "'" + "',\n'".join(pages) + "',",
                "//DDEND",
                "]",
                "function _reduce_next(){",
                "  return _reduce_tests.shift()",
                "}"
            ]))
            # make first test and next test grab from the array
            harness = harness.replace("'/first_test'", "_reduce_next()")
            harness = harness.replace("'/next_test'", "_reduce_next()")
            # insert the close condition. we are iterating over the array of landing pages,
            # undefined means we hit the end and the harness should close
            new_harness = re.sub(r"^(\s*sub\s*=\s*open\(req_url.*'ReduceIter')",
                                 r"if (req_url === undefined) window.close()\n\1",
                                 harness,
                                 flags=re.MULTILINE)
            if new_harness == harness:
                raise ReducerError("Unable to insert finish condition, please update pattern "
                                   "to match harness!")
            harness = new_harness
            fp, harness_path = tempfile.mkstemp(prefix="harness_", suffix=".html", dir=self.tcroot)
            os.close(fp)
            with io.open(harness_path, "w", encoding="utf-8") as harness_fp:
                harness_fp.write(harness)
            self.testcase = harness_path

        # prune unnecessary files from the testcase
        for root, _, files in os.walk(self.tcroot):
            for file in files:
                if file in {"prefs.js", "env_vars.txt", "test_info.txt", "log_metadata.json",
                            "grizzly_fuzz_harness.html", "screenlog.txt"} or \
                        (file.startswith("log_") and file.endswith(".txt")):
                    os.unlink(os.path.join(root, file))


    def close(self):
        """Clean up any resources used for this job.

        Args:
            None

        Returns:
            None
        """
        if self.tmpdir is not None and os.path.isdir(self.tmpdir):
            shutil.rmtree(self.tmpdir)
            self.tmpdir = None

    def _report_result(self, tcroot, temp_prefix, quality_value, force=False):
        self.reporter.quality = quality_value
        self.reporter.force_report = force

        landing_page = os.path.relpath(self.testcase, self.tcroot)
        testcase = TestCase(landing_page, "grizzly.reduce", input_fname=self.input_fname)

        # add testcase contents
        for filename in _testcase_contents(tcroot):
            with open(os.path.join(tcroot, filename)) as testfile_fp:
                testcase.add_testfile(TestFile(filename, testfile_fp.read()))

        # add prefs
        if self.interesting.target.prefs is not None:
            testcase.add_environ_file(self.interesting.target.prefs, "prefs.js")

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
        crash_info = Report.from_path(temp_prefix + "_logs") \
            .create_crash_info(self.interesting.target.binary)
        this_sig = crash_info.createCrashSignature(maxFrames=5)
        crash_hash = hashlib.sha256(this_sig.rawSignature).hexdigest()[:10]
        tmpd = os.path.join(self.tmpdir, "alt", crash_hash)
        if crash_hash in self.other_crashes:
            shutil.rmtree(self.other_crashes[crash_hash]["tcroot"])
            log.info("Found alternate crash (newer): %s", crash_info.createShortSignature())
        else:
            log.info("Found alternate crash: %s", crash_info.createShortSignature())
        os.makedirs(tmpd)
        for file_name in _testcase_contents(self.tcroot):
            out = os.path.join(tmpd, file_name)
            out_dir = os.path.dirname(out)
            if not os.path.isdir(out_dir):
                os.makedirs(out_dir)
            shutil.copyfile(file_name, out)
        self.other_crashes[crash_hash] = {"tcroot": os.path.realpath(tmpd), "prefix": temp_prefix}

    def _report_other_crashes(self):
        """
        After reduce is finished, report any alternate results (if they don't match the collector cache).
        """
        for entry in self.other_crashes.values():
            self._report_result(entry["tcroot"], entry["prefix"], FuzzManagerReporter.QUAL_UNREDUCED)

    def run(self):
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

            # set up tempdir manually so it doesn't go in cwd
            reducer.tempDir = tempfile.mkdtemp(prefix="lithium-", dir=self.tmpdir)

            # if we are using a harness to iterate over multiple testcases, reduce that set of
            # testcases before anything else
            files_to_reduce = [self.testcase]
            if os.path.basename(self.testcase).startswith("harness_"):
                self.interesting.reduce_file = self.testcase
                log.info("Reducing %s with %s on %ss",
                         self.testcase, lithium.Minimize.name, lithium.TestcaseLine.atom)
                reducer.strategy = lithium.Minimize()
                reducer.testcase = lithium.TestcaseLine()
                reducer.testcase.readTestcase(self.testcase)
                result = reducer.run()
                if result != 0:
                    log.warning("Could not reduce: Iterating over history did not reproduce the "
                                "issue")
                    return False
                reducer.testcase.readTestcase(self.testcase)
                if len(reducer.testcase) == 1:
                    # we reduced this down to a single testcase, remove the harness
                    testcase_rel = reducer.testcase.parts[0].strip()
                    assert testcase_rel.startswith("'/")
                    assert testcase_rel.endswith("',")
                    testcase_rel = testcase_rel[2:-2]  # quoted, begins with / and ends with a comma
                    testcase_path = testcase_rel.split('/')
                    assert len(testcase_path) == 2
                    self.tcroot = os.path.join(self.tcroot, testcase_path[0])
                    self.testcase = os.path.join(self.tcroot, testcase_path[1])
                    self.interesting.landing_page = self.testcase
                    files_to_reduce = [self.testcase]
                    log.info("Reduced history to a single file: %s", testcase_path[1])
                else:
                    files_to_reduce = []  # don't bother trying to reduce the harness further
                    log.info("Reduced history down to %d testcases", len(reducer.testcase))

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
            original_size = sum(os.stat(fn).st_size for fn in files_to_reduce)

            # run lithium reduce with strategies
            # XXX: should check the DDBEGIN/DDEND lines to see whether it looks like markup
            #      or script and adjust cutBefore/cutAfter accordingly
            reduce_stages = (
                (lithium.Minimize, lithium.TestcaseLine),
                # CheckOnly is used in conjunction with beautification stage
                # This verifies that beautification didn't break the testcase
                (lithium.CheckOnly, lithium.TestcaseLine),
                (lithium.CollapseEmptyBraces, lithium.TestcaseLine),
                (lithium.Minimize, lithium.TestcaseJsStr),
            )
            for stage_num, (strategy_type, testcase_type) in enumerate(reduce_stages):
                files_reduced = 0
                for testcase_path in files_to_reduce:
                    if stage_num == 1:
                        if HAVE_JSBEAUTIFIER and testcase_path.endswith(".js"):
                            # Beautify testcase
                            with open(testcase_path) as f:
                                original_testcase = f.read()

                            beautified_testcase = jsbeautifier.beautify(original_testcase)
                            # All try/catch pairs will be expanded on their own lines
                            # Collapse these pairs when only a single instruction is contained
                            #   within
                            regex = r"(\s*try {)\n\s*(.*)\n\s*(}\s*catch.*)"
                            beautified_testcase = re.sub(regex, r"\1 \2 \3", beautified_testcase)
                            with open(testcase_path, 'w') as testcase_fp:
                                testcase_fp.write(beautified_testcase)
                            self.interesting.reduce_file = testcase_path
                            reducer.strategy = strategy_type()
                            reducer.testcase = testcase_type()
                            reducer.testcase.readTestcase(testcase_path)
                            log.info("Attempting to beautify %s", testcase_path)
                            result = reducer.run()
                            if result == 0:
                                log.info("Beautification succeeded")
                            else:
                                log.warning("Beautification failed")
                                with open(testcase_path, 'w') as testcase_fp:
                                    testcase_fp.write(original_testcase)
                        else:
                            # jsbeautifier is only effective with JS files
                            continue
                    else:
                        log.info("Reducing %s with %s on %ss",
                                 testcase_path, strategy_type.name, testcase_type.atom)
                        self.interesting.reduce_file = testcase_path
                        reducer.strategy = strategy_type()
                        reducer.testcase = testcase_type()
                        reducer.testcase.readTestcase(testcase_path)
                        result = reducer.run()
                        if result != 0:
                            break
                        files_reduced += 1

                if result != 0:
                    # reducer failed to repro the crash
                    if stage_num == 0 and files_reduced == 0:
                        # first stage, couldn't repro at all
                        log.warning("Could not reduce: The testcase was not reproducible")
                        self.result_code = FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE

                    else:
                        # subsequent stage, reducing broke the testcase?
                        # unclear how to recover from this.
                        # just report failure and hopefully we have another to try
                        log.warning("%s + %s(%s) failed to reproduce. Previous stage broke the "
                                    "testcase?" % (strategy_type.__name__,
                                                   testcase_type.__name__,
                                                   os.path.abspath(files_to_reduce[files_reduced])))
                        self.result_code = FuzzManagerReporter.QUAL_REDUCER_BROKE

                    return False

            # all stages succeeded
            reduced_size = sum(os.stat(fn).st_size for fn in files_to_reduce)
            if reduced_size == original_size:
                raise ReducerError("Reducer succeeded but nothing was reduced!")

            self._report_result(self.tcroot,
                                self.interesting_prefix,
                                FuzzManagerReporter.QUAL_REDUCED_RESULT,
                                force=True)

            # change original quality so unbucketed crashes don't reduce again
            self.result_code = FuzzManagerReporter.QUAL_REDUCED_ORIGINAL
            return True

        except ReducerError as exc:
            log.warning("Could not reduce: %s", exc)
            self.result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            return False
        except Exception:
            log.exception("Exception during reduce")
            self.result_code = FuzzManagerReporter.QUAL_REDUCER_ERROR
            self.reduced_id = None
            return False
        finally:
            self._report_other_crashes()


def main(args):
    if args.quiet and not bool(os.getenv("DEBUG")):
        logging.getLogger().setLevel(logging.WARNING)

    log.info("Starting Grizzly Reducer")

    if args.fuzzmanager:
        reporter.FuzzManagerReporter.sanity_check(args.binary)

    if args.ignore:
        log.info("Ignoring: %s", ", ".join(args.ignore))

    # TODO: should these prints move?
    if args.xvfb:
        log.info("Running with Xvfb")
    if args.valgrind:
        log.info("Running with Valgrind. This will be SLOW!")

    target = Target(
        args.binary,
        args.extension,
        args.launch_timeout,
        args.log_limit,
        args.memory,
        args.prefs,
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
        not args.no_cache)

    try:
        # set this before the testcase, since the testcase may override it
        if args.environ:
            job.interesting.config_environ(args.environ)
        job.config_testcase(args.input)
        if args.sig is not None:
            with io.open(args.sig, encoding="utf-8") as sig_fp:
                job.config_signature(sig_fp.read)

        if args.fuzzmanager:
            log.info("Reporting issues via FuzzManager")
            job.reporter = reporter.FuzzManagerReporter(
                args.binary,
                log_limit=Session.FM_LOG_SIZE_LIMIT)
        else:
            job.reporter = reporter.FilesystemReporter()

        # detect soft assertions
        if args.asserts:
            job.interesting.target._puppet.add_abort_token("###!!! ASSERTION:")

        result = job.run()

        if result:
            log.info("Reduction succeeded: %s", FuzzManagerReporter.quality_name(job.result_code))
        else:
            log.warning("Reduction failed: %s", FuzzManagerReporter.quality_name(job.result_code))

    finally:
        log.warning("Shutting down...")
        job.close()
