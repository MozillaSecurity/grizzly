# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import abc
import logging
import math
import os
import re

try:
    import cssbeautifier
    HAVE_CSSBEAUTIFIER = True
except ImportError:
    HAVE_CSSBEAUTIFIER = False
try:
    import jsbeautifier
    HAVE_JSBEAUTIFIER = True
except ImportError:
    HAVE_JSBEAUTIFIER = False
import lithium

from . import testcase_contents


LOG = logging.getLogger("grizzly.reduce.strategies")


class ReduceStage(metaclass=abc.ABCMeta):
    strategy_type = None
    testcase_type = None

    def __init__(self, job, run_state, reducer):
        if getattr(self, "USES_ANALYSIS_MODE", False):
            self._analysis_mode = job.analysis_mode
        else:
            self._analysis_mode = None

        if getattr(self, "ALTERS_JOB_TESTCASE", False):
            self.job_testcase = job.testcase_proxy(run_state)

        if getattr(self, "ALTERS_JOB_TIMEOUTS", False):
            self.job_timeouts = job.timeouts_proxy()

        self.lithium = reducer

    def read_testcase(self, testcase_path):
        if self._analysis_mode is not None:
            self.lithium.strategy = self.strategy_type(self._analysis_mode)  # pylint: disable=not-callable
        else:
            self.lithium.strategy = self.strategy_type()  # pylint: disable=not-callable
        self.lithium.testcase = self.testcase_type()  # pylint: disable=not-callable
        LOG.info("Reducing %s with %s on %ss",
                 testcase_path, self.strategy_type.name, self.testcase_type.atom)
        self.lithium.testcase.readTestcase(testcase_path)

    def should_skip(self):  # pylint: disable=no-self-use
        return False

    def on_success(self):
        LOG.info("%s succeeded", type(self).__name__)

    def on_failure(self):  # pylint: disable=no-self-use
        raise StopIteration()


class MinimizeLines(ReduceStage):
    name = "line"
    strategy_type = lithium.Minimize
    testcase_type = lithium.TestcaseLine


class _AnalyzeReliability(lithium.Strategy):
    name = "reliability-analysis"
    ITERATIONS = 11  # number of iterations to analyze
    MIN_CRASHES = 2  # --min-crashes value when analysis is used
    TARGET_PROBABILITY = 0.95  # probability that successful reduction will observe the crash
    # to see the worst case, run the `self.repeat` calculation below using
    # crashes_percent = 1.0/ITERATIONS

    def __init__(self, analysis_mode_cb):
        super(_AnalyzeReliability, self).__init__()
        self.analysis_mode_cb = analysis_mode_cb

    def main(self, testcase, interesting, _temp_filename):

        assert self.ITERATIONS > 0

        harness_crashes = 0
        non_harness_crashes = 0

        # Reset parameters.
        # Use repeat=1 & relaunch=ITERATIONS because this is closer to how we will run post-analysis.
        # We're only using repeat=1 instead of repeat=ITERATIONS so we can get feedback on every
        #   call to interesting.
        with self.analysis_mode_cb(min_crashes=1, relaunch=self.ITERATIONS, repeat=1) as iter_params:

            iter_params.commit()

            if not iter_params.force_no_harness:
                LOG.info("Running for %d iterations to assess reliability using harness.", self.ITERATIONS)
                for _ in range(self.ITERATIONS):
                    result = interesting(testcase, writeIt=False)  # pylint: disable=invalid-name
                    LOG.info("Lithium result: %s", "interesting." if result else "not interesting.")
                    if result:
                        harness_crashes += 1
                LOG.info("Testcase was interesting %0.1f%% of %d attempts using harness for iteration.",
                         100.0 * harness_crashes / self.ITERATIONS, self.ITERATIONS)

                # close target so new parameters take effect
                iter_params.commit()

            if harness_crashes != self.ITERATIONS:
                # try without harness
                iter_params.no_harness = True

                LOG.info("Running for %d iterations to assess reliability without harness.",
                         self.ITERATIONS)
                for _ in range(self.ITERATIONS):
                    result = interesting(testcase, writeIt=False)  # pylint: disable=invalid-name
                    LOG.info("Lithium result: %s", "interesting." if result else "not interesting.")
                    if result:
                        non_harness_crashes += 1
                LOG.info("Testcase was interesting %0.1f%% of %d attempts without harness.",
                         100.0 * non_harness_crashes / self.ITERATIONS, self.ITERATIONS)

                # close target so new parameters take effect
                iter_params.commit()

        if harness_crashes == 0 and non_harness_crashes == 0:
            return 1  # no crashes ever?

        # should we use the harness? go with whichever crashed more
        iter_params.no_harness = non_harness_crashes > harness_crashes

        # this is max 99% to avoid domain errors in the calculation below
        crashes_percent = min(1.0 * max(non_harness_crashes, harness_crashes) / self.ITERATIONS, 0.99)

        # adjust repeat/min-crashes depending on how reliable the testcase was
        iter_params.min_crashes = self.MIN_CRASHES
        iter_params.repeat = \
            int(math.ceil(math.log(1 - self.TARGET_PROBABILITY, 1 - crashes_percent)) * self.MIN_CRASHES)
        iter_params.relaunch = iter_params.repeat  # actual value used will respect relaunch requested by user

        LOG.info("Analysis results:")
        if harness_crashes == self.ITERATIONS:
            LOG.info("* testcase was perfectly reliable with the harness (--no-harness not assessed)")
        elif harness_crashes == non_harness_crashes:
            LOG.info("* testcase was equally reliable with/without the harness")
        elif iter_params.force_no_harness:
            LOG.info("* --no-harness was already set")
        else:
            LOG.info("* testcase was %s reliable with the harness",
                     "less" if iter_params.no_harness else "more")
        LOG.info("* adjusted parameters: --min-crashes=%d --repeat=%d --relaunch=%d",
                 iter_params.min_crashes, iter_params.repeat,
                 iter_params.relaunch)

        return 0


class AnalyzeTestcase(ReduceStage):
    name = "analyze"
    USES_ANALYSIS_MODE = True
    strategy_type = _AnalyzeReliability
    testcase_type = lithium.TestcaseLine

    def on_success(self):
        super(AnalyzeTestcase, self).on_success()
        # only run this strategy once, not once per reducible file in the testcase
        raise StopIteration()


class MinimizeCacheIterHarness(MinimizeLines):
    name = "minimize-cache"
    ALTERS_JOB_TESTCASE = True
    ALTERS_JOB_TIMEOUTS = True

    # job attributes:
    # write: files_to_reduce (clear, append), tcroot, testcase, landing_page
    # read: cache_iter_harness_created

    def should_skip(self):
        return not self.job_testcase.cache_iter_harness_created

    def read_testcase(self, testcase_path):
        if self.should_skip():
            return

        super(MinimizeCacheIterHarness, self).read_testcase(testcase_path)

        # we are running multiple testcases in a single "iteration", so we need to
        #   fix the timeout values

        # start polling for idle after n-1 testcases have finished
        self.job_timeouts.idle += \
            self.job_timeouts.idle * (len(self.lithium.testcase) - 1)

        # iteration timeout is * n testcases, but add 10 seconds for overhead from the
        #   outer harness
        self.job_timeouts.iteration = \
            (self.job_timeouts.iteration + 10) * len(self.lithium.testcase)

    def on_success(self):
        # XXX: when py27 is dropped, this can be files_to_reduce.clear()
        while self.job_testcase.files_to_reduce:
            self.job_testcase.files_to_reduce.pop()
        lines = lithium.TestcaseLine()
        lines.readTestcase(self.job_testcase.entry)
        if len(lines) == 1:
            # we reduced this down to a single testcase, remove the harness
            testcase_rel = lines.parts[0].strip().decode("utf-8")
            assert testcase_rel.startswith("'/")
            assert testcase_rel.endswith("',")
            testcase_rel = testcase_rel[2:-2]  # trim chars asserted above
            testcase_path = testcase_rel.split('/')
            assert len(testcase_path) == 2
            self.job_testcase.root = os.path.join(self.job_testcase.root, testcase_path[0])
            self.job_testcase.entry = os.path.join(self.job_testcase.root, testcase_path[1])
            self.job_testcase.landing_page = self.job_testcase.entry
            self.job_testcase.files_to_reduce.append(self.job_testcase.entry)
            LOG.info("Reduced history to a single file: %s", testcase_path[1])
        else:
            # don't bother trying to reduce the harness further,
            #   leave harness out of files_to_reduce
            LOG.info("Reduced history down to %d testcases", len(self.lithium.testcase))


class ScanFilesToReduce(ReduceStage):
    name = "scan-files"
    ALTERS_JOB_TESTCASE = True

    # job attributes:
    # read: tcroot, testcase, files_to_reduce (len, iter)
    # modify: files_to_reduce (append, sort)
    # write: original_size

    def __init__(self, *args, **kwds):
        super(ScanFilesToReduce, self).__init__(*args, **kwds)
        # find all files for reduction
        for file_name in testcase_contents(self.job_testcase.root):
            file_name = os.path.join(self.job_testcase.root, file_name)
            if file_name == self.job_testcase.entry:
                continue
            with open(file_name, "rb") as tc_fp:
                for line in tc_fp:
                    if b"DDBEGIN" in line:
                        self.job_testcase.files_to_reduce.append(file_name)
                        break
        if len(self.job_testcase.files_to_reduce) > 1:
            # sort by descending size
            self.job_testcase.files_to_reduce.sort(key=lambda fn: os.stat(fn).st_size, reverse=True)
        self.job_testcase.original_size = self.job_testcase.total_size()

    def read_testcase(self, testcase_path):
        pass

    def should_skip(self):  # pylint: disable=no-self-argument
        # no real reduce strategy, just used to scan for files
        return True


class CSSBeautify(ReduceStage):
    name = "cssbeautify"
    strategy_type = lithium.CheckOnly
    testcase_type = lithium.TestcaseLine

    def __init__(self, *args, **kwds):
        super(CSSBeautify, self).__init__(*args, **kwds)
        self.testcase_path = None
        self.original_testcase = None
        self._ext = None
        self._force_skip = False

    def read_testcase(self, testcase_path):
        self.testcase_path = testcase_path
        self._ext = testcase_path.rsplit(".", 1)[-1]

        if self.should_skip():
            return

        # Beautify testcase
        opts = (
            ('end_with_newline', False),
            ('indent_size', 2),
            ('newline_between_rules', False),
            ('preserve_newlines', False),
        )
        with open(testcase_path) as testcase_fp:
            self.original_testcase = testcase_fp.read()
        if self._ext == "css":
            # DDBEGIN and DDEND are ignored here atm
            LOG.info("Attempting to cssbeautify %s", testcase_path)
            with open(testcase_path, "w") as testcase_fp:
                testcase_fp.write(cssbeautifier.beautify(self.original_testcase, opts))
        else:
            # handle html files
            begin = max(self.original_testcase.find("DDBEGIN"), 0)
            end = self.original_testcase.find("DDEND")
            if end == -1:
                end = len(self.original_testcase)
            re_tag = re.compile(r"(<style.*?>)(.*?)(</style>)", flags=re.DOTALL|re.IGNORECASE)
            if not re_tag.search(self.original_testcase, begin, end):
                LOG.debug("<style> tags not found in %r", testcase_path)
                self._force_skip = True
                self.original_testcase = None
                return
            pos = 0
            with open(testcase_path, "w") as testcase_fp:
                for match in re_tag.finditer(self.original_testcase, begin, end):
                    testcase_fp.write(self.original_testcase[pos:match.start(2)])
                    css = cssbeautifier.beautify(match.group(2), opts)
                    if css:
                        testcase_fp.write("\n")
                        testcase_fp.write(css)
                        testcase_fp.write("\n")
                    pos = match.end(2)
                testcase_fp.write(self.original_testcase[pos:])
            LOG.info("Ran cssbeautify on %s", testcase_path)

        self.lithium.strategy = self.strategy_type()  # pylint: disable=not-callable
        self.lithium.testcase = self.testcase_type()  # pylint: disable=not-callable
        self.lithium.testcase.readTestcase(testcase_path)

    def should_skip(self):
        if HAVE_CSSBEAUTIFIER and not self._force_skip:
            if self._ext in ("css", "htm", "html"):
                return False
        return True

    def on_failure(self):
        LOG.warning("CSSBeautification failed (reverting)")
        with open(self.testcase_path, "w") as testcase_fp:
            testcase_fp.write(self.original_testcase)


class JSBeautify(ReduceStage):
    name = "jsbeautify"
    strategy_type = lithium.CheckOnly
    testcase_type = lithium.TestcaseLine

    def __init__(self, *args, **kwds):
        super(JSBeautify, self).__init__(*args, **kwds)
        self.testcase_path = None
        self.original_testcase = None

    def read_testcase(self, testcase_path):
        self.testcase_path = testcase_path

        if self.should_skip():
            return

        LOG.info("Attempting to jsbeautify %s", testcase_path)

        self.lithium.strategy = self.strategy_type()  # pylint: disable=not-callable
        self.lithium.testcase = self.testcase_type()  # pylint: disable=not-callable

        # Beautify testcase
        with open(testcase_path) as testcase_fp:
            self.original_testcase = testcase_fp.read()

        beautified_testcase = jsbeautifier.beautify(self.original_testcase)
        # All try/catch pairs will be expanded on their own lines
        # Collapse these pairs when only a single instruction is contained
        #   within
        regex = r"(\s*try {)\n\s*(.*)\n\s*(}\s*catch.*)"
        beautified_testcase = re.sub(regex, r"\1 \2 \3", beautified_testcase)
        with open(testcase_path, 'w') as testcase_fp:
            testcase_fp.write(beautified_testcase)

        self.lithium.testcase.readTestcase(testcase_path)

    def should_skip(self):
        if HAVE_JSBEAUTIFIER and self.testcase_path.endswith(".js"):
            # jsbeautifier is only effective with JS files
            return False
        return True

    def on_failure(self):
        LOG.warning("JSBeautification failed (reverting)")
        with open(self.testcase_path, 'w') as testcase_fp:
            testcase_fp.write(self.original_testcase)


class CollapseEmptyBraces(ReduceStage):
    name = "collapsebraces"
    strategy_type = lithium.CollapseEmptyBraces
    testcase_type = lithium.TestcaseLine


class MinimizeChars(ReduceStage):
    name = "char"
    strategy_type = lithium.Minimize
    testcase_type = lithium.TestcaseChar


class MinimizeJSChars(ReduceStage):
    name = "jschar"
    strategy_type = lithium.Minimize
    testcase_type = lithium.TestcaseJsStr


def strategies_by_name():
    result = {}
    for cls in globals().values():
        if isinstance(cls, type) and issubclass(cls, ReduceStage) and cls is not ReduceStage:
            if cls.name in result:
                raise RuntimeError("Duplicate strategy name: %s" % (cls.name,))
            result[cls.name] = cls
    return result
