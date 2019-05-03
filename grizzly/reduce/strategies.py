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
    import jsbeautifier
    HAVE_JSBEAUTIFIER = True
except ImportError:
    HAVE_JSBEAUTIFIER = False
import six
import lithium

from . import testcase_contents


LOG = logging.getLogger("grizzly.reduce.strategies")


@six.add_metaclass(abc.ABCMeta)
class ReduceStage(object):
    strategy_type = None
    testcase_type = None

    def __init__(self, job, reducer):
        self.job = job
        self.reducer = reducer

    def read_testcase(self, testcase_path):
        if getattr(self.strategy_type, "TAKES_JOB", False):
            self.reducer.strategy = self.strategy_type(self.job)  # pylint: disable=not-callable
        else:
            self.reducer.strategy = self.strategy_type()  # pylint: disable=not-callable
        self.reducer.testcase = self.testcase_type()  # pylint: disable=not-callable
        LOG.info("Reducing %s with %s on %ss",
                 testcase_path, self.strategy_type.name, self.testcase_type.atom)
        self.reducer.testcase.readTestcase(testcase_path)

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
    TAKES_JOB = True
    ITERATIONS = 11  # number of iterations to analyze
    MIN_CRASHES = 2  # --min-crashes value when analysis is used
    TARGET_PROBABILITY = 0.95  # probability that successful reduction will observe the crash
    # to see the worst case, run the `self.interesting.repeat` calculation below using
    # crashes_percent = 1.0/ITERATIONS

    def __init__(self, job):
        super(_AnalyzeReliability, self).__init__()
        self.job = job

    def main(self, testcase, interesting, tempFilename):

        assert self.ITERATIONS > 0

        # disable result cache setting
        use_result_cache = self.job.interesting.use_result_cache
        self.job.interesting.use_result_cache = False

        # Reset parameters.
        # Use repeat=1 & relaunch=ITERATIONS because this is closer to how we will run
        #   post-analysis.
        # We're only using repeat=1 instead of repeat=ITERATIONS so we can get feedback on every
        #   call to interesting.
        self.job.interesting.repeat = 1
        self.job.interesting.min_crashes = 1
        self.job.interesting.target.rl_reset = min(self.job.original_relaunch, self.ITERATIONS)

        harness_crashes = 0
        non_harness_crashes = 0

        # close target so new parameters take effect
        if not self.job.interesting.target.closed:
            self.job.interesting.target.close()

        if not self.job.force_no_harness:
            LOG.info("Running for %d iterations to assess reliability using harness.", self.ITERATIONS)
            for _ in range(self.ITERATIONS):
                result = interesting(testcase, writeIt=False)  # pylint: disable=invalid-name
                LOG.info("Lithium result: %s", "interesting." if result else "not interesting.")
                if result:
                    harness_crashes += 1
            LOG.info("Testcase was interesting %0.1f%% of %d attempts using harness for iteration.",
                     100.0 * harness_crashes / self.ITERATIONS, self.ITERATIONS)

            # close target so new parameters take effect
            if not self.job.interesting.target.closed:
                self.job.interesting.target.close()

        if harness_crashes != self.ITERATIONS:
            # try without harness
            self.job.interesting.no_harness = True

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
            if not self.job.interesting.target.closed:
                self.job.interesting.target.close()

        # restore result cache setting
        self.job.interesting.use_result_cache = use_result_cache

        if harness_crashes == 0 and non_harness_crashes == 0:
            return 1  # no crashes ever?

        # should we use the harness? go with whichever crashed more
        self.job.interesting.no_harness = non_harness_crashes > harness_crashes
        # this is max 99% to avoid domain errors in the calculation below
        crashes_percent = min(1.0 * max(non_harness_crashes, harness_crashes) / self.ITERATIONS, 0.99)

        # adjust repeat/min-crashes depending on how reliable the testcase was
        self.job.interesting.min_crashes = self.MIN_CRASHES
        self.job.interesting.repeat = \
            int(math.log(1 - self.TARGET_PROBABILITY, 1 - crashes_percent) + 0.5) * self.MIN_CRASHES

        # set relaunch to min(relaunch, repeat)
        self.job.interesting.target.rl_reset = min(self.job.original_relaunch, self.job.interesting.repeat)

        LOG.info("Analysis results:")
        if harness_crashes == self.ITERATIONS:
            LOG.info("* testcase was perfectly reliable with the harness (--no-harness not assessed)")
        elif harness_crashes == non_harness_crashes:
            LOG.info("* testcase was equally reliable with/without the harness")
        elif self.job.force_no_harness:
            LOG.info("* --no-harness was already set")
        else:
            LOG.info("* testcase was %s reliable with the harness",
                     "less" if self.job.interesting.no_harness else "more")
        LOG.info("* adjusted parameters: --min-crashes=%d --repeat=%d --relaunch=%d",
                 self.job.interesting.min_crashes, self.job.interesting.repeat,
                 self.job.interesting.target.rl_reset)

        return 0


class AnalyzeTestcase(ReduceStage):
    name = "analyze"
    strategy_type = _AnalyzeReliability
    testcase_type = lithium.TestcaseLine

    def on_success(self):
        super(AnalyzeTestcase, self).on_success()
        # only run this strategy once, not once per reducible file in the testcase
        raise StopIteration()


class MinimizeCacheIterHarness(MinimizeLines):
    name = "minimize-cache"

    def should_skip(self):
        return not self.job.cache_iter_harness_created

    def read_testcase(self, testcase_path):
        if self.should_skip():
            return

        super(MinimizeCacheIterHarness, self).read_testcase(testcase_path)

        # we are running multiple testcases in a single "iteration", so we need to
        #   fix the timeout values

        # start polling for idle after n-1 testcases have finished
        self.job.interesting.idle_timeout += \
            self.job.interesting.idle_timeout * (len(self.reducer.testcase) - 1)

        # iteration timeout is * n testcases, but add 10 seconds for overhead from the
        #   outer harness
        self.job.interesting.iter_timeout = \
            (self.job.interesting.iter_timeout + 10) * len(self.reducer.testcase)

    def on_success(self):
        while self.job.files_to_reduce:
            self.job.files_to_reduce.pop()
        lines = lithium.TestcaseLine()
        lines.readTestcase(self.job.testcase)
        if len(lines) == 1:
            # we reduced this down to a single testcase, remove the harness
            testcase_rel = lines.parts[0].strip().decode("utf-8")
            assert testcase_rel.startswith("'/")
            assert testcase_rel.endswith("',")
            testcase_rel = testcase_rel[2:-2]  # trim chars asserted above
            testcase_path = testcase_rel.split('/')
            assert len(testcase_path) == 2
            self.job.tcroot = os.path.join(self.job.tcroot, testcase_path[0])
            self.job.testcase = os.path.join(self.job.tcroot, testcase_path[1])
            self.job.interesting.landing_page = self.job.testcase
            self.job.files_to_reduce.append(self.job.testcase)
            LOG.info("Reduced history to a single file: %s", testcase_path[1])
        else:
            # don't bother trying to reduce the harness further,
            #   leave harness out of files_to_reduce
            LOG.info("Reduced history down to %d testcases", len(self.reducer.testcase))


class ScanFilesToReduce(ReduceStage):
    name = "scan-files"

    def __init__(self, *args, **kwds):
        super(ScanFilesToReduce, self).__init__(*args, **kwds)
        # find all files for reduction
        for file_name in testcase_contents(self.job.tcroot):
            file_name = os.path.join(self.job.tcroot, file_name)
            if file_name == self.job.testcase:
                continue
            with open(file_name, "rb") as tc_fp:
                for line in tc_fp:
                    if b"DDBEGIN" in line:
                        self.job.files_to_reduce.append(file_name)
                        break
        if len(self.job.files_to_reduce) > 1:
            # sort by descending size
            self.job.files_to_reduce.sort(key=lambda fn: os.stat(fn).st_size, reverse=True)
        self.job.original_size[0] = sum(os.stat(fn).st_size for fn in self.job.files_to_reduce)

    def read_testcase(self, testcase_path):
        pass

    def should_skip(self):  # pylint: disable=no-self-argument
        # no real reduce strategy, just used to scan for files
        return True


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

        LOG.info("Attempting to beautify %s", testcase_path)

        self.reducer.strategy = self.strategy_type()  # pylint: disable=not-callable
        self.reducer.testcase = self.testcase_type()  # pylint: disable=not-callable

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

        self.reducer.testcase.readTestcase(testcase_path)

    def should_skip(self):
        if HAVE_JSBEAUTIFIER and self.testcase_path.endswith(".js"):
            # jsbeautifier is only effective with JS files
            return False
        return True

    def on_failure(self):
        LOG.warning("Beautification failed (reverting)")
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
