# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import logging
import re

try:
    import jsbeautifier
    HAVE_JSBEAUTIFIER = True
except ImportError:
    HAVE_JSBEAUTIFIER = False
import lithium


log = logging.getLogger("grizzly.reduce.strategies")  # pylint: disable=invalid-name


class ReduceStage(object):
    strategy_type = None
    testcase_type = None

    def read_testcase(self, reducer, testcase_path):
        reducer.strategy = self.strategy_type()  # pylint: disable=not-callable
        reducer.testcase = self.testcase_type()  # pylint: disable=not-callable
        log.info("Reducing %s with %s on %ss",
                 testcase_path, self.strategy_type.name, self.testcase_type.atom)
        reducer.testcase.readTestcase(testcase_path)

    def should_skip(self):
        return False

    def on_success(self):
        log.info("%s succeeded", type(self).__name__)

    def on_failure(self):
        raise StopIteration()


class MinimizeLines(ReduceStage):
    name = "line"
    strategy_type = lithium.Minimize
    testcase_type = lithium.TestcaseLine


class JSBeautify(ReduceStage):
    name = "jsbeautify"
    strategy_type = lithium.CheckOnly
    testcase_type = lithium.TestcaseLine

    def read_testcase(self, reducer, testcase_path):
        self.testcase_path = testcase_path

        if self.should_skip():
            return

        log.info("Attempting to beautify %s", testcase_path)

        reducer.strategy = self.strategy_type()  # pylint: disable=not-callable
        reducer.testcase = self.testcase_type()  # pylint: disable=not-callable

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

        reducer.testcase.readTestcase(testcase_path)

    def should_skip(self):
        if HAVE_JSBEAUTIFIER and self.testcase_path.endswith(".js"):
            # jsbeautifier is only effective with JS files
            return False
        return True

    def on_failure(self):
        log.warning("Beautification failed (reverting)")
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
