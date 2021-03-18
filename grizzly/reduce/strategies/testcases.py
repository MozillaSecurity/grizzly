# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer testcase list strategy definition."""

from logging import getLogger

from ...common.storage import TestCase
from . import Strategy

LOG = getLogger(__name__)


class MinimizeTestcaseList(Strategy):
    """Try removing testcases from a list of sequential testcases (eg. Grizzly result
    cache). The strategy favours testcases at the tail of the list, so for a list of
    five testcases:
                            testcases
                    0       1 2 3 4 5
        iteration   1         2 3 4 5
                    2       1   3 4 5
                    3       1 2   4 5
                    4       1 2 3   5
                    5       1 2 3 4
    """

    name = "list"

    def __init__(self, testcases):
        """Initialize strategy instance.

        Arguments:
            testcases (list(grizzly.common.storage.TestCase)):
                List of testcases to reduce. The object does not take ownership of the
                testcases.
        """
        super().__init__(testcases)
        self._current_feedback = None
        self._current_served = None

    def update(self, success, served=None):
        """Inform the strategy whether or not the last reduction yielded was good.

        Arguments:
            success (bool): Whether or not the last reduction was acceptable.
            served (list(list(str))): The list of served files for each testcase in the
                                      last reduction.

        Returns:
            None
        """
        assert self._current_feedback is None
        assert self._current_served is None
        self._current_feedback = success
        self._current_served = served

    def __iter__(self):
        """Iterate over potential reductions of testcases according to this strategy.

        The caller should evaluate each testcase set yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            list(grizzly.common.storage.TestCase): list of testcases with reduction
                                                   applied
        """
        assert self._current_feedback is None
        idx = 0
        testcases = None
        try:
            testcases = TestCase.load(str(self._testcase_root), True)
            n_testcases = len(testcases)
            # indicates that self._testcase_root contains changes that haven't been
            # yielded (if iteration ends, changes would be lost)
            testcase_root_dirty = False
            while True:
                if n_testcases <= 1:
                    LOG.info(
                        "Testcase list has length %d, not enough to reduce!",
                        n_testcases,
                    )
                    break
                if idx >= n_testcases:
                    LOG.info("Attempted to remove every single testcase")
                    break
                # try removing the testcase at idx
                if testcases is None:
                    testcases = TestCase.load(str(self._testcase_root), True)
                    assert n_testcases == len(testcases)
                testcases.pop(idx).cleanup()
                yield testcases
                testcases = None  # caller owns testcases now
                assert self._current_feedback is not None, "no feedback received!"

                if self._current_feedback:
                    testcase_root_dirty = False
                    LOG.info(
                        "Removing testcase %d/%d was successful!", idx + 1, n_testcases
                    )
                    testcases = TestCase.load(str(self._testcase_root), True)
                    try:
                        # remove the actual testcase we were reducing
                        testcases.pop(idx).cleanup()
                        if testcases and self._current_served is not None:
                            testcase_root_dirty = self.purge_unserved(
                                testcases, self._current_served
                            )
                        else:
                            self.dump_testcases(testcases, recreate_tcroot=True)
                    finally:
                        for testcase in testcases:
                            testcase.cleanup()
                    testcases = TestCase.load(str(self._testcase_root), True)
                    n_testcases = len(testcases)
                else:
                    LOG.info("No result without testcase %d/%d", idx + 1, n_testcases)
                    idx += 1
                # reset
                self._current_feedback = None
                self._current_served = None
            if testcase_root_dirty:
                # purging unserved files enabled us to exit early from the loop.
                # need to yield once more to set this trimmed version to the current
                # best in ReduceManager
                testcases = TestCase.load(str(self._testcase_root), True)
                LOG.info("[%s] final iteration triggered by purge_optional", self.name)
                yield testcases
                testcases = None  # caller owns testcases now
                assert (
                    self._current_feedback
                ), "Purging unserved files broke the testcase."
        finally:
            if testcases is not None:
                for testcase in testcases:
                    testcase.cleanup()
