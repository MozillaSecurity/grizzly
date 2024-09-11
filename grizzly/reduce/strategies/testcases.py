# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer testcase list strategy definition."""
from __future__ import annotations

from logging import getLogger
from shutil import rmtree
from typing import Generator

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

    def __init__(self, testcases: list[TestCase]) -> None:
        """Initialize strategy instance.

        Arguments:
            testcases: Testcases to reduce. The object does not take ownership of the
                       testcases.
        """
        super().__init__(testcases)
        self._current_feedback: bool | None = None
        # TODO: is this unused?
        self._current_served = None

    def update(self, success: bool) -> None:
        """Inform the strategy whether or not the last reduction yielded was good.

        Arguments:
            success: Whether or not the last reduction was acceptable.

        Returns:
            None
        """
        assert self._current_feedback is None
        assert self._current_served is None
        self._current_feedback = success

    def __iter__(self) -> Generator[list[TestCase], None, None]:
        """Iterate over potential reductions of testcases according to this strategy.

        The caller should evaluate each testcase set yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            Testcases with reduction applied
        """
        assert self._current_feedback is None
        idx = 0
        testcases = [TestCase.load(x) for x in sorted(self._testcase_root.iterdir())]
        n_testcases = len(testcases)
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
            excluded = testcases.pop(idx)
            yield testcases
            assert self._current_feedback is not None, "no feedback received!"
            if self._current_feedback:
                rmtree(excluded.root, ignore_errors=True)
                LOG.info(
                    "Removing testcase %d/%d was successful!", idx + 1, n_testcases
                )
                n_testcases = len(testcases)
            else:
                testcases.insert(idx, excluded)
                LOG.info("No result without testcase %d/%d", idx + 1, n_testcases)
                idx += 1
            # reset
            self._current_feedback = None
            self._current_served = None
