# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer lithium strategy definitions."""
from __future__ import annotations

from abc import ABC
from logging import getLogger
from typing import TYPE_CHECKING, Iterator

from lithium.strategies import CheckOnly, Minimize, ReductionIterator
from lithium.strategies import CollapseEmptyBraces as LithCollapseEmptyBraces
from lithium.strategies import Strategy as LithStrategy
from lithium.testcases import Testcase as LithTestcase
from lithium.testcases import TestcaseAttrs, TestcaseChar, TestcaseJsStr, TestcaseLine

from ...common.storage import TestCase
from . import Strategy, _contains_dd

if TYPE_CHECKING:
    from pathlib import Path

LOG = getLogger(__name__)


class _LithiumStrategy(Strategy, ABC):
    """Use a Lithium `Strategy`/`Testcase` pair to reduce the given Grizzly `TestCase`
    set.

    Implementers must define these class attributes:

    Class attributes:
        name: The strategy name.
        strategy_cls: Lithium strategy type.
        testcase_cls: Lithium testcase type.
    """

    strategy_cls: type[LithStrategy]
    testcase_cls: type[LithTestcase]

    def __init__(self, testcases: list[TestCase]) -> None:
        """Initialize strategy instance.

        Arguments:
            testcases: Testcases to reduce. The object does not take ownership of the
                       testcases.
        """
        super().__init__(testcases)
        self._current_feedback: bool | None = None
        self._current_reducer: ReductionIterator | None = None
        self._files_to_reduce: list[Path] = []
        self.rescan_files_to_reduce(
            [
                TestCase.load(x, catalog=True)
                for x in sorted(self._testcase_root.iterdir())
            ]
        )

    def rescan_files_to_reduce(self, testcases: list[TestCase]) -> None:
        """Repopulate the private `files_to_reduce` attribute by scanning the testcase
        root.

        Returns:
            None
        """
        self._files_to_reduce.clear()
        for test in testcases:
            for path in (test.root / x for x in test):
                if _contains_dd(path):
                    self._files_to_reduce.append(path)

    def update(self, success: bool) -> None:
        """Inform the strategy whether or not the last reduction yielded was good.

        Arguments:
            success: Whether or not the last reduction was acceptable.

        Returns:
            None
        """
        if self._current_reducer is not None:
            self._current_reducer.feedback(success)
        self._current_feedback = success

    def __iter__(self) -> Iterator[list[TestCase]]:
        """Iterate over potential reductions of testcases according to this strategy.

        The caller should evaluate each testcase set yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            Testcases with reduction applied.
        """
        LOG.info("Reducing %d files", len(self._files_to_reduce))
        file_no = 0
        reduce_queue = self._files_to_reduce.copy()
        reduce_queue.sort()  # not necessary, but helps make tests more predictable
        while reduce_queue:
            LOG.debug(
                "Reduce queue: %r",
                ", ".join(
                    str(x.relative_to(self._testcase_root)) for x in reduce_queue
                ),
            )
            file = reduce_queue.pop(0)
            file_no += 1
            LOG.info(
                "[%s] Reducing %s (file %d/%d)",
                self.name,
                file.relative_to(self._testcase_root),
                file_no,
                len(self._files_to_reduce),
            )
            lithium_testcase = self.testcase_cls()  # pylint: disable=not-callable
            lithium_testcase.load(file)
            strategy = self.strategy_cls()  # pylint: disable=not-callable
            self._current_reducer = strategy.reduce(lithium_testcase)

            # Populate the lithium strategy "tried" cache.
            # Use all cache values where all hashes other than the current file match
            #   the current testcase_root state.
            current_tc_hash_map = dict(self._calculate_testcase_hash())
            del current_tc_hash_map[str(file.relative_to(self._testcase_root))]
            this_tc_tried = set()
            for tried in self._tried:
                tried_map = dict(tried)
                tc_tried = tried_map.pop(str(file.relative_to(self._testcase_root)))
                if tried_map == current_tc_hash_map:
                    this_tc_tried.add(tc_tried)
            self._current_reducer.update_tried(this_tc_tried)

            for reduction in self._current_reducer:
                reduction.dump()
                testcases = [
                    TestCase.load(x, catalog=True)
                    for x in sorted(self._testcase_root.iterdir())
                ]
                LOG.info("[%s] %s", self.name, self._current_reducer.description)
                yield testcases
                if not self._current_feedback:
                    self._tried.add(self._calculate_testcase_hash())
                else:
                    LOG.debug(
                        "files being reduced before: %r",
                        ", ".join(
                            str(x.relative_to(self._testcase_root))
                            for x in self._files_to_reduce
                        ),
                    )
                    self.rescan_files_to_reduce(testcases)
                    LOG.debug(
                        "files being reduced after: %r",
                        ", ".join(
                            str(x.relative_to(self._testcase_root))
                            for x in self._files_to_reduce
                        ),
                    )
                    files_to_reduce = set(self._files_to_reduce)
                    reduce_queue = sorted(set(reduce_queue) & files_to_reduce)
                    if file not in files_to_reduce:
                        # current reduction was for a purged file
                        break
            else:
                # write out the best found testcase
                self._current_reducer.testcase.dump()
            self._current_reducer = None


class Check(_LithiumStrategy):
    """Check whether the testcase is reproducible.

    This strategy does no reduction, and only yields once. It is intended to provide a
    pass/fail result in a reduction pipeline.
    """

    name = "check"
    strategy_cls = CheckOnly
    testcase_cls = TestcaseLine

    def __init__(self, testcases: list[TestCase]) -> None:
        super().__init__(testcases)
        # trim files_to_reduce, for check we don't need to run on every file
        # just once per Grizzly TestCase set is enough.
        self._files_to_reduce = self._files_to_reduce[:1]

    def __iter__(self) -> Iterator[list[TestCase]]:
        yield from super().__iter__()


class CollapseEmptyBraces(_LithiumStrategy):
    """Minimize lines, but collapse empty curly braces between each iteration.

    During reduction, the contents of a block may be reduced away entirely, but removing
    the starting brace or ending brace alone will break the syntax of the test file.
    This strategy tries to collapse empty braces onto the same line between each
    iteration, so that empty blocks can be removed if otherwise possible.
    """

    name = "collapsebraces"
    strategy_cls = LithCollapseEmptyBraces
    testcase_cls = TestcaseLine


class MinimizeChars(_LithiumStrategy):
    """Minimize all bytes in the testcase."""

    name = "chars"
    strategy_cls = Minimize
    testcase_cls = TestcaseChar


class MinimizeJSChars(_LithiumStrategy):
    """Minimize all bytes contained in javascript strings.

    This works the same as MinimizeChars, but only operates if it can identify what
    looks like a quoted string. It also treats escaped characters as a single token
    for reduction.
    """

    name = "jschars"
    strategy_cls = Minimize
    testcase_cls = TestcaseJsStr


class MinimizeLines(_LithiumStrategy):
    """Minimize all lines in the testcase."""

    name = "lines"
    strategy_cls = Minimize
    testcase_cls = TestcaseLine


class MinimizeAttrs(_LithiumStrategy):
    """Remove HTML/XML attributes and their values."""

    name = "attrs"
    strategy_cls = Minimize
    testcase_cls = TestcaseAttrs
