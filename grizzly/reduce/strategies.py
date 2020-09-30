# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Grizzly Reducer strategy definitions
"""
from abc import ABC, abstractmethod
import json
from logging import getLogger
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from types import MappingProxyType

from lithium.strategies import CheckOnly, Minimize
from lithium.testcases import TestcaseChar, TestcaseLine
from pkg_resources import iter_entry_points

from ..common.utils import grz_tmp
from ..common.storage import TestCase


LOG = getLogger(__name__)


DEFAULT_STRATEGIES = (
    "list",
    "lines",
)


def _load_strategies():
    """STRATEGIES is created at the end of this file.
    """
    strategies = {}
    for entry_point in iter_entry_points("grizzly_reduce_strategies"):
        try:
            strategy_cls = entry_point.load()
            assert (
                strategy_cls.name == entry_point.name
            ), "entry_point name mismatch, check setup.py and %s.name" % (
                strategy_cls.__name__,
            )
        except Exception as exc:  # pylint: disable=broad-except
            LOG.debug("error loading strategy type %s: %s", entry_point.name, exc)
            continue
        strategies[entry_point.name] = strategy_cls
    for strategy in DEFAULT_STRATEGIES:
        assert (
            strategy in strategies
        ), "Unknown entry in DEFAULT_STRATEGIES: %s (STRATEGIES: [%s])" % (
            strategy, ",".join(strategies)
        )
    return MappingProxyType(strategies)


class Strategy(ABC):
    def __init__(self, testcases):
        self._testcase_root = Path(mkdtemp(prefix="tc_", dir=grz_tmp("reduce")))
        for idx, testcase in enumerate(testcases):
            LOG.debug("Extracting testcase %d/%d", idx + 1, len(testcases))
            testpath = self._testcase_root / ("%03d" % (idx,))
            testcase.dump(str(testpath), include_details=True)

    @abstractmethod
    def __iter__(self):
        pass

    @abstractmethod
    def update(self, success):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwds):
        self.cleanup()

    def cleanup(self):
        rmtree(str(self._testcase_root))


class _LithiumStrategy(Strategy, ABC):
    """Must define name, testcase_cls (lithium.testcases.Testcase), and
    strategy_cls (lithium.strategies.Strategy).
    """
    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self._current_reducer = None
        self._files_to_reduce = []
        for path in self._testcase_root.glob("**/*"):
            if path.is_file() and path.name not in {"test_info.json", "prefs.js"}:
                self._files_to_reduce.append(path)

    def update(self, success):
        assert self._current_reducer is not None
        self._current_reducer.feedback(success)

    def __iter__(self):
        LOG.info("Reducing %d files", len(self._files_to_reduce))
        for file_no, file in enumerate(self._files_to_reduce):
            LOG.info("Reducing %s (file %d/%d)", file, file_no + 1, len(self._files_to_reduce))
            lithium_testcase = self.testcase_cls()  # pylint: disable=no-member
            lithium_testcase.load(file)
            # pylint: disable=no-member
            self._current_reducer = self.strategy_cls().reduce(lithium_testcase)
            for reduction in self._current_reducer:
                reduction.dump()
                yield TestCase.load(str(self._testcase_root), False)
            # write out the best found testcase
            self._current_reducer.testcase.dump()
            self._current_reducer = None


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

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self._current_feedback = None

    def update(self, success):
        assert self._current_feedback is None
        self._current_feedback = success

    def __iter__(self):
        assert self._current_feedback is None
        idx = 0
        testcases = None
        try:
            testcases = TestCase.load(str(self._testcase_root), False)
            n_testcases = len(testcases)
            while True:
                if n_testcases <= 1:
                    LOG.info("Testcase list has length %d, not enough to reduce!", n_testcases)
                    break
                if idx >= n_testcases:
                    LOG.info("Attempted to remove every single testcase")
                    break
                # try removing the testcase at idx
                if testcases is None:
                    testcases = TestCase.load(str(self._testcase_root), False)
                    assert n_testcases == len(testcases)
                removed_ts = testcases[idx].timestamp
                testcases.pop(idx).cleanup()
                yield testcases
                testcases = None  # caller owns testcases now
                assert self._current_feedback is not None, "no feedback received!"
                if self._current_feedback:
                    # removal was success! find the testcase that matches timestamp,
                    # and remove it
                    LOG.info("Removing testcase %d/%d was successful!", idx, n_testcases)
                    removed_path = None
                    for test_info in self._testcase_root.glob("*/test_info.json"):
                        info = json.loads(test_info.read_text())
                        if removed_ts == info["timestamp"]:
                            assert (
                                removed_path is None
                            ), "Duplicate testcases found with timestamp %s" % (
                                removed_ts,
                            )
                            removed_path = test_info
                    assert (
                        removed_path is not None
                    ), "No testcase found with timestamp %s" % (removed_ts,)
                    rmtree(str(removed_path.parent))
                    n_testcases -= 1
                else:
                    LOG.info("No result without testcase %d/%d", idx, n_testcases)
                    idx += 1
                # reset
                self._current_feedback = None
        finally:
            if testcases is not None:
                for testcase in testcases:
                    testcase.cleanup()


class Check(_LithiumStrategy):
    name = "check"
    strategy_cls = CheckOnly
    testcase_cls = TestcaseLine


class MinimizeLines(_LithiumStrategy):
    name = "lines"
    strategy_cls = Minimize
    testcase_cls = TestcaseLine


class MinimizeChars(_LithiumStrategy):
    name = "chars"
    strategy_cls = Minimize
    testcase_cls = TestcaseChar


STRATEGIES = _load_strategies()
