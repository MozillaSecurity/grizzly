# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer strategy definitions.

Each class defined here is an iterator yielding *potential* reductions. The caller
should evaluate each set of testcases, and keep the best one. The caller is responsible
for cleaning up all testcases that are yielded.

Constants:
    DEFAULT_STRATEGIES (list(str)): List of strategy names run by default if none are
                                    specified.
    STRATEGIES (dict{str: Strategy}): Mapping of available strategy names to
                                      implementing class.
"""
from abc import ABC, abstractmethod
from hashlib import sha512
from logging import DEBUG, getLogger
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from types import MappingProxyType

from pkg_resources import iter_entry_points

from ...common.utils import grz_tmp

LOG = getLogger(__name__)


DEFAULT_STRATEGIES = (
    "list",
    "lines",
    "cssbeautify",
    "jsbeautify",
    "collapsebraces",
    "attrs",
)


def _load_strategies():
    """STRATEGIES is created at the end of this file.

    Returns:
        mapping: A mapping of strategy names to strategy class.
    """
    strategies = {}
    for entry_point in iter_entry_points("grizzly_reduce_strategies"):
        try:
            strategy_cls = entry_point.load()
            strategy_cls.sanity_check_cls_attrs()
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
            strategy,
            ",".join(strategies),
        )
    return MappingProxyType(strategies)


def _contains_dd(path):
    data = path.read_bytes()
    return b"DDBEGIN" in data and b"DDEND" in data


class Strategy(ABC):
    """A strategy is a procedure for repeatedly running a testcase to find the smallest
    equivalent test.

    Implementors must define these class attributes:

    Class Attributes:
        name (str): The strategy name.
    """

    name = None

    def __init__(self, testcases):
        """Initialize strategy instance.

        Arguments:
            testcases (list(grizzly.common.storage.TestCase)):
                List of testcases to reduce. The object does not take ownership of the
                testcases.
        """
        self._tried = set()  # set of tuple(tuple(str(Path), SHA512))
        self._testcase_root = Path(mkdtemp(prefix="tc_", dir=grz_tmp("reduce")))
        self.dump_testcases(testcases)

    def _calculate_testcase_hash(self):
        """Calculate hashes of all files in testcase root.

        Returns:
            tuple(tuple(str, str)): A tuple of 2-tuples mapping str(Path) to SHA-512 of
                                    each file in testcase root.
        """
        result = []
        for path in self._testcase_root.glob("**/*"):
            if path.is_file():
                tf_hash = sha512()
                tf_hash.update(path.read_bytes())
                result.append(
                    (str(path.relative_to(self._testcase_root)), tf_hash.digest())
                )
        result = tuple(sorted(result))

        if LOG.getEffectiveLevel() == DEBUG:
            print_hash = sha512()
            print_hash.update(repr(result).encode("utf-8", errors="surrogateescape"))
            in_tried = result in self._tried
            LOG.debug(
                "Testcase hash: %s (%sin cache)",
                print_hash.hexdigest()[:32],
                "" if in_tried else "not ",
            )

        return result

    def update_tried(self, tried):
        """Update the list of tried testcase/hash sets. Testcases are hashed with
        SHA-512 and digested to bytes (`hashlib.sha512(testcase).digest()`)

        Arguments:
            tried (iterable(tuple(tuple(str, str)))): Set of already tried testcase
                                                      hashes.

        Returns:
            None
        """
        self._tried.update(frozenset(tried))

    def get_tried(self):
        """Return the set of tried testcase hashes. Testcases are hashed with SHA-512
        and digested to bytes (`hashlib.sha512(testcase).digest()`)

        Returns:
            frozenset(tuple(tuple(str, str))): Testcase hashes.
        """
        return frozenset(self._tried)

    def dump_testcases(self, testcases, recreate_tcroot=False):
        """Dump a testcase list to the testcase root on disk.

        Arguments:
            testcases (list(grizzly.common.storage.TestCase)): list of testcases to dump
            recreate_tcroot (bool): if True, delete testcase root and recreate it before
                                    dumping

        Returns:
            None
        """
        if recreate_tcroot:
            rmtree(str(self._testcase_root))
            self._testcase_root.mkdir()
        for idx, testcase in enumerate(testcases):
            LOG.debug("Extracting testcase %d/%d", idx + 1, len(testcases))
            testpath = self._testcase_root / ("%03d" % (idx,))
            testcase.dump(str(testpath), include_details=True)

    @classmethod
    def sanity_check_cls_attrs(cls):
        """Sanity check the strategy class implementation.

        This should assert that any required class attributes are defined and correct.

        Raises:
            AssertionError: Any required class attributes are missing or wrong type.

        Returns:
            None
        """
        assert isinstance(cls.name, str)

    @abstractmethod
    def __iter__(self):
        """Iterate over potential reductions of testcases according to this strategy.

        The caller should evaluate each reduction yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            list(grizzly.common.storage.TestCase): list of testcases with reduction
                                                   applied
        """

    @abstractmethod
    def update(self, success, served=None):
        """Inform the strategy whether or not the last reduction yielded was good.

        Arguments:
            success (bool): Whether or not the last reduction was acceptable.
            served (list(list(str))): The list of served files for each testcase in the
                                      last reduction.

        Returns:
            None
        """

    def __enter__(self):
        """Enter a runtime context that will automatically call `cleanup` on exit.

        Returns:
            Strategy: self
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the runtime context. `cleanup` is called.

        Arguments:
            exc_type (type or None): Type of exception object currently raised.
            exc_val (Exception or None): Exception object currently raised.
            exc_tb (traceback or None): Traceback for currently raised exception.

        Returns:
            None
        """
        self.cleanup()

    def cleanup(self):
        """Destroy all resources held by the strategy.

        Returns:
            None
        """
        rmtree(str(self._testcase_root))

    def purge_unserved(self, testcases, served):
        """Given the testcase list yielded and list of what was served, purge
        everything in testcase root to hold only what was served.

        Arguments:
            testcases (list(grizzly.common.storage.TestCase): testcases last replayed
            served (list(list(str))): list of files served for each testcase.

        Returns:
            bool: True if anything was purged
        """
        LOG.debug("purging from %d testcases", len(testcases))
        anything_purged = False
        while len(served) < len(testcases):
            LOG.debug(
                "not all %d testcases served (%d served), popping one",
                len(testcases),
                len(served),
            )
            testcases.pop().cleanup()
            anything_purged = True
        remove_testcases = []
        for idx, (testcase, tc_served) in enumerate(zip(testcases, served)):
            LOG.debug("testcase %d served %r", idx, tc_served)
            if testcase.landing_page not in tc_served:
                LOG.debug("landing page %r not served", testcase.landing_page)
                remove_testcases.append(idx)
                anything_purged = True
            else:
                size_before = testcase.data_size
                testcase.purge_optional(tc_served)
                anything_purged = anything_purged or testcase.data_size != size_before
        for idx in reversed(remove_testcases):
            testcases.pop(idx).cleanup()
        self.dump_testcases(testcases, recreate_tcroot=True)
        return anything_purged


STRATEGIES = _load_strategies()
