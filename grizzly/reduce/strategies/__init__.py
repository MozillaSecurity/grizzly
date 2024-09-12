# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer strategy definitions.

Each class defined here is an iterator yielding *potential* reductions. The caller
should evaluate each set of testcases, and keep the best one. The caller is responsible
for cleaning up all testcases that are yielded.

Constants:
    DEFAULT_STRATEGIES: Strategy names run by default if unspecified.
    STRATEGIES: Mapping of available strategy names to implementing class.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from hashlib import sha512
from logging import DEBUG, getLogger
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from typing import TYPE_CHECKING, Iterable, Iterator, Type, cast

from ...common.utils import grz_tmp

if TYPE_CHECKING:
    from ...common.storage import TestCase

try:
    from pkg_resources import iter_entry_points
except ImportError:
    from ...common.utils import iter_entry_points  # type: ignore

LOG = getLogger(__name__)


DEFAULT_STRATEGIES = (
    "list",
    "lines",
    "cssbeautify",
    "jsbeautify",
    "collapsebraces",
    "attrs",
)


class Strategy(ABC):
    """A strategy is a procedure for repeatedly running a testcase to find the smallest
    equivalent test.

    Implementers must define these class attributes:

    Class Attributes:
        name: The strategy name.
    """

    name: str

    def __init__(self, testcases: list[TestCase]) -> None:
        """Initialize strategy instance.

        Arguments:
            testcases: Testcases to reduce. The object does not take ownership of the
                       testcases.
        """
        # Tuple[str, bytes] is str(path.relative_to(tc_root)) -> hash(testfile data)
        #   for each test file in tc_root (see calculate_testcase_hash below)
        # Tuple[above, ...] is all the test files for a set of test cases meaning:
        #   0/**, 1/**, etc.
        # Set[above] is the unique test case sets which have been tried
        self._tried: set[tuple[tuple[str, bytes], ...]] = set()
        self._testcase_root = Path(mkdtemp(prefix="tc_", dir=grz_tmp("reduce")))
        self.dump_testcases(testcases)

    def _calculate_testcase_hash(self) -> tuple[tuple[str, bytes], ...]:
        """Calculate hashes of all files in testcase root.

        Returns:
            Mapping of file path to SHA-512 of each file in testcase root.
        """
        result: list[tuple[str, bytes]] = []
        for path in self._testcase_root.glob("**/*"):
            if path.is_file():
                tf_hash = sha512()
                tf_hash.update(path.read_bytes())
                result.append(
                    (str(path.relative_to(self._testcase_root)), tf_hash.digest())
                )
        sorted_result = tuple(sorted(result))

        if LOG.getEffectiveLevel() == DEBUG:
            print_hash = sha512()
            print_hash.update(
                repr(sorted_result).encode("utf-8", errors="surrogateescape")
            )
            in_tried = sorted_result in self._tried
            LOG.debug(
                "Testcase hash: %s (%sin cache)",
                print_hash.hexdigest()[:32],
                "" if in_tried else "not ",
            )

        return sorted_result

    def update_tried(self, tried: Iterable[tuple[tuple[str, bytes], ...]]) -> None:
        """Update the list of tried testcase/hash sets. Testcases are hashed with
        SHA-512 and digested to bytes (`hashlib.sha512(testcase).digest()`)

        Arguments:
            tried: Collection of already tried testcase hashes.

        Returns:
            None
        """
        self._tried.update(frozenset(tried))

    def get_tried(self) -> frozenset[tuple[tuple[str, bytes], ...]]:
        """Return the set of tried testcase hashes. Testcases are hashed with SHA-512
        and digested to bytes (`hashlib.sha512(testcase).digest()`)

        Returns:
            Testcase hashes.
        """
        return frozenset(self._tried)

    def dump_testcases(
        self, testcases: list[TestCase], recreate_tcroot: bool = False
    ) -> None:
        """Dump a testcase list to the testcase root on disk.

        Arguments:
            testcases: Testcases to dump.
            recreate_tcroot: if True, delete and recreate tcroot before dumping it.

        Returns:
            None
        """
        if recreate_tcroot:
            rmtree(self._testcase_root)
            self._testcase_root.mkdir()
        for idx, testcase in enumerate(testcases):
            LOG.debug("Extracting testcase %d/%d", idx + 1, len(testcases))
            # NOTE: naming determines load order
            testcase.dump(self._testcase_root / f"{idx:03d}", include_details=True)

    @abstractmethod
    def __iter__(self) -> Iterator[list[TestCase]]:
        """Iterate over potential reductions of testcases according to this strategy.

        The caller should evaluate each reduction yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            Testcases with reduction applied.
        """

    @abstractmethod
    def update(self, success: bool) -> None:
        """Inform the strategy whether or not the last reduction yielded was good.

        Arguments:
            success: Whether or not the last reduction was acceptable.

        Returns:
            None
        """

    def __enter__(self) -> Strategy:
        """Enter a runtime context that will automatically call `cleanup` on exit.

        Returns:
            self
        """
        return self

    def __exit__(self, *exc: object) -> None:
        """Exit the runtime context. `cleanup` is called.

        Arguments:

        Returns:
            None
        """
        self.cleanup()

    def cleanup(self) -> None:
        """Destroy all resources held by the strategy.

        Returns:
            None
        """
        rmtree(self._testcase_root)


def _load_strategies() -> dict[str, type[Strategy]]:
    """STRATEGIES is created at the end of this file.

    Returns:
        A mapping of strategy names to strategy class.
    """
    strategies: dict[str, type[Strategy]] = {}
    for entry_point in iter_entry_points("grizzly_reduce_strategies"):
        try:
            strategy_cls = cast(Type[Strategy], entry_point.load())
            assert (
                strategy_cls.name == entry_point.name
            ), f"entry_point name mismatch, check setup.py and {strategy_cls.__name__}"
        except Exception as exc:  # pylint: disable=broad-except
            LOG.debug("error loading strategy type %s: %s", entry_point.name, exc)
            continue
        strategies[entry_point.name] = strategy_cls
    for strategy in DEFAULT_STRATEGIES:
        assert strategy in strategies, (
            f"Unknown entry in DEFAULT_STRATEGIES: {strategy} "
            f"(STRATEGIES: [{','.join(strategies)}])"
        )
    return strategies


def _contains_dd(path: Path) -> bool:
    data = path.read_bytes()
    return b"DDBEGIN" in data and b"DDEND" in data


STRATEGIES = _load_strategies()
