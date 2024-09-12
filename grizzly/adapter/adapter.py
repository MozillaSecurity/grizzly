# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, final

from ..common.utils import DEFAULT_TIME_LIMIT, HARNESS_FILE

if TYPE_CHECKING:
    from sapphire import ServerMap

    from ..common.storage import TestCase
    from ..target.target_monitor import TargetMonitor

__all__ = ("Adapter", "AdapterError")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class AdapterError(Exception):
    """The base class for exceptions raised by an Adapter"""


class Adapter(metaclass=ABCMeta):
    """An Adapter is the interface between Grizzly and a fuzzer. A subclass must
    be created in order to add support for additional fuzzers. The Adapter is
    responsible for handling input/output data and executing the fuzzer.
    It is expected that any processes launched or files created on file system
    by the adapter will also be cleaned up by the adapter.

    NOTE: Some methods must not be overridden doing so will prevent Grizzly from
    operating correctly.

    Attributes:
        _harness: Harness file that will be used.
        fuzz: Available as a safe scratch pad for the end-user.
        monitor: Used to provide Target status information to the adapter.
        name: Name of the adapter.
        remaining: Can be used to indicate the number of TestCases remaining to process.
    """

    IGNORE_FILES = ("desktop.ini", "thumbs.db")
    # Maximum iterations between Target relaunches (<1 use default)
    RELAUNCH = 0
    # Maximum execution time per test (used as minimum timeout). The iteration is
    # expected to be complete. If the test is still open the harness will attempt to
    # close it.
    TIME_LIMIT = DEFAULT_TIME_LIMIT

    __slots__ = ("_harness", "fuzz", "monitor", "name", "remaining")

    def __init__(self, name: str) -> None:
        assert isinstance(name, str)
        if not name:
            raise AdapterError("name must not be empty")
        if len(name.split()) != 1 or name.strip() != name:
            raise AdapterError("name must not contain whitespace")
        self._harness: bytes | None = None
        self.fuzz: dict[str, Any] = {}
        self.monitor: TargetMonitor | None = None
        self.name = name
        self.remaining: int | None = None

    def __enter__(self) -> Adapter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    @final
    def cleanup(self) -> None:
        """Automatically called once at shutdown. Used internally by Grizzly.
        *** DO NOT OVERRIDE! ***

        Args:
            None

        Returns:
            None
        """
        self.shutdown()

    @final
    def enable_harness(self, path: Path = HARNESS_FILE) -> None:
        """Enable use of a harness during fuzzing. By default no harness is used.
        *** DO NOT OVERRIDE! ***

        Args:
            path: HTML file to use as a harness.

        Returns:
            None
        """
        self._harness = path.read_bytes()
        assert self._harness, f"empty harness file '{path.resolve()}'"

    @final
    def get_harness(self) -> bytes | None:
        """Get the harness. Used internally by Grizzly.
        *** DO NOT OVERRIDE! ***

        Args:
            None

        Returns:
            The active harness data.
        """
        return self._harness

    # TODO: change return type from str to Path and accept Path instead of str
    @staticmethod
    def scan_path(
        path: str,
        ignore: tuple[str, ...] = IGNORE_FILES,
        recursive: bool = False,
    ) -> Generator[str, None, None]:
        """Scan a path and yield the files within it. This is available as
        a helper method.

        Args:
            path: Path to file or directory.
            ignore: File names to ignore.
            recursive: Scan recursively into directories.

        Yields:
            Absolute path to files.
        """
        src = Path(path)
        if src.is_dir():
            path_iter = src.rglob("*") if recursive else src.glob("*")
            for entry in path_iter:
                if not entry.is_file():
                    continue
                if entry.name.lower() in ignore or entry.name.startswith("."):
                    # skip ignored and hidden system files
                    continue
                yield str(entry.resolve())
        elif src.is_file():
            yield str(src.resolve())

    @abstractmethod
    def generate(self, testcase: TestCase, server_map: ServerMap) -> None:
        """Automatically called. Populate testcase here.

        Args:
            testcase: TestCase intended to be populated.
            server_map: A ServerMap.

        Returns:
            None
        """

    def on_served(self, testcase: TestCase, served: tuple[str, ...]) -> None:
        """Optional. Automatically called after a test case is successfully served.

        Args:
            testcase: TestCase that was served.
            served: Files served from testcase.

        Returns:
            None
        """

    def on_timeout(self, testcase: TestCase, served: tuple[str, ...]) -> None:
        """Optional. Automatically called if timeout occurs while attempting to
        serve a test case. By default it calls `self.on_served()`.

        Args:
            testcase: TestCase that was served.
            served: Files served from testcase.

        Returns:
            None
        """
        self.on_served(testcase, served)

    def pre_launch(self) -> None:
        """Optional. Automatically called before launching the Target.

        Args:
            None

        Returns:
            None
        """

    # TODO: update input_path type (str -> Path)
    def setup(self, input_path: str | None, server_map: ServerMap) -> None:
        """Optional. Automatically called once at startup.

        Args:
            input_path: File or directory passed by the user.
            server_map: A ServerMap

        Returns:
            None
        """

    def shutdown(self) -> None:
        """Optional. Automatically called once at shutdown.

        Args:
            None

        Returns:
            None
        """
