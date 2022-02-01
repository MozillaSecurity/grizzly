# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod
from pathlib import Path

__all__ = ("Adapter", "AdapterError")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class AdapterError(Exception):
    """The base class for exceptions raised by an Adapter"""


class Adapter(metaclass=ABCMeta):
    """An Adapter is an interface between Grizzly and a fuzzer. A subclass must
    be created in order to add support for additional fuzzers. The Adapter is
    responsible for handling input/output data and executing the fuzzer.
    It is expected that any processes launched or file created on file system
    in the adapter will also be cleaned up in the adapter.
    NOTE: Some methods must not be overloaded doing so will prevent Grizzly from
    operating correctly.

    Attributes:
        _harness (str): Path to harness file that will be used. If None, no
                        harness will be used.
        fuzz (dict): Available as a safe scratch pad for the end-user.
        monitor (TargetMonitor): Used to provide Target status information to
                                 the adapter.
        name (str): Name of the adapter.
        remaining (int): Can be used to indicate the number of TestCases
                         remaining to process.
    """

    HARNESS_FILE = str((Path(__file__).parent / "../common/harness.html").resolve())
    # Only report test cases with served content.
    IGNORE_UNSERVED = True
    # Maximum iterations between Target relaunches (<1 use default)
    RELAUNCH = 0
    # Maximum execution time per test (used as minimum timeout). The iteration is
    # expected to be complete. If the test is still open the harness will attempt to
    # close it.
    TIME_LIMIT = 30

    __slots__ = ("_harness", "fuzz", "monitor", "name", "remaining")

    def __init__(self, name):
        assert isinstance(name, str)
        if not name:
            raise AdapterError("name must not be empty")
        self._harness = None
        self.fuzz = dict()
        self.monitor = None
        self.name = name
        self.remaining = None

    def cleanup(self):
        """Automatically called once at shutdown. Used internally by Grizzly.
        *** DO NOT OVERLOAD! ***

        Args:
            None

        Returns:
            None
        """
        self.shutdown()

    def enable_harness(self, file_path=None):
        """Enable use of a harness during fuzzing. By default no harness is used.
        *** DO NOT OVERLOAD! ***

        Args:
            file_path (str): Path to file to use as a harness. If None the default
                             harness is used.

        Returns:
            None
        """
        if file_path is None:
            file_path = self.HARNESS_FILE
        with open(file_path, "rb") as in_fp:
            self._harness = in_fp.read()

    def get_harness(self):
        """Get the harness. Used internally by Grizzly.
        *** DO NOT OVERLOAD! ***

        Args:
            None

        Returns:
            TestFile: The active harness.
        """
        return self._harness

    @staticmethod
    def scan_path(path, ignore=("desktop.ini", "thumbs.db"), recursive=False):
        """Scan a path and yield the files within it. This is available as
        a helper method.

        Args:
            path (str): Path to file or directory.
            ignore (iterable(str)): Files to ignore.
            recursive (bool): Scan recursively into directories.

        Yields:
            str: Absolute path to files.
        """
        path = Path(path).resolve()
        if path.is_dir():
            path_iter = path.rglob("*") if recursive else path.glob("*")
            for entry in path_iter:
                if not entry.is_file():
                    continue
                if entry.name in ignore or entry.name.startswith("."):
                    # skip ignored and hidden system files
                    continue
                yield str(entry)
        elif path.is_file():
            yield str(path)

    @abstractmethod
    def generate(self, testcase, server_map):
        """Automatically called. Populate testcase here.

        Args:
            testcase (TestCase): TestCase intended to be populated.
            server_map (ServerMap): A ServerMap.

        Returns:
            None
        """

    def on_served(self, testcase, served):
        """Optional. Automatically called after a test case is successfully served.

        Args:
            testcase (TestCase): TestCase that was served.
            served (list(str)): Files served from testcase.

        Returns:
            None
        """

    def on_timeout(self, testcase, served):
        """Optional. Automatically called if timeout occurs while attempting to
        serve a test case. By default it calls `self.on_served()`.

        Args:
            testcase (TestCase): TestCase that was served.
            served (list(str)): Files served from testcase.

        Returns:
            None
        """
        self.on_served(testcase, served)

    def pre_launch(self):
        """Optional. Automatically called before launching the Target.

        Args:
            None

        Returns:
            None
        """

    def setup(self, input_path, server_map):
        """Optional. Automatically called once at startup.

        Args:
            input_path (str): Points to a file or directory passed by the user.
                              None is passed by default.
            server_map (ServerMap): A ServerMap

        Returns:
            None
        """

    def shutdown(self):
        """Optional. Automatically called once at shutdown.

        Args:
            None

        Returns:
            None
        """
