# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
from collections import namedtuple
from itertools import chain, product
from os.path import normpath, split
from pathlib import Path
from shutil import copyfile, move, rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from time import time
from zipfile import BadZipfile, ZipFile
from zlib import error as zlib_error

from ..target import AssetError, AssetManager
from .utils import grz_tmp

__all__ = ("TestCase", "TestCaseLoadFailure", "TestFileExists")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class TestCaseLoadFailure(Exception):
    """Raised when loading a TestCase fails"""


class TestFileExists(Exception):
    """Raised when adding a TestFile to a TestCase that has an existing
    TestFile with the same name"""


TestFile = namedtuple("TestFile", "file_name data_file")
TestFileMap = namedtuple("TestFileMap", "optional required")


class TestCase:
    __slots__ = (
        "adapter_name",
        "assets",
        "duration",
        "env_vars",
        "hang",
        "input_fname",
        "landing_page",
        "redirect_page",
        "time_limit",
        "timestamp",
        "_data_path",
        "_files",
    )

    def __init__(
        self,
        landing_page,
        redirect_page,
        adapter_name,
        input_fname=None,
        time_limit=None,
        timestamp=None,
    ):
        self.adapter_name = adapter_name
        self.assets = None
        self.duration = None
        self.env_vars = dict()
        self.hang = False
        self.input_fname = input_fname  # file that was used to create the test case
        self.landing_page = self.sanitize_path(landing_page)
        if redirect_page is not None:
            self.redirect_page = self.sanitize_path(redirect_page)
        else:
            self.redirect_page = None
        self.time_limit = time_limit
        self.timestamp = time() if timestamp is None else timestamp
        self._files = TestFileMap(optional=list(), required=list())
        self._data_path = Path(mkdtemp(prefix="testcase_", dir=grz_tmp("storage")))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add_batch(self, path, include_files, prefix=None, copy=True):
        """Iterate over files in include_files and attach the files that are
        located in path to TestCase.

        Args:
            path (str): Path to the root of the directory that contains files.
            include_files (iterable(str)): Paths of the files to be added to the
                                           TestCase if they exist in path.
            prefix (str): Path prefix to prepend to file when adding to
                          the TestCase.
            copy (bool): File will be copied if True otherwise the file will be moved.

        Returns:
            None
        """
        path = Path(path)
        for fname in include_files:
            file = Path(fname)
            try:
                relative = file.relative_to(path)
            except ValueError:
                # cannot add files outside path
                continue
            if prefix:
                relative = prefix / relative
            self.add_from_file(file, file_name=relative.as_posix(), copy=copy)

    def add_from_bytes(self, data, file_name, required=False):
        """Create a file and add it to the TestCase.

        Args:
            data (bytes): Data to write to file.
            file_name (str): Used as file path on disk and URI. Relative to wwwroot.
            required (bool): Indicates whether the file must be served.

        Returns:
            None
        """
        assert isinstance(data, bytes)
        with NamedTemporaryFile(delete=False, dir=grz_tmp("storage")) as in_fp:
            in_fp.write(data)
            data_file = Path(in_fp.name)

        try:
            self.add_from_file(
                data_file, file_name=file_name, required=required, copy=False
            )
        finally:
            # the temporary file should have been moved to the data path of the TestCase
            # unless an exception occurred so remove it if needed
            if data_file.is_file():
                data_file.unlink()

    def add_from_file(self, src_file, file_name=None, required=False, copy=False):
        """Add a file to the TestCase by either copying or moving an existing file.

        Args:
            src_file (str): Path to existing file to use.
            file_name (str): Used as file path on disk and URI. Relative to wwwroot.
                             If file_name is not given the name of the src_file
                             will be used.
            required (bool): Indicates whether the file must be served.
            copy (bool): File will be copied if True otherwise the file will be moved.

        Returns:
            None
        """
        src_file = Path(src_file)
        if file_name is None:
            file_name = src_file.name
        file_name = self.sanitize_path(file_name)

        test_file = TestFile(file_name, self._data_path / file_name)
        if test_file.file_name in self.contents:
            raise TestFileExists("%r exists in test" % (test_file.file_name,))

        test_file.data_file.parent.mkdir(parents=True, exist_ok=True)
        if copy:
            copyfile(src_file, test_file.data_file)
        else:
            move(src_file, test_file.data_file)

        # landing_page is always 'required'
        if required or test_file.file_name == self.landing_page:
            self._files.required.append(test_file)
        else:
            self._files.optional.append(test_file)

    def cleanup(self):
        """Remove all the test files.

        Args:
            None

        Returns:
            None
        """
        rmtree(self._data_path, ignore_errors=True)

    def clone(self):
        """Make a copy of the TestCase.

        Args:
            None

        Returns:
            TestCase: A copy of the TestCase instance.
        """
        result = type(self)(
            self.landing_page,
            self.redirect_page,
            self.adapter_name,
            self.input_fname,
            self.time_limit,
            self.timestamp,
        )
        result.assets = self.assets
        result.duration = self.duration
        result.env_vars = dict(self.env_vars)
        result.hang = self.hang

        # copy test data files
        for entry, required in chain(
            product(self._files.required, [True]),
            product(self._files.optional, [False]),
        ):
            result.add_from_file(
                entry.data_file, file_name=entry.file_name, required=required, copy=True
            )
        return result

    @property
    def contents(self):
        """All files in TestCase.

        Args:
            None

        Yields:
            str: File path (relative to wwwroot).
        """
        for tfile in chain(self._files.required, self._files.optional):
            yield tfile.file_name

    @property
    def data_path(self):
        """Location test data is stored on disk. This is intended to be used as wwwroot.

        Args:
            None

        Returns:
            str: Path to directory containing test case files.
        """
        return str(self._data_path)

    @property
    def data_size(self):
        """Total amount of data used (bytes) by the files in the TestCase.

        Args:
            None

        Returns:
            int: Total size of the TestCase in bytes.
        """
        total = 0
        for group in self._files:
            total += sum(x.data_file.stat().st_size for x in group)
        return total

    def dump(self, dst_path, include_details=False):
        """Write all the test case data to the filesystem.

        Args:
            dst_path (str): Path to directory to output data.
            include_details (bool): Output "test_info.json" file.

        Returns:
            None
        """
        dst_path = Path(dst_path)
        # save test files to dst_path
        for test_file in chain(self._files.required, self._files.optional):
            dst_file = dst_path / test_file.file_name
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            copyfile(test_file.data_file, dst_file)
        # save test case files and meta data including:
        # adapter used, input file, environment info and files
        if include_details:
            assert isinstance(self.env_vars, dict)
            info = {
                "adapter": self.adapter_name,
                "duration": self.duration,
                "env": self.env_vars,
                "hang": self.hang,
                "input": Path(self.input_fname).name if self.input_fname else None,
                "target": self.landing_page,
                "time_limit": self.time_limit,
                "timestamp": self.timestamp,
            }
            # save target assets and update meta data
            if self.assets and not self.assets.is_empty():
                info["assets_path"] = "_assets_"
                info["assets"] = self.assets.dump(
                    str(dst_path), subdir=info["assets_path"]
                )
            with (dst_path / "test_info.json").open("w") as out_fp:
                json.dump(info, out_fp, indent=2, sort_keys=True)

    def get_file(self, path):
        """Lookup and return the TestFile with the specified file name.

        Args:
            path (str): Path (relative to wwwroot) of TestFile to retrieve.

        Returns:
            TestFile: TestFile with matching path otherwise None.
        """
        for tfile in chain(self._files.optional, self._files.required):
            if tfile.file_name == path:
                return tfile
        return None

    @classmethod
    def load(cls, path, adjacent=False):
        """Load TestCases from disk.

        Args:
            path (str): Path can be:
                        1) A directory containing `test_info.json` and data.
                        2) A directory with one or more subdirectories of 1.
                        3) A zip archive containing testcase data or
                           subdirectories containing testcase data.
                        4) A single file to be used as a test case.
            adjacent (bool): Load adjacent files as part of the test case.
                             This is always the case when loading a directory.
                             WARNING: This should be used with caution!

        Returns:
            list: TestCases successfully loaded from path.
        """
        path = Path(path)
        # unpack archive if needed
        if path.name.lower().endswith(".zip"):
            try:
                unpacked = mkdtemp(prefix="unpack_", dir=grz_tmp("storage"))
                with ZipFile(path) as zip_fp:
                    zip_fp.extractall(path=unpacked)
            except (BadZipfile, zlib_error):
                rmtree(unpacked, ignore_errors=True)
                raise TestCaseLoadFailure("Testcase archive is corrupted") from None
            path = Path(unpacked)
        else:
            unpacked = None
        # load testcase data from disk
        try:
            if path.is_file():
                tests = [cls.load_single(path, adjacent=adjacent)]
            elif path.is_dir():
                tests = list()
                assets = None
                for tc_path in TestCase.scan_path(path):
                    tests.append(
                        cls.load_single(
                            tc_path, load_assets=assets is None, copy=unpacked is None
                        )
                    )
                    # only load assets once
                    if not assets and tests[-1].assets:
                        assets = tests[-1].assets
                # reuse AssetManager on all tests
                if assets:
                    for test in tests:
                        if test.assets is None:
                            test.assets = assets
                tests.sort(key=lambda tc: tc.timestamp)
            else:
                raise TestCaseLoadFailure("Invalid TestCase path")
        finally:
            if unpacked is not None:
                rmtree(unpacked, ignore_errors=True)
        return tests

    @classmethod
    def load_single(cls, path, adjacent=False, load_assets=True, copy=True):
        """Load contents of a TestCase from disk. If `path` is a directory it must
        contain a valid 'test_info.json' file.

        Args:
            path (Path): Path to the directory or file to load.
            adjacent (bool): Load adjacent files as part of the TestCase.
                             This is always true when loading a directory.
                             WARNING: This should be used with caution!
            load_assets (bool): Load assets files.
            copy (bool): Files will be copied if True otherwise the they will be moved.

        Returns:
            TestCase: A TestCase.
        """
        path = Path(path)
        if path.is_dir():
            # load using test_info.json
            try:
                with (path / "test_info.json").open("r") as in_fp:
                    info = json.load(in_fp)
            except IOError:
                raise TestCaseLoadFailure("Missing 'test_info.json'") from None
            except ValueError:
                raise TestCaseLoadFailure("Invalid 'test_info.json'") from None
            if not isinstance(info.get("target"), str):
                raise TestCaseLoadFailure("'test_info.json' has invalid 'target' entry")
            entry_point = Path(path / info["target"])
            if not entry_point.is_file():
                raise TestCaseLoadFailure(
                    "Entry point %r not found in %r" % (info["target"], str(path))
                )
            # always load all contents of a directory if a 'test_info.json' is loaded
            adjacent = True
        elif path.is_file():
            entry_point = path
            info = dict()
        else:
            raise TestCaseLoadFailure("Missing or invalid TestCase %r" % (str(path),))
        # create testcase and add data
        test = cls(
            entry_point.relative_to(entry_point.parent).as_posix(),
            None,
            info.get("adapter", None),
            input_fname=info.get("input", None),
            time_limit=info.get("time_limit", None),
            timestamp=info.get("timestamp", 0),
        )
        test.duration = info.get("duration", None)
        test.hang = info.get("hang", False)
        test.add_from_file(
            entry_point, file_name=test.landing_page, required=True, copy=copy
        )
        if info:
            # load assets
            try:
                if load_assets and info.get("assets", None):
                    test.assets = AssetManager.load(
                        info.get("assets"),
                        str(entry_point.parent / info.get("assets_path", "")),
                    )
            except (AssetError, OSError) as exc:
                test.cleanup()
                raise TestCaseLoadFailure(str(exc)) from None
            # load environment variables
            test.env_vars = info.get("env", dict())
            assert isinstance(test.env_vars, dict)
            # sanity check environment variable data
            for name, value in test.env_vars.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    test.cleanup()
                    if test.assets:
                        test.assets.cleanup()
                    raise TestCaseLoadFailure("'env' contains invalid entries")
        # load all adjacent data from directory
        if adjacent:
            asset_path = info.get("assets_path", None)
            for entry in Path(entry_point.parent).rglob("*"):
                if not entry.is_file():
                    continue
                location = entry.relative_to(entry_point.parent).as_posix()
                # ignore asset path
                if asset_path and location.startswith(asset_path):
                    continue
                # ignore files that have been previously loaded
                if location in (test.landing_page, "test_info.json"):
                    continue
                # NOTE: when loading all files except the entry point are
                # marked as `required=False`
                test.add_from_file(
                    entry,
                    file_name=location,
                    required=False,
                    copy=copy,
                )
        return test

    @property
    def optional(self):
        """Get file paths of optional files.

        Args:
            None

        Yields:
            str: File path of each optional file.
        """
        for test in self._files.optional:
            yield test.file_name

    def pop_assets(self):
        """Remove AssetManager from TestCase.

        Args:
            None

        Returns:
            AssetManager: AssetManager if exists otherwise None.
        """
        if self.assets is None:
            assets = None
        else:
            assets = self.assets
            self.assets = None
        return assets

    def purge_optional(self, keep):
        """Remove optional files that are not in keep.

        Args:
            keep (iterable(str)): Files that will not be removed. This can contain
                                  absolute (includes) and relative paths.

        Returns:
            None
        """
        to_remove = list()
        # iterate over optional files
        for idx, opt in enumerate(self._files.optional):
            # check entries in 'keep' for a match
            if not any(x.endswith(opt.file_name) for x in keep):
                to_remove.append(idx)
        # purge
        for idx in reversed(to_remove):
            self._files.optional.pop(idx).data_file.unlink()

    @staticmethod
    def sanitize_path(path):
        """Sanitize given path for use as a URI path.

        Args:
            path (str): Path to sanitize. Must be relative to wwwroot.

        Returns:
            str: Sanitized path.
        """
        assert isinstance(path, str)
        # check for missing filename or path containing drive letter (Windows)
        if split(path)[-1] in ("", ".", "..") or ":" in path:
            raise ValueError("invalid path %r" % (path,))
        # normalize path
        path = normpath(path).replace("\\", "/")
        # check normalized path does not resolve to location outside of '.'
        if path.startswith("../"):
            raise ValueError("invalid path %r" % (path,))
        return path.lstrip("/")

    @staticmethod
    def scan_path(path):
        """Check path and subdirectories for potential test cases.

        Args:
            path (Path): Path to scan.

        Yields:
            str: Path to what appears to be a valid testcase.
        """
        if "test_info.json" in (x.name for x in path.iterdir()):
            yield path
        else:
            for entry in path.iterdir():
                if entry.is_dir() and (entry / "test_info.json").is_file():
                    yield entry
