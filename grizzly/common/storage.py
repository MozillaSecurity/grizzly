# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import json
from dataclasses import dataclass, field
from itertools import chain, product
from logging import getLogger
from os.path import normpath, split
from pathlib import Path
from shutil import copyfile, copytree, move, rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from time import time
from typing import Any, Generator, Iterator, cast

from .utils import grz_tmp, package_version

__all__ = ("TestCase", "TestCaseLoadFailure", "TestFileExists")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


LOG = getLogger(__name__)
GRZ_VERSION = package_version("grizzly-framework")
TEST_INFO = "test_info.json"


class TestCaseLoadFailure(Exception):
    """Raised when loading a TestCase fails"""


class TestFileExists(Exception):
    """Raised when adding a TestFile to a TestCase that has an existing
    TestFile with the same name"""


@dataclass(eq=False)
class TestFileMap:
    optional: dict[str, Path] = field(default_factory=dict)
    required: dict[str, Path] = field(default_factory=dict)


class TestCase:
    __slots__ = (
        "adapter_name",
        "assets",
        "assets_path",
        "duration",
        "entry_point",
        "env_vars",
        "hang",
        "https",
        "input_fname",
        "timestamp",
        "version",
        "_files",
        "_in_place",
        "_root",
    )

    def __init__(
        self,
        entry_point: str,
        adapter_name: str,
        data_path: Path | None = None,
        input_fname: str | None = None,
        timestamp: float | None = None,
    ) -> None:
        assert entry_point
        self.adapter_name = adapter_name
        self.assets: dict[str, str] = {}
        self.assets_path: Path | None = None
        self.duration: float | None = None
        self.env_vars: dict[str, str] = {}
        self.hang = False
        self.https = False
        self.input_fname = input_fname  # file that was used to create the test case
        self.entry_point = self.sanitize_path(entry_point)
        self.timestamp = time() if timestamp is None else timestamp
        self.version = GRZ_VERSION
        self._files = TestFileMap()
        if data_path is not None:
            self._root = data_path
            self._in_place = True
        else:
            self._root = Path(mkdtemp(prefix="testcase_", dir=grz_tmp("storage")))
            self._in_place = False

    def __contains__(self, item: str) -> bool:
        """Scan TestCase contents for a URL.

        Args:
            item: URL.

        Returns:
            URL found in contents.
        """
        return item in self._files.required or item in self._files.optional

    def __getitem__(self, key: str) -> Path:
        """Lookup file path by URL.

        Args:
            key: URL.

        Returns:
            Test file.
        """
        if key in self._files.required:
            return self._files.required[key]
        return self._files.optional[key]

    def __enter__(self) -> TestCase:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def __iter__(self) -> Iterator[str]:
        """TestCase contents.

        Args:
            None

        Yields:
            URLs of contents.
        """
        yield from self._files.required
        yield from self._files.optional

    def __len__(self) -> int:
        """Number files in TestCase.

        Args:
            None

        Returns:
            Number files in TestCase.
        """
        return len(self._files.optional) + len(self._files.required)

    def add_from_bytes(
        self, data: bytes, file_name: str, required: bool = False
    ) -> None:
        """Create a file and add it to the TestCase.

        Args:
            data: Data to write to file.
            file_name: Used as file path on disk and URI. Relative to wwwroot.
            required: Indicates whether the file must be served.

        Returns:
            None
        """
        with NamedTemporaryFile(
            delete=False, dir=grz_tmp("storage"), mode="w+b"
        ) as in_fp:
            in_fp.write(data)
            data_file = Path(in_fp.name)

        try:
            self.add_from_file(
                data_file, file_name=file_name, required=required, copy=False
            )
        finally:
            # the temporary file should have been moved to the data path of the TestCase
            # unless an exception occurred so remove it if needed
            data_file.unlink(missing_ok=True)

    def add_from_file(
        self,
        src_file: str | Path,
        file_name: str | None = None,
        required: bool = False,
        copy: bool = False,
    ) -> None:
        """Add a file to the TestCase. Copy or move an existing file if needed.

        Args:
            src_file: Path to existing file to use.
            file_name: Used as file path on disk and URI. Relative to wwwroot.
                       If file_name is not given the name of the src_file
                       will be used.
            required: Indicates whether the file must be served. Typically this
                      is only used for the entry point.
            copy: Copy existing file data. Existing data is moved by default.

        Returns:
            None
        """
        src_file = Path(src_file)
        if file_name is None:
            url_path = self.sanitize_path(src_file.name)
        else:
            url_path = self.sanitize_path(file_name)
        if url_path in self:
            raise TestFileExists(f"{url_path!r} exists in test")

        dst_file = self._root / url_path
        # don't move/copy data is already in place
        if src_file.resolve() != dst_file.resolve():
            assert not self._in_place
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            if copy:
                copyfile(src_file, dst_file)
            else:
                # Python 3.9+: move() accepts a path-like object for both src and dst
                move(str(src_file.resolve()), str(dst_file.resolve()))

        # entry_point is always 'required'
        if required or url_path == self.entry_point:
            self._files.required[url_path] = dst_file
        else:
            self._files.optional[url_path] = dst_file

    def cleanup(self) -> None:
        """Remove all the test files.

        Args:
            None

        Returns:
            None
        """
        if not self._in_place:
            rmtree(self._root, ignore_errors=True)

    def clear_optional(self) -> None:
        """Clear optional files. This does not remove data from the file system.

        Args:
            None

        Returns:
            None
        """
        self._files.optional.clear()

    def clone(self) -> TestCase:
        """Make a copy of the TestCase.

        Args:
            None

        Returns:
            A copy of the TestCase instance.
        """
        result = type(self)(
            self.entry_point,
            self.adapter_name,
            input_fname=self.input_fname,
            timestamp=self.timestamp,
        )
        result.assets = dict(self.assets)
        if result.assets:
            assert self.assets_path
            try:
                # copy asset data from test case
                result.assets_path = result.root / self.assets_path.relative_to(
                    self.root
                )
                copytree(self.assets_path, result.assets_path)
            except ValueError:
                # asset data is not part of the test case
                result.assets_path = self.assets_path
        result.duration = self.duration
        result.env_vars = dict(self.env_vars)
        result.hang = self.hang
        result.https = self.https
        # copy test data files
        for (file_name, data_file), required in chain(
            product(self._files.required.items(), [True]),
            product(self._files.optional.items(), [False]),
        ):
            result.add_from_file(
                data_file, file_name=file_name, required=required, copy=True
            )
        return result

    @property
    def data_size(self) -> int:
        """Total amount of data used (in bytes) by the files in the TestCase.

        Args:
            None

        Returns:
            Total size of the TestCase in bytes.
        """
        total = 0
        for data_file in chain(
            self._files.required.values(),
            self._files.optional.values(),
        ):
            total += data_file.stat().st_size
        return total

    def dump(self, dst_path: Path, include_details: bool = False) -> None:
        """Write all the test case data to the filesystem.

        Args:
            dst_path: Path to directory to output data.
            include_details: Output test info file.

        Returns:
            None
        """
        # save test files to dst_path
        for src_url, src_file in chain(
            self._files.required.items(),
            self._files.optional.items(),
        ):
            dst_file = dst_path / src_url
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            copyfile(src_file, dst_file)
        # save test case files and meta data including:
        # adapter used, input file, environment info and files
        if include_details:
            info = {
                "https": self.https,
                "target": self.entry_point,
            }
            if self.adapter_name:
                info["adapter"] = self.adapter_name
            if self.duration:
                info["duration"] = self.duration
            if self.env_vars:
                info["env"] = self.env_vars
            if self.hang:
                info["hang"] = self.hang
            if self.input_fname:
                info["input"] = Path(self.input_fname).name
            if self.timestamp:
                info["timestamp"] = self.timestamp
            if self.version:
                info["version"] = self.version
            # save target assets and update meta data
            if self.assets:
                assert isinstance(self.assets_path, Path)
                info["assets"] = self.assets
                info["assets_path"] = "_assets_"
                copytree(self.assets_path, dst_path / cast(str, info["assets_path"]))
            with (dst_path / TEST_INFO).open("w") as out_fp:
                json.dump(info, out_fp, indent=2, sort_keys=True)

    @staticmethod
    def _find_entry_point(path: Path) -> Path:
        """Locate potential entry point.

        Args:
            path: Directory to scan.

        Returns:
            Entry point.
        """
        entry_point = None
        for entry in path.iterdir():
            if entry.suffix.lower() in (".htm", ".html"):
                if entry_point is not None:
                    raise TestCaseLoadFailure("Ambiguous entry point")
                entry_point = entry
        if entry_point is None:
            raise TestCaseLoadFailure("Could not determine entry point")
        return entry_point

    @classmethod
    def load(
        cls, path: Path, entry_point: Path | None = None, catalog: bool = False
    ) -> TestCase:
        """Load a TestCase.

        Args:
            path: Path can be:
                - A single file to be used as a test case.
                - A directory containing the test case data.
            entry_point: File to use as entry point.
            catalog: Scan contents of TestCase.root and track files.
                Untracked files will be missed when using clone() or dump().
                Only the entry point will be marked as 'required'.

        Returns:
            A TestCase.
        """
        assert isinstance(path, Path)
        # load test case info
        entry_point, info = cls.load_meta(path, entry_point=entry_point)
        # create test case
        test = cls(
            entry_point.relative_to(entry_point.parent).as_posix(),
            info.get("adapter", None),
            data_path=entry_point.parent,
            input_fname=info.get("input", None),
            timestamp=info.get("timestamp", 0),
        )
        test.assets = info.get("assets", {})
        test.duration = info.get("duration", None)
        test.env_vars = info.get("env", {})
        test.hang = info.get("hang", False)
        test.https = info.get("https", False)
        test.version = info.get("version", None)
        # sanity check assets data
        assert isinstance(test.assets, dict)
        for name, value in test.assets.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise TestCaseLoadFailure("'assets' contains invalid entry")
        if test.assets:
            assets_path = info.get("assets_path", None)
            if not assets_path or not (test.root / assets_path).is_dir():
                LOG.warning("Could not find assets in test case")
                test.assets = {}
            else:
                test.assets_path = test.root / assets_path
        # sanity check environment variable data
        assert isinstance(test.env_vars, dict)
        for name, value in test.env_vars.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise TestCaseLoadFailure("'env' contains invalid entry")
        # add contents of directory to test case 'contents' (excluding assets)
        # data is not copied/moved because it is already in place
        if catalog and path.is_dir():
            # NOTE: only entry point will be marked as 'required'
            for entry in test.root.rglob("*"):
                if (
                    not entry.is_dir()
                    and test.assets_path not in entry.parents
                    and entry.name != TEST_INFO
                ):
                    test.add_from_file(
                        entry, file_name=entry.relative_to(test.root).as_posix()
                    )
        else:
            # add entry point
            test.add_from_file(entry_point, required=True)
        return test

    @classmethod
    def load_meta(
        cls, path: Path, entry_point: Path | None = None
    ) -> tuple[Path, dict[str, Any]]:
        """Process and sanitize TestCase meta data.

        Args:
            path: Directory containing test info file.
            entry_point: See TestCase.load().

        Returns:
            Test case entry point and loaded test info.
        """
        # load test case info if available
        if path.is_dir():
            try:
                info = cls.read_info(path)
            except TestCaseLoadFailure as exc:
                LOG.info(exc)
                info = {}
            if entry_point is not None:
                info["target"] = entry_point.name
            elif info:
                entry_point = path / info["target"]
                assert entry_point
            else:
                # attempt to determine entry point
                entry_point = cls._find_entry_point(path)
            if path not in entry_point.parents:
                raise TestCaseLoadFailure("Entry point must be in root of given path")
        else:
            # single file test case
            entry_point = path
            info = {}

        if not entry_point.exists():
            raise TestCaseLoadFailure(f"Missing or invalid TestCase '{path}'")

        return (entry_point, info)

    @property
    def optional(self) -> Generator[str, None, None]:
        """Get file paths of optional files.

        Args:
            None

        Yields:
            File path of each optional file.
        """
        yield from self._files.optional

    @staticmethod
    def read_info(path: Path) -> dict[str, Any]:
        """Attempt to load test info.

        Args:
            path: Directory containing test info file.

        Returns:
            Test info.
        """
        try:
            with (path / TEST_INFO).open("r") as in_fp:
                info = json.load(in_fp)
        except FileNotFoundError:
            info = None
        except ValueError:
            raise TestCaseLoadFailure(f"Invalid '{TEST_INFO}'") from None
        if info is not None and not isinstance(info.get("target"), str):
            raise TestCaseLoadFailure(f"Invalid 'target' entry in '{TEST_INFO}'")
        return info or {}

    @property
    def required(self) -> Generator[str, None, None]:
        """Get file paths of required files.

        Args:
            None

        Yields:
            File path of each file.
        """
        yield from self._files.required

    @property
    def root(self) -> Path:
        """Location test data is stored on disk. This is intended to be used as wwwroot.

        Args:
            None

        Returns:
            Directory containing test case files.
        """
        return self._root

    @staticmethod
    def sanitize_path(path: str) -> str:
        """Sanitize given path for use as a URI path.

        Args:
            path: Path to sanitize. Must be relative to wwwroot.

        Returns:
            Sanitized path.
        """
        assert isinstance(path, str)
        # check for missing filename or path containing drive letter (Windows)
        if split(path)[-1] in ("", ".", "..") or ":" in path:
            raise ValueError(f"invalid path {path!r}")
        # normalize path
        path = normpath(path).replace("\\", "/")
        # check normalized path does not resolve to location outside of '.'
        if path.startswith("../"):
            raise ValueError(f"invalid path {path!r}")
        return path.lstrip("/")
