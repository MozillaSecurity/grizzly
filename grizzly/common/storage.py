# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from collections import namedtuple
from itertools import chain
import json
import os
import shutil
from tempfile import SpooledTemporaryFile

from ..target import sanitizer_opts
from .utils import grz_tmp


__all__ = ("TestCase", "TestFile", "TestCaseLoadFailure", "TestFileExists")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class TestCaseLoadFailure(Exception):
    """Raised when loading a TestCase fails"""


class TestFileExists(Exception):
    """Raised when adding a TestFile to a TestCase that has an existing TestFile with the same name"""


TestFileMap = namedtuple("TestFileMap", "meta optional required")


class TestCase(object):
    __slots__ = (
        "adapter_name", "duration", "env_vars", "input_fname", "landing_page",
        "redirect_page", "_existing_paths", "_files")

    def __init__(self, landing_page, redirect_page, adapter_name, input_fname=None):
        self.adapter_name = adapter_name
        self.duration = None
        self.env_vars = dict()  # environment variables
        self.input_fname = input_fname  # file that was used to create the test case
        self.landing_page = landing_page
        self.redirect_page = redirect_page
        self._existing_paths = list()  # file paths in use
        self._files = TestFileMap(
            meta=list(),  # environment files such as prefs.js, etc...
            optional=list(),
            required=list())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def _add(self, target, test_file):
        """Add a test file to test case and perform sanity checks.

        Args:
            target (list): Specific list of Files to append target test_file to.
            test_file (TestFile): TestFile to append

        Returns:
            None
        """
        assert isinstance(test_file, TestFile), "only accepts TestFiles"
        if test_file.file_name in self._existing_paths:
            raise TestFileExists("%r exists in test" % (test_file.file_name,))
        self._existing_paths.append(test_file.file_name)
        target.append(test_file)

    def add_batch(self, path, include_files, prefix=None):
        """Iterate over files in include_files and attach the files that are
        located in path to testcase.

        Args:
            path (str): Path to the root of the directory that contains files.
            include_files (iterable): Paths of the files to be added to the
                                      test case if they exist in path.
            prefix (str): Path prefix to prepend to file when adding to
                          test case.

        Returns:
            None
        """
        path = os.path.abspath(path)
        for fname in (x for x in include_files if x.startswith(path)):
            test_path = os.path.relpath(fname, path)
            if test_path.startswith(".."):
                continue
            if prefix:
                test_path = "/".join((prefix, test_path))
            self.add_from_file(fname, file_name=test_path)

    def add_meta(self, meta_file):
        """Add a test file to test case as a meta file.

        Args:
            meta_file (TestFile): TestFile to add to TestCase

        Returns:
            None
        """
        self._add(self._files.meta, meta_file)

    def add_environ_var(self, name, value):
        """Add environment variable to test case.

        Args:
            name (str): Environment variable name
            value (str): Environment variable value

        Returns:
            None
        """
        self.env_vars[name] = value

    def add_file(self, test_file, required=True):
        """Add a test file to test case.

        Args:
            meta_file (TestFile): TestFile to add to TestCase
            required (bool): Indicates if test file must be served

        Returns:
            None
        """
        if required:
            self._add(self._files.required, test_file)
        else:
            self._add(self._files.optional, test_file)

    def add_from_data(self, data, file_name, encoding="UTF-8", required=True):
        """Create a TestFile and add it to the test case.

        Args:
            data (bytes): Data to write to file
            file_name (str): Name for the test file
            encoding (str): Encoding to be used
            required (bool): Indicates if test file must be served

        Returns:
            None
        """
        tfile = TestFile.from_data(data, file_name, encoding=encoding)
        try:
            self.add_file(tfile, required=required)
        except TestFileExists:
            tfile.close()
            raise

    def add_from_file(self, input_file, file_name=None, required=True):
        """Create a TestFile from an existing file and add it to the test case.

        Args:
            input_file (str): Path to existing file to use
            file_name (str): Name for the test file
            required (bool): Indicates if test file must be served

        Returns:
            None
        """
        tfile = TestFile.from_file(input_file, file_name=file_name)
        try:
            self.add_file(tfile, required=required)
        except TestFileExists:
            tfile.close()
            raise

    def cleanup(self):
        """Close all the test files.

        Args:
            None

        Returns:
            None
        """
        for file_group in self._files:
            for test_file in file_group:
                test_file.close()

    def contains(self, file_name):
        """Check TestCase contains the TestFile with name matching `file_name`.

        Args:
            file_name (str): File name to search for in TestCase.

        Returns:
            bool: True if file exists in the TestCase otherwise False
        """
        return file_name in self._existing_paths

    @property
    def data_size(self):
        """The total amount of data used by the test case (bytes).

        Args:
            None

        Returns:
            int: Total size of the test case in byte.
        """
        total = 0
        for group in self._files:
            total += sum(x.size for x in group)
        return total

    def dump(self, out_path, include_details=False):
        """Write all the test case data to the filesystem.

        Args:
            out_path (str): Path to directory to output data
            include_details (bool): Output "test_info.json" file

        Returns:
            None
        """
        # save test files to out_path
        for test_file in chain(self._files.required, self._files.optional):
            test_file.dump(out_path)
        # save test case files and meta data including:
        # adapter used, input file, environment info and files
        if include_details:
            assert isinstance(self.env_vars, dict)
            info = {
                "adapter": self.adapter_name,
                "duration": self.duration,
                "env": self.env_vars,
                "input": os.path.basename(self.input_fname) if self.input_fname else None,
                "target": self.landing_page}
            with open(os.path.join(out_path, "test_info.json"), "w") as out_fp:
                json.dump(info, out_fp, indent=2, sort_keys=True)
            # save meta files
            for meta_file in self._files.meta:
                meta_file.dump(out_path)

    def load_environ(self, path, env_data):
        # sanity check environment variable data
        for name, value in env_data.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise TestCaseLoadFailure("'env_data' contains invalid 'env' entries")
        self.env_vars = env_data
        known_suppressions = ("lsan.supp", "tsan.supp", "ubsan.supp")
        for supp in os.listdir(path):
            if supp.lower() in known_suppressions:
                # Update *SAN_OPTIONS environment variable to use provided suppression files.
                opt_key = "%s_OPTIONS" % (supp.split(".")[0].upper(),)
                opts = sanitizer_opts(self.env_vars.get(opt_key, ""))
                opts["suppressions"] = "'%s'" % (os.path.join(path, supp),)
                self.env_vars[opt_key] = ":".join("=".join((k, v)) for k, v in opts.items())

    @classmethod
    def load_path(cls, path, full_scan=False, prefs=True):
        """Load contents of a TestCase from disk. If `path` is a directory it must
        contain a valid test_info.json file.

        Args:
            path (str): Path to the directory or file to load.
            full_scan (bool): Include all files in the directory containing the
                              test case entry point as well as the contents of
                              subdirectories. This is always the case when
                              loading a directory.
                              WARNING: This should be used with caution!
            prefs (bool): Include prefs.js file in the test case.

        Returns:
            TestCase: A TestCase.
        """
        path = os.path.abspath(path)
        if os.path.isdir(path):
            # load a directory using test_info.json
            try:
                with open(os.path.join(path, "test_info.json"), "r") as in_fp:
                    info = json.load(in_fp)
            except IOError:
                raise TestCaseLoadFailure("Missing 'test_info.json'")
            except ValueError:
                raise TestCaseLoadFailure("Invalid 'test_info.json'")
            if "target" not in info:
                raise TestCaseLoadFailure("'test_info.json' missing 'target' entry")
            entry_point = os.path.basename(info["target"])
            if not os.path.isfile(os.path.join(path, entry_point)):
                raise TestCaseLoadFailure("entry_point '%s' not found in '%s'" % (entry_point, path))
            adapter = info.get("adapter", None)
            full_scan = True
        elif os.path.isfile(path):
            adapter = None
            entry_point = os.path.basename(path)
            path = os.path.dirname(path)
            info = None
        else:
            raise TestCaseLoadFailure("Cannot find %r" % (path,))
        test = cls(None, None, adapter)
        if full_scan:
            # load all files from directory as test
            for dpath, _, files in os.walk(path):
                for fname in files:
                    if fname == "test_info.json":
                        continue
                    if dpath == path:
                        if fname == "prefs.js":
                            if prefs:
                                test.add_meta(TestFile.from_file(os.path.join(dpath, fname)))
                            continue
                        if fname == entry_point:
                            test.add_from_file(os.path.join(dpath, fname))
                            # set entry point
                            test.landing_page = fname
                            continue
                        location = None
                    else:
                        # handle nested directories
                        location = "/".join((dpath.split(path, 1)[-1], fname))
                    test.add_from_file(
                        os.path.join(dpath, fname),
                        file_name=location,
                        required=False)
        else:
            # load single file as test
            test.add_from_file(os.path.join(path, entry_point))
            test.landing_page = entry_point
        if test.landing_page is None:  # pragma: no cover
            # this should not be possible
            test.cleanup()
            raise AssertionError("Scanning for test case 'entry point' failed")
        # load environment variables
        if info:
            try:
                test.load_environ(path, info.get("env", {}))
            except TestCaseLoadFailure:
                test.cleanup()
                raise
        return test

    @property
    def optional(self):
        """Get file names of optional TestFiles

        Args:
            None

        Returns:
            generator: file names (str) of optional files
        """
        for test in self._files.optional:
            yield test.file_name

    def purge_optional(self, keep):
        """Remove optional files (by name) that are not in keep.

        Args:
            keep (iterable): Filenames that will not be removed.

        Returns:
            None
        """
        keep = set(keep)
        to_remove = []
        for idx, tfile in enumerate(self._files.optional):
            if tfile.file_name not in keep:
                to_remove.append(idx)
        for idx in reversed(to_remove):
            self._files.optional.pop(idx).close()


class TestFile(object):
    CACHE_LIMIT = 0x80000  # data cache limit per file: 512KB
    XFER_BUF = 0x10000  # transfer buffer size: 64KB

    __slots__ = ("_fp", "file_name")

    def __init__(self, file_name):
        if not file_name:
            raise TypeError("TestFile requires a name")
        self._fp = SpooledTemporaryFile(max_size=self.CACHE_LIMIT, dir=grz_tmp(), prefix="grz_tf_")
        # TODO: Add file_name sanitation since it is used when the file is written to the fs
        # XXX: This is a naive fix for a larger path issue
        if "\\" in file_name:
            file_name = file_name.replace("\\", "/")
        if file_name.startswith("/"):
            file_name = file_name.lstrip("/")
        self.file_name = os.path.normpath(file_name)  # name including path relative to wwwroot

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def clone(self):
        """Make a copy of the TestFile.

        Args:
            None

        Returns:
            TestFile: A copy of the TestFile instance
        """
        cloned = TestFile(self.file_name)
        self._fp.seek(0)
        shutil.copyfileobj(self._fp, cloned._fp, self.XFER_BUF)  # pylint: disable=protected-access
        return cloned

    def close(self):
        """Close the TestFile.

        Args:
            None

        Returns:
            None TestFile instance
        """
        self._fp.close()

    @property
    def data(self):
        """Get the data from the TestFile. Not recommenced for large files.

        Args:
            None

        Returns:
            bytes: Data from the TestFile
        """
        pos = self._fp.tell()
        self._fp.seek(0)
        data = self._fp.read()
        self._fp.seek(pos)
        return data

    def dump(self, path):
        """Write test file data to the filesystem.

        Args:
            path (str): Path to output data

        Returns:
            None
        """
        target_path = os.path.join(path, os.path.dirname(self.file_name))
        if not os.path.isdir(target_path):
            os.makedirs(target_path)
        self._fp.seek(0)
        with open(os.path.join(path, self.file_name), "wb") as dst_fp:
            shutil.copyfileobj(self._fp, dst_fp, self.XFER_BUF)

    @classmethod
    def from_data(cls, data, file_name, encoding="UTF-8"):
        """Create a TestFile and add it to the test case.

        Args:
            data (bytes): Data to write to file
            file_name (str): Name for the test file
            encoding (str): Encoding to be used

        Returns:
            TestFile: new instance
        """
        t_file = cls(file_name)
        if data:
            if isinstance(data, bytes) or not encoding:
                t_file.write(data)
            else:
                t_file.write(data.encode(encoding))
        return t_file

    @classmethod
    def from_file(cls, input_file, file_name=None):
        """Create a TestFile from an existing file.

        Args:
            input_file (str): Path to existing file to use
            file_name (str): Name for the test file

        Returns:
            TestFile: new instance
        """
        if file_name is None:
            file_name = os.path.basename(input_file)
        t_file = cls(file_name)
        with open(input_file, "rb") as src_fp:
            shutil.copyfileobj(src_fp, t_file._fp, cls.XFER_BUF)  # pylint: disable=protected-access
        return t_file

    @property
    def size(self):
        """Size of the file in bytes.

        Args:
            None

        Returns:
            int: Size in bytes.
        """
        pos = self._fp.tell()
        self._fp.seek(0, os.SEEK_END)
        size = self._fp.tell()
        self._fp.seek(pos)
        return size

    def write(self, data):
        """Add data to the TestFile.

        Args:
            data (bytes): Data to add to the TestFile

        Returns:
            None
        """
        self._fp.write(data)
