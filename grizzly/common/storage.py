# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from collections import namedtuple
from itertools import chain
import json
from os import listdir, makedirs, SEEK_END, walk
from os.path import abspath, basename, dirname, isfile, isdir, join as pathjoin, \
    normpath, relpath
from shutil import copyfileobj, rmtree
from tempfile import mkdtemp, SpooledTemporaryFile
from time import time
from zipfile import BadZipfile, ZipFile
from zlib import error as zlib_error

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


class TestCase:
    __slots__ = (
        "adapter_name", "duration", "env_vars", "input_fname", "landing_page",
        "redirect_page", "timestamp", "_existing_paths", "_files")

    def __init__(self, landing_page, redirect_page, adapter_name, input_fname=None, timestamp=None):
        self.adapter_name = adapter_name
        self.duration = None
        self.env_vars = dict()  # environment variables
        self.input_fname = input_fname  # file that was used to create the test case
        self.landing_page = landing_page
        self.redirect_page = redirect_page
        self.timestamp = time() if timestamp is None else timestamp
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
            target (list): Specific list of files to append target test_file to.
            test_file (TestFile): TestFile to append.

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
        located in path to TestCase.

        Args:
            path (str): Path to the root of the directory that contains files.
            include_files (iterable): Paths of the files to be added to the
                                      TestCase if they exist in path.
            prefix (str): Path prefix to prepend to file when adding to
                          the TestCase.

        Returns:
            None
        """
        path = abspath(path)
        for fname in (x for x in include_files if x.startswith(path)):
            test_path = relpath(fname, path)
            if test_path.startswith(".."):
                continue
            if prefix:
                test_path = "/".join((prefix, test_path))
            self.add_from_file(fname, file_name=test_path)

    def add_meta(self, meta_file):
        """Add a TestFile to TestCase as a meta file.

        Args:
            meta_file (TestFile): TestFile to add to TestCase.

        Returns:
            None
        """
        self._add(self._files.meta, meta_file)

    def add_environ_var(self, name, value):
        """Add environment variable to TestCase.

        Args:
            name (str): Environment variable name.
            value (str): Environment variable value.

        Returns:
            None
        """
        self.env_vars[name] = value

    def add_file(self, test_file, required=True):
        """Add a TestFile to TestCase.

        Args:
            meta_file (TestFile): TestFile to add to TestCase.
            required (bool): Indicates if test file must be served.

        Returns:
            None
        """
        if required:
            self._add(self._files.required, test_file)
        else:
            self._add(self._files.optional, test_file)

    def add_from_data(self, data, file_name, encoding="UTF-8", required=True):
        """Create a TestFile and add it to the TestCase.

        Args:
            data (bytes or str): Data to write to file. If data is of type str
                                 encoding must be given.
            file_name (str): Name for the TestFile.
            encoding (str): Encoding to be used.
            required (bool): Indicates whether the TestFile must be served.

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
        """Create a TestFile from an existing file and add it to the TestCase.

        Args:
            input_file (str): Path to existing file to use.
            file_name (str): Name for the TestFile. If file_name is not given
                             the name of the input_file will be used.
            required (bool): Indicates whether the TestFile must be served.

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

    def clone(self):
        """Make a copy of the TestCase.

        Args:
            None

        Returns:
            TestCase: A copy of the TestCase instance
        """
        result = type(self)(self.landing_page, self.redirect_page, self.adapter_name,
                            self.input_fname, self.timestamp)
        result.duration = self.duration
        result.env_vars.update(self.env_vars)
        for entry in self._files.meta:
            result.add_meta(entry.clone())
        for entry in self._files.optional:
            result.add_file(entry.clone(), required=False)
        for entry in self._files.required:
            result.add_file(entry.clone(), required=True)
        return result

    def contains(self, file_name):
        """Check TestCase contains the TestFile with name matching `file_name`.

        Args:
            file_name (str): File name to search for in TestCase.

        Returns:
            bool: True if file exists in the TestCase otherwise False.
        """
        return file_name in self._existing_paths

    @property
    def data_size(self):
        """The total amount of data used (bytes) by the TestFiles in the
        TestCase.

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
            out_path (str): Path to directory to output data.
            include_details (bool): Output "test_info.json" file.

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
                "input": basename(self.input_fname) if self.input_fname else None,
                "target": self.landing_page,
                "timestamp": self.timestamp}
            with open(pathjoin(out_path, "test_info.json"), "w") as out_fp:
                json.dump(info, out_fp, indent=2, sort_keys=True)
            # save meta files
            for meta_file in self._files.meta:
                meta_file.dump(out_path)

    def get_file(self, file_name):
        """Lookup and return the TestFile with the specified file name.

        Args:
            file_name (str): Name of file to retrieve.

        Returns:
            TestFile: TestFile with matching file name otherwise None.
        """
        for tfile in chain(self._files.meta, self._files.optional, self._files.required):
            if tfile.file_name == file_name:
                return tfile
        return None

    @classmethod
    def load(cls, path, load_prefs, adjacent=False):
        """Load TestCases from disk.

        Args:
            path (str): Path can be:
                        1) A directory containing `test_info.json` and data.
                        2) A directory with one or more subdirectories of 1.
                        3) A zip archive containing testcase data or
                           subdirectories containing testcase data.
                        4) A single file to be used as a test case.
            load_prefs (bool): Load prefs.js file if available.
            adjacent (str): Load adjacent files as part of the test case.
                            This is always the case when loading a directory.
                            WARNING: This should be used with caution!

        Returns:
            list: TestCases successfully loaded from path.
        """
        # unpack archive if needed
        if path.lower().endswith(".zip"):
            unpacked = mkdtemp(prefix="unpack_", dir=grz_tmp("storage"))
            try:
                with ZipFile(path) as zip_fp:
                    zip_fp.extractall(path=unpacked)
            except (BadZipfile, zlib_error):
                rmtree(unpacked, ignore_errors=True)
                raise TestCaseLoadFailure("Testcase archive is corrupted") from None
            path = unpacked
        else:
            unpacked = None
        # load testcase data from disk
        try:
            if isfile(path):
                tests = [cls.load_single(path, load_prefs, adjacent=adjacent)]
            elif isdir(path):
                tests = list()
                for tc_path in TestCase.scan_path(path):
                    tests.append(cls.load_single(tc_path, load_prefs))
                tests.sort(key=lambda tc: tc.timestamp)
            else:
                raise TestCaseLoadFailure("Invalid TestCase path")
        finally:
            if unpacked is not None:
                rmtree(unpacked, ignore_errors=True)
        return tests

    def load_environ(self, path, env_data):
        # sanity check environment variable data
        for name, value in env_data.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise TestCaseLoadFailure("'env_data' contains invalid 'env' entries")
        self.env_vars = env_data
        known_suppressions = ("lsan.supp", "tsan.supp", "ubsan.supp")
        for supp in listdir(path):
            if supp.lower() in known_suppressions:
                # Update *SAN_OPTIONS environment variable to use provided suppression files.
                opt_key = "%s_OPTIONS" % (supp.split(".")[0].upper(),)
                opts = sanitizer_opts(self.env_vars.get(opt_key, ""))
                opts["suppressions"] = "'%s'" % (pathjoin(path, supp),)
                self.env_vars[opt_key] = ":".join("=".join((k, v)) for k, v in opts.items())

    @classmethod
    def load_single(cls, path, load_prefs, adjacent=False):
        """Load contents of a TestCase from disk. If `path` is a directory it must
        contain a valid 'test_info.json' file.

        Args:
            path (str): Path to the directory or file to load.
            load_prefs (bool): Load prefs.js file if available.
            adjacent (bool): Load adjacent files as part of the TestCase.
                             This is always true when loading a directory.
                             WARNING: This should be used with caution!

        Returns:
            TestCase: A TestCase.
        """
        path = abspath(path)
        if isdir(path):
            # load using test_info.json
            try:
                with open(pathjoin(path, "test_info.json"), "r") as in_fp:
                    info = json.load(in_fp)
            except IOError:
                raise TestCaseLoadFailure("Missing 'test_info.json'") from None
            except ValueError:
                raise TestCaseLoadFailure("Invalid 'test_info.json'") from None
            if not isinstance(info.get("target"), str):
                raise TestCaseLoadFailure("'test_info.json' has invalid 'target' entry")
            entry_point = basename(info["target"])
            if not isfile(pathjoin(path, entry_point)):
                raise TestCaseLoadFailure("Entry point %r not found in '%s'" % (entry_point, path))
            # always load all contents of a directory if a 'test_info.json' is loaded
            adjacent = True
        elif isfile(path):
            entry_point = basename(path)
            info = dict()
            path = dirname(path)
        else:
            raise TestCaseLoadFailure("Missing or invalid TestCase %r" % (path,))
        # create testcase and add data
        test = cls(None, None, info.get("adapter", None), timestamp=info.get("timestamp", 0))
        if load_prefs and isfile(pathjoin(path, "prefs.js")):
            test.add_meta(TestFile.from_file(pathjoin(path, "prefs.js")))
        test.add_from_file(pathjoin(path, entry_point))
        test.landing_page = entry_point
        # load environment variables
        if info:
            try:
                test.load_environ(path, info.get("env", {}))
            except TestCaseLoadFailure:
                test.cleanup()
                raise
        # load all adjacent data from directory
        if adjacent:
            for dpath, _, files in walk(path):
                for fname in files:
                    # ignore files that have been previously loaded
                    if fname in (entry_point, "prefs.js", "test_info.json"):
                        continue
                    location = "/".join((dpath.split(path, 1)[-1], fname))
                    test.add_from_file(
                        pathjoin(dpath, fname),
                        file_name=location,
                        required=False)
        return test

    @property
    def optional(self):
        """Get file names of optional TestFiles.

        Args:
            None

        Yields:
            str: File names of optional files.
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
        opt_files = tuple(x.file_name for x in self._files.optional)
        if not opt_files:
            # nothing to purge
            return
        # filter required files from opt_files files to keep
        keep_opt = list()
        for fname in set(keep):
            if fname not in (x.file_name for x in self._files.required):
                keep_opt.append(fname)
        # sanity check keep (cannot remove file that does not exist)
        assert all(fname in opt_files for fname in keep_opt)
        # purge
        to_remove = list()
        for idx, fname in enumerate(opt_files):
            if fname not in keep_opt:
                to_remove.append(idx)
        for idx in reversed(to_remove):
            self._files.optional.pop(idx).close()

    @staticmethod
    def scan_path(path):
        """Check path and subdirectories for potential test cases.

        Args:
            path (str): Path to scan.

        Yields:
            str: Path to what appears to be a valid testcase.
        """
        contents = listdir(path)
        if "test_info.json" in contents:
            yield path
        else:
            for entry in contents:
                tc_path = pathjoin(path, entry)
                if isfile(pathjoin(tc_path, "test_info.json")):
                    yield tc_path


class TestFile:
    CACHE_LIMIT = 0x80000  # data cache limit per file: 512KB
    XFER_BUF = 0x10000  # transfer buffer size: 64KB

    __slots__ = ("_file_name", "_fp")

    def __init__(self, file_name):
        # This is a naive fix for a larger path issue. This is a simple sanity
        # check and does not check if invalid characters are used. If an invalid
        # file name is used an exception will be raised when trying to write
        # that file to the file system.
        if "\\" in file_name:
            file_name = file_name.replace("\\", "/")
        if file_name.startswith("/"):
            file_name = file_name.lstrip("/")
        if file_name.endswith("."):
            file_name = file_name.rstrip(".")
        if not file_name \
                or ("/" in file_name and not file_name.rsplit("/", 1)[-1]) \
                or file_name.startswith("../"):
            raise TypeError("file_name is invalid %r" % (file_name,))
        # name including path relative to wwwroot
        self._file_name = normpath(file_name)
        self._fp = SpooledTemporaryFile(
            dir=grz_tmp("storage"),
            max_size=self.CACHE_LIMIT,
            prefix="testfile_")

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
        cloned = type(self)(self._file_name)
        self._fp.seek(0)
        copyfileobj(self._fp, cloned._fp, self.XFER_BUF)  # pylint: disable=protected-access
        return cloned

    def close(self):
        """Close the TestFile.

        Args:
            None

        Returns:
            None
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
        """Write TestFile data to the filesystem.

        Args:
            path (str): Path to output data.

        Returns:
            None
        """
        target_path = pathjoin(path, dirname(self._file_name))
        if not isdir(target_path):
            makedirs(target_path)
        self._fp.seek(0)
        with open(pathjoin(path, self._file_name), "wb") as dst_fp:
            copyfileobj(self._fp, dst_fp, self.XFER_BUF)

    @property
    def file_name(self):
        return self._file_name

    @classmethod
    def from_data(cls, data, file_name, encoding="UTF-8"):
        """Create a TestFile and add it to the test case.

        Args:
            data (bytes or str): Data to write to file. If data is of type str
                                 encoding must be given.
            file_name (str): Name for the TestFile.
            encoding (str): Encoding to be used.

        Returns:
            TestFile: A TestFile.
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
            input_file (str): Path to existing file to use.
            file_name (str): Name for the TestFile. If file_name is not given
                             the name of the input_file will be used.

        Returns:
            TestFile: A TestFile.
        """
        if file_name is None:
            file_name = basename(input_file)
        t_file = cls(file_name)
        with open(input_file, "rb") as src_fp:
            copyfileobj(src_fp, t_file._fp, cls.XFER_BUF)  # pylint: disable=protected-access
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
        self._fp.seek(0, SEEK_END)
        size = self._fp.tell()
        self._fp.seek(pos)
        return size

    def write(self, data):
        """Add data to the TestFile.

        Args:
            data (bytes): Data to add to the TestFile.

        Returns:
            None
        """
        self._fp.write(data)
