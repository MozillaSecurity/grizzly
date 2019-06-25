# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from collections import namedtuple
import json
import os
import shutil
import tempfile

__all__ = ("InputFile", "TestCase", "TestFile", "TestFileExists")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class TestFileExists(RuntimeError):
    """Raised when adding a TestFile to a TestCase that has an existing TestFile with the same name"""


class InputFile(object):
    CACHE_LIMIT = 0x100000  # 1MB

    def __init__(self, file_name):
        self.extension = None
        self.file_name = file_name
        self._fp = None
        if not os.path.isfile(file_name):
            raise IOError("File %r does not exist" % (self.file_name,))
        # TODO: add kwarg to set self.extension?
        if "." in self.file_name:
            self.extension = os.path.splitext(self.file_name)[-1].lstrip(".")

    def _cache_data(self):
        """Cache file data.

        Args:
            None

        Returns:
            None
        """
        self._fp = tempfile.SpooledTemporaryFile(max_size=self.CACHE_LIMIT)
        with open(self.file_name, "rb") as src_fp:
            shutil.copyfileobj(src_fp, self._fp, 0x10000)  # 64KB

    def close(self):
        """Close file handles.

        Args:
            None

        Returns:
            None
        """
        if self._fp is not None:
            self._fp.close()
        self._fp = None

    def get_data(self):
        """Read file data.

        Args:
            None

        Returns:
            bytes: Data from input file
        """
        if self._fp is None:
            self._cache_data()
        self._fp.seek(0)
        # TODO: add size limit
        return self._fp.read()

    def get_fp(self):
        """Get input file File object.

        Args:
            None

        Returns:
            file: input file object
        """
        if self._fp is None:
            self._cache_data()
        self._fp.seek(0)
        return self._fp


TestFileMap = namedtuple("TestFileMap", "meta optional required")

class TestCase(object):
    def __init__(self, landing_page, redirect_page, adapter_name, input_fname=None):
        self.adapter_name = adapter_name
        self.input_fname = input_fname  # file that was used to create the test case
        self.landing_page = landing_page
        self.redirect_page = redirect_page
        self._env_vars = dict()  # environment variables
        self._existing_paths = list()  # file paths in use
        self._files = TestFileMap(
            meta=list(),  # environment files such as prefs.js, etc...
            optional=list(),
            required=list())

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
        self._env_vars[name] = value

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
        tfile = TestFile.from_data(data=data, file_name=file_name, encoding=encoding)
        try:
            self.add_file(tfile, required=required)
        except TestFileExists:
            tfile.close()
            raise

    def add_from_file(self, input_file, file_name, required=True):
        """Create a TestFile from an existing file and add it to the test case.

        Args:
            input_file (str): Path to existing file to use
            file_name (str): Name for the test file
            required (bool): Indicates if test file must be served

        Returns:
            None
        """
        tfile = TestFile.from_file(input_file=input_file, file_name=file_name)
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

    def dump(self, out_path, include_details=False):
        """Write all the test case data to the filesystem.

        Args:
            out_path (str): Path to directory to output data
            include_details (bool): Output "test_info.json" file

        Returns:
            None
        """
        # save test files to out_path
        for test_file in self._files.required + self._files.optional:
            test_file.dump(out_path)
        # save test case files and meta data including:
        # adapter used, input file, environment info and files
        if include_details:
            assert isinstance(self._env_vars, dict)
            info = {
                "adapter": self.adapter_name,
                "env": self._env_vars,
                "input": os.path.basename(self.input_fname) if self.input_fname else None,
                "target": self.landing_page}
            with open(os.path.join(out_path, "test_info.json"), "w") as out_fp:
                json.dump(info, out_fp, indent=2, sort_keys=True)
            # save meta files
            for meta_file in self._files.meta:
                meta_file.dump(out_path)

    @property
    def env_vars(self):
        """Get TestCase environment variables

        Args:
            None

        Returns:
            generator: environment variables (str)
        """
        for name, value in self._env_vars.items():
            if value is not None:
                yield "=".join((name, value))

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

    def remove_files_not_served(self, files_served):
        """Remove optional files (by name) that were not served.

        Args:
            files_served (iterable): Filenames that were reported as served by sapphire.

        Returns:
            None
        """
        files_served = set(files_served)
        to_remove = []

        for idx, file in enumerate(self._files.optional):
            if file.file_name not in files_served:
                to_remove.append(idx)

        to_remove.reverse()
        for idx in to_remove:
            self._files.optional.pop(idx).close()


class TestFile(object):
    CACHE_LIMIT = 0x40000  # data cache limit per file: 256KB
    XFER_BUF = 0x10000  # transfer buffer size: 64KB

    __slots__ = ("_fp", "file_name")

    def __init__(self, file_name):
        self._fp = tempfile.SpooledTemporaryFile(max_size=self.CACHE_LIMIT, prefix="grz_tf_")
        # XXX: This is a naive fix for a larger path issue
        if "\\" in file_name:
            file_name = file_name.replace("\\", "/")
        if file_name.startswith("/"):
            file_name = file_name.lstrip("/")
        self.file_name = os.path.normpath(file_name)  # name including path relative to wwwroot

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
        self._fp.flush()
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
        t_file = cls(file_name=file_name)
        if data:
            if isinstance(data, bytes) or not encoding:
                t_file.write(data)
            else:
                t_file.write(data.encode(encoding))
        return t_file

    @classmethod
    def from_file(cls, input_file, file_name):
        """Create a TestFile from an existing file.

        Args:
            input_file (str): Path to existing file to use
            file_name (str): Name for the test file

        Returns:
            TestFile: new instance
        """
        t_file = cls(file_name=file_name)
        with open(input_file, "rb") as src_fp:
            shutil.copyfileobj(src_fp, t_file._fp, cls.XFER_BUF)  # pylint: disable=protected-access
        return t_file

    def write(self, data):
        """Add data to the TestFile.

        Args:
            data (bytes): Data to add to the TestFile

        Returns:
            None
        """
        self._fp.write(data)
