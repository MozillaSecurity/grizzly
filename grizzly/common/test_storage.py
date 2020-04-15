# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

import json
import re
import os

import pytest

from .storage import InputFile, TestCase, TestFile, TestCaseLoadFailure, TestFileExists


def test_testcase_01(tmp_path):
    """test empty TestCase"""
    l_page = "land.html"
    r_page = "redirect.html"
    adpt_name = "test-adapter"
    with TestCase(l_page, r_page, adpt_name) as tcase:
        assert tcase.landing_page == l_page
        assert tcase.redirect_page == r_page
        assert tcase.adapter_name == adpt_name
        assert tcase.duration is None
        assert tcase.data_size == 0
        assert tcase.input_fname is None
        assert not tcase.env_vars
        assert not tcase._files.meta
        assert not tcase._files.optional
        assert not tcase._files.required
        assert not any(tcase.optional)
        tcase.dump(str(tmp_path))
        assert not any(tmp_path.glob("*"))
        tcase.dump(str(tmp_path), include_details=True)
        assert (tmp_path / "test_info.json").is_file()

def test_testcase_02(tmp_path):
    """test TestCase with TestFiles"""
    tcase = TestCase("land_page.html", "redirect.html", "test-adapter", input_fname="testinput.bin")
    try:
        in_file = tmp_path / "testfile1.bin"
        in_file.write_bytes(b"test_req")
        tcase.add_from_file(str(in_file), "testfile1.bin")
        assert tcase.data_size == 8
        with pytest.raises(TestFileExists, match="'testfile1.bin' exists in test"):
            tcase.add_from_file(str(in_file), "testfile1.bin")
        with pytest.raises(TestFileExists, match="'testfile1.bin' exists in test"):
            tcase.add_from_data("test", "testfile1.bin")
        tcase.add_from_data("test_nreq", "nested/testfile2.bin", required=False)
        tcase.add_from_data("test_blah", "/testfile3.bin")
        tcase.add_from_data("test_windows", "\\\\dir\\file.bin")
        opt_files = list(tcase.optional)
        assert len(opt_files) == 1
        assert os.path.join("nested", "testfile2.bin") in opt_files
        tcase.dump(str(tmp_path), include_details=True)
        assert (tmp_path / "nested").is_dir()
        with (tmp_path / "test_info.json").open() as info:
            test_info = json.load(info)
        assert test_info["adapter"] == "test-adapter"
        assert test_info["input"] == "testinput.bin"
        assert test_info["target"] == "land_page.html"
        assert isinstance(test_info["env"], dict)
        with (tmp_path / "testfile1.bin").open() as test_fp:
            assert test_fp.read() == "test_req"
        with (tmp_path / "nested" / "testfile2.bin").open() as test_fp:
            assert test_fp.read() == "test_nreq"
        with (tmp_path / "testfile3.bin").open() as test_fp:
            assert test_fp.read() == "test_blah"
        with (tmp_path / "dir" / "file.bin").open() as test_fp:
            assert test_fp.read() == "test_windows"
    finally:
        tcase.cleanup()

def test_testcase_03(tmp_path):
    """test TestCase.add_meta()"""
    with TestCase("land_page.html", "redirect.html", "test-adapter") as tcase:
        dmp_path = tmp_path / "dmp_test"
        dmp_path.mkdir()
        meta_file = dmp_path / "metafile.bin"
        meta_data = b"foobar"
        tcase.add_meta(TestFile.from_data(meta_data, meta_file.name))
        tcase.dump(str(dmp_path), include_details=True)
        assert tcase.data_size == 6
        assert meta_file.is_file()
        with meta_file.open("rb") as test_fp:
            assert test_fp.read() == meta_data

def test_testcase_04(tmp_path):
    """test TestCase.add_environ_var() and TestCase.env_vars"""
    with TestCase("land_page.html", "redirect.html", "test-adapter") as tcase:
        tcase.add_environ_var("TEST_ENV_VAR", "1")
        assert len(list(tcase.env_vars)) == 1
        tcase.add_environ_var("TEST_NONE", None)
        assert len(tcase.env_vars) == 2
        dmp_path = tmp_path / "dmp_test"
        dmp_path.mkdir()
        tcase.dump(str(dmp_path), include_details=True)
        with (dmp_path / "test_info.json").open("r") as test_fp:
            data = json.load(test_fp)["env"]
        assert data["TEST_ENV_VAR"] == "1"
        assert data["TEST_NONE"] is None

def test_testcase_05(tmp_path):
    """test TestCase.purge_optional()"""
    with TestCase("land_page.html", "redirect.html", "test-adapter") as tcase:
        tcase.add_from_data("foo", "testfile1.bin")
        tcase.add_from_data("foo", "testfile2.bin", required=False)
        tcase.add_from_data("foo", "testfile3.bin", required=False)
        tcase.add_from_data("foo", "not_served.bin", required=False)
        assert len(tuple(tcase.optional)) == 3
        tcase.purge_optional(tcase.optional)
        assert len(tuple(tcase.optional)) == 3
        served = ["testfile2.bin", "testfile3.bin"]
        tcase.purge_optional(served)
        assert len(tuple(tcase.optional)) == 2
        tcase.dump(str(tmp_path))
        assert "testfile1.bin" in os.listdir(str(tmp_path))
        assert "not_served.bin" not in os.listdir(str(tmp_path))

def test_testcase_06():
    """test TestCase.data_size"""
    with TestCase("land_page.html", "redirect.html", "test-adapter") as tcase:
        assert tcase.data_size == 0
        tcase.add_from_data("1", "testfile1.bin", required=True)
        assert tcase.data_size == 1
        tcase.add_from_data("12", "testfile2.bin", required=False)
        assert tcase.data_size == 3
        tcase.add_meta(TestFile.from_data("123", "meta.bin"))
        assert tcase.data_size == 6

def test_testcase_07(tmp_path):
    """test TestCase.load_path() using a directory"""
    # missing test_info.json
    with pytest.raises(TestCaseLoadFailure, match="Missing 'test_info.json'"):
        TestCase.load_path(str(tmp_path))
    # invalid test_info.json
    (tmp_path / "test_info.json").write_bytes(b"X")
    with pytest.raises(TestCaseLoadFailure, match="Invalid 'test_info.json'"):
        TestCase.load_path(str(tmp_path))
    # test_info.json missing 'target' entry
    (tmp_path / "test_info.json").write_bytes(b"{}")
    with pytest.raises(TestCaseLoadFailure, match="'test_info.json' missing 'target' entry"):
        TestCase.load_path(str(tmp_path))
    # build a valid test case
    src_dir = (tmp_path / "src")
    src_dir.mkdir()
    (src_dir / "prefs.js").touch()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    (src_dir / "optional.bin").touch()
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_environ_var("TEST_ENV_VAR", "100")
        src.add_from_file(str(entry_point), "target.bin")
        src.dump(str(src_dir), include_details=True)
    # load test case from test_info.json
    with TestCase.load_path(str(src_dir)) as dst:
        assert dst.landing_page == "target.bin"
        assert "prefs.js" in (x.file_name for x in dst._files.meta)
        assert "target.bin" in (x.file_name for x in dst._files.required)
        assert "optional.bin" in (x.file_name for x in dst._files.optional)
        assert dst.env_vars["TEST_ENV_VAR"] == "100"
    # bad test_info.json 'target' entry
    entry_point.unlink()
    with pytest.raises(TestCaseLoadFailure, match="entry_point 'target.bin' not found in"):
        TestCase.load_path(str(src_dir))
    # bad test_info.json 'env' entry
    entry_point.touch()
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_environ_var("TEST_ENV_VAR", 100)
        src.dump(str(src_dir), include_details=True)
    with pytest.raises(TestCaseLoadFailure, match="'env_data' contains invalid 'env' entries"):
        TestCase.load_path(str(src_dir))

def test_testcase_08(tmp_path):
    """test TestCase.load_path() using a file"""
    # invalid entry_point specified
    with pytest.raises(TestCaseLoadFailure, match="Cannot find"):
        TestCase.load_path(str(tmp_path / "missing_file"))
    # valid test case
    src_dir = (tmp_path / "src")
    src_dir.mkdir()
    (src_dir / "prefs.js").touch()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    (src_dir / "optional.bin").touch()
    # load single file test case
    with TestCase.load_path(str(entry_point)) as tcase:
        assert tcase.landing_page == "target.bin"
        assert "prefs.js" not in (x.file_name for x in tcase._files.meta)
        assert "target.bin" in (x.file_name for x in tcase._files.required)
        assert "optional.bin" not in (x.file_name for x in tcase._files.optional)
    # load full test case
    with TestCase.load_path(str(entry_point), full_scan=True, prefs=True) as tcase:
        assert tcase.landing_page == "target.bin"
        assert "prefs.js" in (x.file_name for x in tcase._files.meta)
        assert "target.bin" in (x.file_name for x in tcase._files.required)
        assert "optional.bin" in (x.file_name for x in tcase._files.optional)

def test_testcase_09(tmp_path):
    """test TestCase.load_environ()"""
    (tmp_path / "ubsan.supp").touch()
    (tmp_path / "other_file").touch()
    with TestCase("a.html", "b.html", "test-adapter") as tcase:
        tcase.load_environ(str(tmp_path), {})
        assert "UBSAN_OPTIONS" in tcase.env_vars
        assert "ubsan.supp" in tcase.env_vars["UBSAN_OPTIONS"]
        # existing *SAN_OPTIONS
        tcase.load_environ(str(tmp_path), {"UBSAN_OPTIONS": "a=1:b=2"})
        assert "UBSAN_OPTIONS" in tcase.env_vars
        assert "ubsan.supp" in tcase.env_vars["UBSAN_OPTIONS"]
        opts = re.split(r":(?![\\|/])", tcase.env_vars["UBSAN_OPTIONS"])
        assert len(opts) == 3
        assert "a=1" in opts
        assert "b=2" in opts

def test_inputfile_01():
    """test InputFile with non-existing file"""
    with pytest.raises(IOError, match="File '/foo/bar/none' does not exist"):
        InputFile("/foo/bar/none")

def test_inputfile_02(tmp_path):
    """test InputFile object"""
    tfile = tmp_path / "testfile.bin"
    tfile.write_bytes(b"test")
    with InputFile(str(tfile)) as in_file:
        assert in_file.extension == "bin"
        assert in_file.file_name == str(tfile)
        assert in_file._fp is None
        assert in_file.get_data() == b"test"
        assert in_file._fp is not None
        in_file.close()
        assert in_file._fp is None
        assert in_file.get_fp().read() == b"test"
        assert in_file._fp is not None

def test_testfile_01():
    """test simple TestFile"""
    with TestFile("test_file.txt") as tfile:
        assert tfile.file_name == "test_file.txt"
        assert not tfile._fp.closed
        assert tfile.size == 0
        tfile.close()
        assert tfile._fp.closed

def test_testfile_02(tmp_path):
    """test TestFile.write() and TestFile.dump()"""
    out_file = tmp_path / "test_file.txt"
    with TestFile(out_file.name) as tfile:
        tfile.write(b"foo")
        assert not out_file.is_file()
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
        with out_file.open("r") as in_fp:
            assert in_fp.read() == "foo"
        tfile.write(b"bar")
        tfile.dump(str(tmp_path))
        with out_file.open("r") as in_fp:
            assert in_fp.read() == "foobar"

def test_testfile_03(tmp_path):
    """test TestFile.dump() file with nested path"""
    file_path = "test/dir/path/file.txt"
    with TestFile(file_path) as tfile:
        out_file = tmp_path / file_path
        tfile.write(b"foo")
        assert not out_file.is_file()
        tfile.dump(str(tmp_path))
        assert out_file.is_file()

def test_testfile_04(tmp_path):
    """test TestFile.from_data()"""
    # TODO: different encodings
    with TestFile.from_data("foo", "test_file.txt") as tfile:
        out_file = tmp_path / "test_file.txt"
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
        with out_file.open("r") as in_fp:
            assert in_fp.read() == "foo"

def test_testfile_05(tmp_path):
    """test TestFile.from_file()"""
    in_file = tmp_path / "infile.txt"
    in_file.write_bytes(b"foobar")
    with TestFile.from_file(str(in_file), "outfile.txt") as tfile:
        out_file = tmp_path / "outfile.txt"
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
        with out_file.open("r") as in_fp:
            assert in_fp.read() == "foobar"

def test_testfile_06(tmp_path):
    """test TestFile.clone()"""
    out_file = tmp_path / "test_file.txt"
    with TestFile(out_file.name) as tf1:
        tf1.write(b"foobar")
        try:
            tf2 = tf1.clone()
            tf2.write(b"test")
            assert tf1.file_name == tf2.file_name
            assert tf1._fp != tf2._fp
            tf2.dump(str(tmp_path))
            assert out_file.is_file()
            with out_file.open("r") as in_fp:
                assert in_fp.read() == "foobartest"
        finally:
            tf2.close()
        tf1.dump(str(tmp_path))
        assert out_file.is_file()
        with out_file.open("r") as in_fp:
            assert in_fp.read() == "foobar"

def test_testfile_07(tmp_path):
    """test TestFile.data()"""
    in_file = tmp_path / "infile.txt"
    in_file.write_bytes(b"foobar")
    with TestFile.from_file(str(in_file), "outfile.txt") as tfile:
        assert tfile.data == b"foobar"
