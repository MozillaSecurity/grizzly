# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

import json
import os

import pytest

from .storage import InputFile, TestCase, TestFile, TestFileExists


def test_testcase_01(tmp_path):
    """test empty TestCase"""
    l_page = "land.html"
    r_page = "redirect.html"
    adpt_name = "test-adapter"
    tcase = TestCase(l_page, r_page, adpt_name)
    try:
        assert tcase.landing_page == l_page
        assert tcase.redirect_page == r_page
        assert tcase.adapter_name == adpt_name
        assert tcase.input_fname is None
        assert not tcase._files.meta
        assert not tcase._files.optional
        assert not tcase._files.required
        assert not tcase._env_vars
        assert not list(tcase.optional)
        tcase.dump(str(tmp_path))
        assert not os.listdir(str(tmp_path))
        tcase.dump(str(tmp_path), include_details=True)
        assert (tmp_path / "test_info.json").is_file()
    finally:
        tcase.cleanup()

def test_testcase_02(tmp_path):
    """test TestCase with TestFiles"""
    tcase = TestCase("land_page.html", "redirect.html", "test-adapter", input_fname="testinput.bin")
    try:
        in_file = tmp_path / "testfile1.bin"
        in_file.write_bytes(b"test_req")
        tcase.add_from_file(str(in_file), "testfile1.bin")
        with pytest.raises(TestFileExists) as exc:
            tcase.add_from_file(str(in_file), "testfile1.bin")
        assert "'testfile1.bin' exists in test" in str(exc.value)
        with pytest.raises(TestFileExists) as exc:
            tcase.add_from_data("test", "testfile1.bin")
        assert "'testfile1.bin' exists in test" in str(exc.value)
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
    """test TestCase add_meta()"""
    tcase = TestCase("land_page.html", "redirect.html", "test-adapter")
    try:
        dmp_path = tmp_path / "dmp_test"
        dmp_path.mkdir()
        meta_file = dmp_path / "metafile.bin"
        meta_data = b"foobar"
        tcase.add_meta(TestFile.from_data(meta_data, meta_file.name))
        tcase.dump(str(dmp_path), include_details=True)
        assert meta_file.is_file()
        with meta_file.open("rb") as test_fp:
            assert test_fp.read() == meta_data
    finally:
        tcase.cleanup()

def test_testcase_04(tmp_path):
    """test TestCase.add_environ_var() and TestCase.env_vars"""
    tcase = TestCase("land_page.html", "redirect.html", "test-adapter")
    try:
        tcase.add_environ_var("TEST_ENV_VAR", "1")
        assert len(list(tcase.env_vars)) == 1
        tcase.add_environ_var("TEST_NONE", None)
        assert len(list(tcase.env_vars)) == 1
        assert len(tcase._env_vars) == 2
        dmp_path = tmp_path / "dmp_test"
        dmp_path.mkdir()
        tcase.dump(str(dmp_path), include_details=True)
        with (dmp_path / "test_info.json").open("r") as test_fp:
            data = json.load(test_fp)["env"]
        assert data["TEST_ENV_VAR"] == "1"
        assert data["TEST_NONE"] is None
    finally:
        tcase.cleanup()

def test_testcase_05(tmp_path):
    """test TestCase.remove_files_not_served()"""
    tcase = TestCase("land_page.html", "redirect.html", "test-adapter")
    try:
        tcase.add_from_data("foo", "testfile1.bin")
        tcase.add_from_data("foo", "testfile2.bin", required=False)
        tcase.add_from_data("foo", "testfile3.bin", required=False)
        tcase.add_from_data("foo", "not_served.bin", required=False)
        assert len(list(tcase.optional)) == 3
        tcase.remove_files_not_served(tcase.optional)
        assert len(list(tcase.optional)) == 3
        served = ["testfile2.bin", "testfile3.bin"]
        tcase.remove_files_not_served(served)
        assert len(list(tcase.optional)) == 2
        tcase.dump(str(tmp_path))
        assert "testfile1.bin" in os.listdir(str(tmp_path))
        assert "not_served.bin" not in os.listdir(str(tmp_path))
    finally:
        tcase.cleanup()

def test_inputfile_01():
    """test InputFile with non-existing file"""
    missing_file = os.path.join("foo", "bar", "none")
    with pytest.raises(IOError) as exc:
        InputFile(missing_file)
    assert "File %r does not exist" % (missing_file,) in str(exc.value)

def test_inputfile_02(tmp_path):
    """test InputFile object"""
    tfile = tmp_path / "testfile.bin"
    tfile.write_bytes(b"test")
    in_file = InputFile(str(tfile))
    try:
        assert in_file.extension == "bin"
        assert in_file.file_name == str(tfile)
        assert in_file._fp is None
        assert in_file.get_data() == b"test"
        assert in_file._fp is not None
        in_file.close()
        assert in_file._fp is None
        assert in_file.get_fp().read() == b"test"
        assert in_file._fp is not None
    finally:
        in_file.close()

def test_testfile_01():
    """test simple TestFile"""
    tfile = TestFile("test_file.txt")
    try:
        assert tfile.file_name == "test_file.txt"
        assert not tfile._fp.closed
        tfile.close()
        assert tfile._fp.closed
    finally:
        tfile.close()

def test_testfile_02(tmp_path):
    """test TestFile.write() and TestFile.dump()"""
    out_file = tmp_path / "test_file.txt"
    tfile = TestFile(out_file.name)
    try:
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
    finally:
        tfile.close()

def test_testfile_03(tmp_path):
    """test TestFile.dump() file with nested path"""
    file_path = "test/dir/path/file.txt"
    tfile = TestFile(file_path)
    try:
        out_file = tmp_path / file_path
        tfile.write(b"foo")
        assert not out_file.is_file()
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
    finally:
        tfile.close()

def test_testfile_04(tmp_path):
    """test TestFile.from_data()"""
    # TODO: different encodings
    tfile = TestFile.from_data("foo", "test_file.txt")
    try:
        out_file = tmp_path / "test_file.txt"
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
        with out_file.open("r") as in_fp:
            assert in_fp.read() == "foo"
    finally:
        tfile.close()

def test_testfile_05(tmp_path):
    """test TestFile.from_file()"""
    in_file = tmp_path / "infile.txt"
    in_file.write_bytes(b"foobar")
    tfile = TestFile.from_file(str(in_file), "outfile.txt")
    try:
        out_file = tmp_path / "outfile.txt"
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
        with out_file.open("r") as in_fp:
            assert in_fp.read() == "foobar"
    finally:
        tfile.close()

def test_testfile_06(tmp_path):
    """test TestFile.clone()"""
    out_file = tmp_path / "test_file.txt"
    tf1 = TestFile(out_file.name)
    try:
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
    finally:
        tf1.close()

def test_testfile_07(tmp_path):
    """test TestFile.data()"""
    in_file = tmp_path / "infile.txt"
    in_file.write_bytes(b"foobar")
    tfile = TestFile.from_file(str(in_file), "outfile.txt")
    try:
        assert tfile.data == b"foobar"
    finally:
        tfile.close()
