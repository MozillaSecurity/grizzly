# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

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
        assert not tcase.get_optional()
        tcase.dump(str(tmp_path))
        assert not os.listdir(str(tmp_path))
        tcase.dump(str(tmp_path), include_details=True)
        assert "test_info.json" in os.listdir(str(tmp_path))
        assert "test_info.txt" in os.listdir(str(tmp_path))  # deprecated
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
        assert "'testfile1.bin' exists in test" in str(exc)
        with pytest.raises(TestFileExists) as exc:
            tcase.add_from_data("test", "testfile1.bin")
        assert "'testfile1.bin' exists in test" in str(exc)
        tcase.add_from_data("test_nreq", "test_dir/testfile2.bin", required=False)
        tcase.add_from_data("test_blah", "/testfile3.bin")
        tcase.add_from_data("test_windows", "\\\\dir\\file.bin")
        opt_files = tcase.get_optional()
        assert len(opt_files) == 1
        assert os.path.join("test_dir", "testfile2.bin") in opt_files
        tcase.dump(str(tmp_path), include_details=True)
        assert os.path.isdir(os.path.join(str(tmp_path), "test_dir"))
        assert os.path.isfile(os.path.join(str(tmp_path), "test_info.json"))
        assert os.path.isfile(os.path.join(str(tmp_path), "test_info.txt"))
        with open(os.path.join(str(tmp_path), "test_info.txt"), "r") as test_fp:
            assert "testinput.bin" in test_fp.read()
        assert os.path.isfile(os.path.join(str(tmp_path), "testfile1.bin"))
        with open(os.path.join(str(tmp_path), "testfile1.bin"), "r") as test_fp:
            assert test_fp.read() == "test_req"
        assert os.path.isfile(os.path.join(str(tmp_path), "test_dir", "testfile2.bin"))
        with open(os.path.join(str(tmp_path), "test_dir", "testfile2.bin"), "r") as test_fp:
            assert test_fp.read() == "test_nreq"
        assert os.path.isfile(os.path.join(str(tmp_path), "testfile3.bin"))
        with open(os.path.join(str(tmp_path), "testfile3.bin"), "r") as test_fp:
            assert test_fp.read() == "test_blah"
        assert os.path.isfile(os.path.join(str(tmp_path), "dir", "file.bin"))
        with open(os.path.join(str(tmp_path), "dir", "file.bin"), "r") as test_fp:
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
    """test TestCase add_environ_var() and env_vars()"""
    tcase = TestCase("land_page.html", "redirect.html", "test-adapter")
    try:
        tcase.add_environ_var("TEST_ENV_VAR", "1")
        assert len(tcase.env_vars()) == 1
        tcase.add_environ_var("TEST_NONE", None)
        assert len(tcase.env_vars()) == 1
        assert len(tcase._env_vars) == 2
        dmp_path = tmp_path / "dmp_test"
        dmp_path.mkdir()
        tcase.dump(str(dmp_path), include_details=True)
        env_file = dmp_path / "env_vars.txt"
        assert env_file.is_file()
        with env_file.open("r") as test_fp:
            data = test_fp.read()
        assert "TEST_ENV_VAR=1\n" in data
        assert "TEST_NONE=\n" in data
    finally:
        tcase.cleanup()

def test_inputfile_01():
    """test InputFile with non-existing file"""
    with pytest.raises(IOError) as exc:
        InputFile(os.path.join("foo", "bar", "none"))
    assert "File 'foo/bar/none' does not exist" in str(exc)

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
