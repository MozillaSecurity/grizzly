# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from itertools import chain
import json
import re
import os
import zipfile

import pytest

from .storage import TestCase, TestFile, TestCaseLoadFailure, TestFileExists


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
        assert tcase.timestamp > 0
        assert not tcase.env_vars
        assert not tcase._existing_paths
        assert not tcase._files.meta
        assert not tcase._files.optional
        assert not tcase._files.required
        assert not tcase.contains("no_file")
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
        tcase.add_from_file(str(in_file))
        assert tcase.data_size == 8
        with pytest.raises(TestFileExists, match="'testfile1.bin' exists in test"):
            tcase.add_from_file(str(in_file), file_name="testfile1.bin")
        with pytest.raises(TestFileExists, match="'testfile1.bin' exists in test"):
            tcase.add_from_data("test", "testfile1.bin")
        tcase.add_from_data("test_nreq", "nested/testfile2.bin", required=False)
        tcase.add_from_data("test_blah", "/testfile3.bin")
        tcase.add_from_data("test_windows", "\\\\dir\\file.bin")
        assert tcase.contains("testfile1.bin")
        opt_files = list(tcase.optional)
        assert os.path.join("nested", "testfile2.bin") in opt_files
        assert len(opt_files) == 1
        tcase.dump(str(tmp_path), include_details=True)
        assert (tmp_path / "nested").is_dir()
        test_info = json.loads((tmp_path / "test_info.json").read_text())
        assert test_info["adapter"] == "test-adapter"
        assert test_info["input"] == "testinput.bin"
        assert test_info["target"] == "land_page.html"
        assert isinstance(test_info["env"], dict)
        assert in_file.read_bytes() == b"test_req"
        assert (tmp_path / "nested" / "testfile2.bin").read_bytes() == b"test_nreq"
        assert (tmp_path / "testfile3.bin").read_bytes() == b"test_blah"
        assert (tmp_path / "dir" / "file.bin").read_bytes() == b"test_windows"
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
        assert meta_file.read_bytes() == meta_data

def test_testcase_04(tmp_path):
    """test TestCase.add_environ_var() and TestCase.env_vars"""
    with TestCase("land_page.html", "redirect.html", "test-adapter") as tcase:
        tcase.add_environ_var("TEST_ENV_VAR", "1")
        assert len(tcase.env_vars) == 1
        tcase.add_environ_var("TEST_NONE", None)
        assert len(tcase.env_vars) == 2
        dmp_path = tmp_path / "dmp_test"
        dmp_path.mkdir()
        tcase.dump(str(dmp_path), include_details=True)
        data = json.loads((dmp_path / "test_info.json").read_text())
        assert "env" in data
        assert data["env"]["TEST_ENV_VAR"] == "1"
        assert data["env"]["TEST_NONE"] is None

def test_testcase_05():
    """test TestCase.purge_optional()"""
    with TestCase("land_page.html", "redirect.html", "test-adapter") as tcase:
        tcase.add_from_data("foo", "testfile1.bin")
        tcase.add_from_data("foo", "testfile2.bin", required=False)
        tcase.add_from_data("foo", "testfile3.bin", required=False)
        tcase.add_from_data("foo", "not_served.bin", required=False)
        assert len(tuple(tcase.optional)) == 3
        # nothing to remove - with required
        tcase.purge_optional(chain(["testfile1.bin"], tcase.optional))
        assert len(tuple(tcase.optional)) == 3
        # nothing to remove - without required
        tcase.purge_optional(tcase.optional)
        assert len(tuple(tcase.optional)) == 3
        # remove not_served.bin
        tcase.purge_optional(["testfile2.bin", "testfile3.bin"])
        assert len(tuple(tcase.optional)) == 2
        assert "testfile2.bin" in tcase.optional
        assert "testfile3.bin" in tcase.optional
        assert "not_served.bin" not in tcase.optional
        # remove remaining optional
        tcase.purge_optional(["testfile1.bin"])
        assert not any(tcase.optional)

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
    """test TestCase.load_single() using a directory fail cases"""
    # missing test_info.json
    with pytest.raises(TestCaseLoadFailure, match="Missing 'test_info.json'"):
        TestCase.load_single(str(tmp_path), True)
    # invalid test_info.json
    (tmp_path / "test_info.json").write_bytes(b"X")
    with pytest.raises(TestCaseLoadFailure, match="Invalid 'test_info.json'"):
        TestCase.load_single(str(tmp_path), True)
    # test_info.json missing 'target' entry
    (tmp_path / "test_info.json").write_bytes(b"{}")
    with pytest.raises(TestCaseLoadFailure, match="'test_info.json' has invalid 'target' entry"):
        TestCase.load_single(str(tmp_path), True)
    # build a test case
    src_dir = (tmp_path / "src")
    src_dir.mkdir()
    (src_dir / "prefs.js").touch()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_file(str(entry_point))
        src.dump(str(src_dir), include_details=True)
    # bad 'target' entry in test_info.json
    entry_point.unlink()
    with pytest.raises(TestCaseLoadFailure, match="Entry point 'target.bin' not found in"):
        TestCase.load_single(str(src_dir), True)
    # bad 'env' entry in test_info.json
    entry_point.touch()
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_environ_var("TEST_ENV_VAR", 100)
        src.dump(str(src_dir), include_details=True)
    with pytest.raises(TestCaseLoadFailure, match="'env_data' contains invalid 'env' entries"):
        TestCase.load_single(str(src_dir), True)

def test_testcase_08(tmp_path):
    """test TestCase.load_single() using a directory"""
    # build a valid test case
    src_dir = (tmp_path / "src")
    src_dir.mkdir()
    (src_dir / "prefs.js").touch()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    (src_dir / "optional.bin").touch()
    (src_dir / "x.bin").touch()
    nested = (tmp_path / "src" / "nested")
    nested.mkdir()
    # overlap file name in different directories
    (nested / "x.bin").touch()
    (tmp_path / "src" / "nested" / "empty").mkdir()
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_environ_var("TEST_ENV_VAR", "100")
        src.add_from_file(str(entry_point))
        src.dump(str(src_dir), include_details=True)
    # load test case from test_info.json
    with TestCase.load_single(str(src_dir), True) as dst:
        assert dst.landing_page == "target.bin"
        assert "prefs.js" in (x.file_name for x in dst._files.meta)
        assert "target.bin" in (x.file_name for x in dst._files.required)
        assert "optional.bin" in (x.file_name for x in dst._files.optional)
        assert "x.bin" in (x.file_name for x in dst._files.optional)
        assert os.path.join("nested", "x.bin") in (x.file_name for x in dst._files.optional)
        assert dst.env_vars["TEST_ENV_VAR"] == "100"
        assert dst.timestamp > 0

def test_testcase_09(tmp_path):
    """test TestCase.load_single() using a file"""
    # invalid entry_point specified
    with pytest.raises(TestCaseLoadFailure, match="Missing or invalid TestCase"):
        TestCase.load_single(str(tmp_path / "missing_file"), False)
    # valid test case
    src_dir = (tmp_path / "src")
    src_dir.mkdir()
    (src_dir / "prefs.js").touch()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    (src_dir / "optional.bin").touch()
    # load single file test case
    with TestCase.load_single(str(entry_point), False) as tcase:
        assert tcase.landing_page == "target.bin"
        assert "prefs.js" not in (x.file_name for x in tcase._files.meta)
        assert "target.bin" in (x.file_name for x in tcase._files.required)
        assert "optional.bin" not in (x.file_name for x in tcase._files.optional)
        assert tcase.timestamp == 0
    # load full test case
    with TestCase.load_single(str(entry_point), True, adjacent=True) as tcase:
        assert tcase.landing_page == "target.bin"
        assert "prefs.js" in (x.file_name for x in tcase._files.meta)
        assert "target.bin" in (x.file_name for x in tcase._files.required)
        assert "optional.bin" in (x.file_name for x in tcase._files.optional)

def test_testcase_10(tmp_path):
    """test TestCase.load() - missing file and empty directory"""
    # missing file
    with pytest.raises(TestCaseLoadFailure, match="Invalid TestCase path"):
        TestCase.load("missing", False)
    # empty path
    assert not TestCase.load(str(tmp_path), True)

def test_testcase_11(tmp_path):
    """test TestCase.load() - single file"""
    tfile = (tmp_path / "testcase.html")
    tfile.touch()
    testcases = TestCase.load(str(tfile), False)
    try:
        assert len(testcases) == 1
    finally:
        map(lambda x: x.cleanup, testcases)

def test_testcase_12(tmp_path):
    """test TestCase.load() - single directory"""
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_data("test", "target.bin")
        src.dump(str(tmp_path), include_details=True)
    testcases = TestCase.load(str(tmp_path), False)
    try:
        assert len(testcases) == 1
    finally:
        map(lambda x: x.cleanup, testcases)

def test_testcase_13(tmp_path):
    """test TestCase.load() - multiple directories"""
    nested = (tmp_path / "nested")
    nested.mkdir()
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_data("test", "target.bin")
        src.dump(str(nested / "test-1"), include_details=True)
        src.dump(str(nested / "test-2"), include_details=True)
        src.dump(str(nested / "test-3"), include_details=True)
    testcases = TestCase.load(str(nested), False)
    try:
        assert len(testcases) == 3
    finally:
        map(lambda x: x.cleanup, testcases)
    # try loading testcases that are nested too deep
    assert not TestCase.load(str(tmp_path), False)

def test_testcase_14(tmp_path):
    """test TestCase.load() - archive"""
    archive = tmp_path / "testcase.zip"
    # bad archive
    archive.write_bytes(b"x")
    with pytest.raises(TestCaseLoadFailure, match="Testcase archive is corrupted"):
        TestCase.load(str(archive), True)
    # build archive containing multiple testcases
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_data("test", "target.bin")
        src.dump(str(tmp_path / "test-0"), include_details=True)
        src.dump(str(tmp_path / "test-1"), include_details=True)
        src.dump(str(tmp_path / "test-2"), include_details=True)
    (tmp_path / "test-1" / "prefs.js").write_bytes(b"fake_prefs")
    (tmp_path / "log_dummy.txt").touch()
    (tmp_path / "not_a_tc").mkdir()
    (tmp_path / "not_a_tc" / "file.txt").touch()
    with zipfile.ZipFile(str(archive), mode="w", compression=zipfile.ZIP_DEFLATED) as zfp:
        for dir_name, _, dir_files in os.walk(str(tmp_path)):
            arc_path = os.path.relpath(dir_name, str(tmp_path))
            for file_name in dir_files:
                zfp.write(
                    os.path.join(dir_name, file_name),
                    arcname=os.path.join(arc_path, file_name))
    testcases = TestCase.load(str(archive), True)
    try:
        assert len(tuple(testcases)) == 3
    finally:
        map(lambda x: x.cleanup, testcases)

def test_testcase_15(tmp_path):
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
        assert "a=1" in opts
        assert "b=2" in opts
        assert len(opts) == 3

def test_testcase_16(tmp_path):
    """test TestCase.add_batch()"""
    include = (tmp_path / "inc_path")
    include.mkdir()
    inc_1 = (include / "file.bin")
    inc_1.write_bytes(b"a")
    (include / "nested").mkdir()
    inc_2 = (include / "nested" / "nested.js")
    inc_2.write_bytes(b"a")
    other_path = (tmp_path / "other_path")
    other_path.mkdir()
    (other_path / "no_include.bin").write_bytes(b"a")
    with TestCase("a.b", "a.b", "simple") as tcase:
        # missing directory
        tcase.add_batch("/missing/path/", tuple())
        assert not tcase._existing_paths
        # missing file
        with pytest.raises(IOError):
            tcase.add_batch(str(tmp_path), [str(tmp_path / "missing.bin")])
        assert not tcase._existing_paths
        # relative file name
        tcase.add_batch(str(include), ["file.bin"])
        assert not tcase._existing_paths
        # valid list
        tcase.add_batch(str(include), [str(inc_1), str(inc_2), str(tmp_path / "inc_path2" / "extra.bin")])
        assert tcase.contains("file.bin")
        assert tcase.contains(os.path.join("nested", "nested.js"))
        assert len(tcase._existing_paths) == 2
        # nested url
        tcase.add_batch(str(include), [str(inc_1)], prefix="test")
        assert tcase.contains(os.path.join("test", "file.bin"))
        assert len(tcase._existing_paths) == 3
        # collision
        with pytest.raises(TestFileExists, match="'file.bin' exists in test"):
            tcase.add_batch(str(include), [str(inc_1)])

def test_testcase_17(tmp_path):
    """test TestCase.scan_path()"""
    # empty path
    (tmp_path / "not-test").mkdir()
    assert not tuple(TestCase.scan_path(str(tmp_path)))
    # multiple test case directories
    paths = [str(tmp_path / ("test-%d" % i)) for i in range(3)]
    with TestCase("test.htm", None, "test-adapter") as src:
        src.add_from_data("test", "test.htm")
        for path in paths:
            src.dump(path, include_details=True)
    tc_paths = list(TestCase.scan_path(str(tmp_path)))
    assert len(tc_paths) == 3
    # single test case directory
    tc_paths = list(TestCase.scan_path(str(paths[0])))
    assert len(tc_paths) == 1

def test_testcase_18():
    """test TestCase.get_file()"""
    with TestCase("test.htm", None, "test-adapter") as src:
        src.add_from_data("test", "test.htm")
        assert src.get_file("missing") is None
        assert src.get_file("test.htm").data == b"test"

def test_testcase_19(tmp_path):
    """test TestCase.clone()"""
    with TestCase("test.htm", "redirect.htm", "test-adaptor", "input.py") as src:
        src.add_from_data("123", "test.htm")
        src.add_from_data("456", "opt.htm", required=False)
        src.add_meta(TestFile.from_data("pref", "prefs.js"))
        src.add_environ_var("go", "away")
        with src.clone() as tgt:
            for prop in TestCase.__slots__:
                if prop.startswith("_"):
                    continue
                assert getattr(src, prop) == getattr(tgt, prop)
            assert src.data_size == tgt.data_size
            for file, data in (("test.htm", b"123"), ("opt.htm", b"456"), ("prefs.js", b"pref")):
                src.get_file(file).write(b"src")
                tgt.get_file(file).write(b"tgt")
                assert src.get_file(file).data == data + b"src"
                assert tgt.get_file(file).data == data + b"tgt"
            src.add_environ_var("foo", "bar")
            tgt.add_environ_var("hello", "kitty")
            assert src.env_vars == {"foo": "bar", "go": "away"}
            assert tgt.env_vars == {"hello": "kitty", "go": "away"}

def test_testfile_01():
    """test simple TestFile"""
    with TestFile("test_file.txt") as tfile:
        assert tfile.file_name == "test_file.txt"
        assert not tfile._fp.closed
        assert tfile.size == 0
        tfile.close()
        assert tfile._fp.closed

def test_testfile_02():
    """test TestFile file names"""
    # empty file name
    with pytest.raises(TypeError, match="file_name is invalid"):
        TestFile("")
    # path (root) with missing file name
    with pytest.raises(TypeError, match="file_name is invalid"):
        TestFile("/")
    # path (root) with missing file name
    with pytest.raises(TypeError, match="file_name is invalid"):
        TestFile("/.")
    # path with missing file name
    with pytest.raises(TypeError, match="file_name is invalid"):
        TestFile("path/")
    # invalid use of '..'
    with pytest.raises(TypeError, match="file_name is invalid"):
        TestFile("../test")
    # path (root) with file
    with TestFile("/valid.txt") as tfile:
        assert tfile.file_name == "valid.txt"
    # path with file
    with TestFile("path\\file") as tfile:
        assert os.path.split(tfile.file_name) == ("path", "file")
    # with valid use of '.' and '..'
    with TestFile("./a/./b/../c") as tfile:
        assert os.path.split(tfile.file_name) == ("a", "c")
    # filename starting with '.'
    with TestFile(".file") as tfile:
        assert tfile.file_name == ".file"

def test_testfile_03(tmp_path):
    """test TestFile.write() and TestFile.dump()"""
    out_file = tmp_path / "test_file.txt"
    with TestFile(out_file.name) as tfile:
        tfile.write(b"foo")
        assert not out_file.is_file()
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
        assert out_file.read_text() == "foo"
        tfile.write(b"bar")
        tfile.dump(str(tmp_path))
        assert out_file.read_text() == "foobar"

def test_testfile_04(tmp_path):
    """test TestFile.dump() file with nested path"""
    file_path = "test/dir/path/file.txt"
    with TestFile(file_path) as tfile:
        out_file = tmp_path / file_path
        tfile.write(b"foo")
        assert not out_file.is_file()
        tfile.dump(str(tmp_path))
        assert out_file.is_file()

def test_testfile_05(tmp_path):
    """test TestFile.from_data()"""
    # TODO: different encodings
    with TestFile.from_data("foo", "test_file.txt") as tfile:
        out_file = tmp_path / "test_file.txt"
        tfile.dump(str(tmp_path))
        assert out_file.is_file()
        assert out_file.read_text() == "foo"

def test_testfile_06(tmp_path):
    """test TestFile.from_file()"""
    in_file = tmp_path / "infile.txt"
    in_file.write_bytes(b"foobar")
    # check re-using filename
    with TestFile.from_file(str(in_file)) as tfile:
        assert tfile.file_name == "infile.txt"
    # check data
    with TestFile.from_file(str(in_file), file_name="outfile.txt") as tfile:
        assert tfile.file_name == "outfile.txt"
        tfile.dump(str(tmp_path))
        out_file = tmp_path / "outfile.txt"
        assert out_file.is_file()
        assert out_file.read_text() == "foobar"

def test_testfile_07(tmp_path):
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
            assert out_file.read_text() == "foobartest"
        finally:
            tf2.close()
        tf1.dump(str(tmp_path))
        assert out_file.is_file()
        assert out_file.read_text() == "foobar"

def test_testfile_08(tmp_path):
    """test TestFile.data()"""
    in_file = tmp_path / "infile.txt"
    in_file.write_bytes(b"foobar")
    with TestFile.from_file(str(in_file), file_name="outfile.txt") as tfile:
        assert tfile.data == b"foobar"
