# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from itertools import chain
from json import dumps, loads
from zipfile import ZIP_DEFLATED, ZipFile

from pytest import mark, raises

from ..target import AssetManager
from .storage import TestCase, TestCaseLoadFailure, TestFileExists


def test_testcase_01(tmp_path):
    """test empty TestCase"""
    l_page = "land.html"
    r_page = "redirect.html"
    adpt_name = "test-adapter"
    with TestCase(l_page, r_page, adpt_name) as tcase:
        assert tcase.landing_page == l_page
        assert tcase.redirect_page == r_page
        assert tcase.assets is None
        assert tcase.adapter_name == adpt_name
        assert tcase.duration is None
        assert tcase.data_size == 0
        assert tcase.input_fname is None
        assert tcase.timestamp > 0
        assert not tcase.env_vars
        assert tcase.data_path
        assert not tcase._files.optional
        assert not tcase._files.required
        assert not any(tcase.contents)
        assert tcase.pop_assets() is None
        assert not any(tcase.optional)
        tcase.dump(tmp_path)
        assert not any(tmp_path.iterdir())
        tcase.dump(tmp_path, include_details=True)
        assert (tmp_path / "test_info.json").is_file()


@mark.parametrize(
    "copy, required",
    [
        (True, True),
        (True, False),
        (False, True),
        (False, False),
    ],
)
def test_testcase_02(tmp_path, copy, required):
    """test TestCase.add_from_file()"""
    with TestCase("land_page.html", "a.html", "adpt", input_fname="in.bin") as tcase:
        in_file = tmp_path / "file.bin"
        in_file.write_text("data")
        tcase.add_from_file(in_file, copy=copy, required=required)
        assert tcase.data_size == 4
        assert "file.bin" in tcase.contents
        if required:
            assert in_file.name not in tcase.optional
        else:
            assert in_file.name in tcase.optional
        assert in_file.exists() == copy
        # try overwriting existing file
        if copy:
            with raises(TestFileExists, match="'file.bin' exists in test"):
                tcase.add_from_file(in_file, copy=True)
            assert in_file.exists()
        else:
            assert not in_file.exists()


@mark.parametrize(
    "file_paths",
    [
        ("a.bin",),
        ("a/a.bin",),
        ("a.bin", "b.bin"),
        ("a.bin", "b/c.bin", "b/d.bin"),
    ],
)
def test_testcase_03(tmp_path, file_paths):
    """test TestCase.add_from_file()"""
    with TestCase("land_page.html", "a.html", "adpt") as tcase:
        for file_path in file_paths:
            src_file = tmp_path / file_path
            src_file.parent.mkdir(exist_ok=True, parents=True)
            src_file.write_text("data")
            tcase.add_from_file(src_file, file_name=file_path, required=True)
            assert file_path in tcase.contents
            assert file_path not in tcase.optional


def test_testcase_04():
    """test TestCase.add_from_bytes()"""
    with TestCase("a.html", None, "adpt") as tcase:
        tcase.add_from_bytes(b"foo", "a.html", required=True)
        tcase.add_from_bytes(b"foo", "b.html", required=False)
        assert "a.html" in (x.file_name for x in tcase._files.required)
        assert "b.html" in (x.file_name for x in tcase._files.optional)
        # add file with invalid file name
        with raises(ValueError, match="invalid path ''"):
            tcase.add_from_bytes(b"foo", "", required=False)


def test_testcase_05():
    """test TestCase.purge_optional()"""
    with TestCase("land_page.html", "redirect.html", "test-adapter") as tcase:
        # no optional files
        tcase.purge_optional(["foo"])
        # setup
        tcase.add_from_bytes(b"foo", "testfile1.bin", required=True)
        tcase.add_from_bytes(b"foo", "testfile2.bin", required=False)
        tcase.add_from_bytes(b"foo", "testfile3.bin", required=False)
        tcase.add_from_bytes(b"foo", "not_served.bin", required=False)
        assert len(tuple(tcase.optional)) == 3
        # nothing to remove - with required
        tcase.purge_optional(chain(["testfile1.bin"], tcase.optional))
        assert len(tuple(tcase.optional)) == 3
        # nothing to remove - use relative path (forced)
        tcase.purge_optional(x.file_name for x in tcase._files.optional)
        assert len(tuple(tcase.optional)) == 3
        # nothing to remove - use absolute path
        tcase.purge_optional(x.data_file.as_posix() for x in tcase._files.optional)
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
        tcase.add_from_bytes(b"1", "testfile1.bin", required=True)
        assert tcase.data_size == 1
        tcase.add_from_bytes(b"12", "testfile2.bin", required=False)
        assert tcase.data_size == 3


def test_testcase_07(tmp_path):
    """test TestCase.load_single() using a directory - fail cases"""
    # missing test_info.json
    with raises(TestCaseLoadFailure, match="Missing 'test_info.json'"):
        TestCase.load_single(tmp_path)
    # invalid test_info.json
    (tmp_path / "test_info.json").write_bytes(b"X")
    with raises(TestCaseLoadFailure, match="Invalid 'test_info.json'"):
        TestCase.load_single(tmp_path)
    # test_info.json missing 'target' entry
    (tmp_path / "test_info.json").write_bytes(b"{}")
    with raises(
        TestCaseLoadFailure, match="'test_info.json' has invalid 'target' entry"
    ):
        TestCase.load_single(tmp_path)
    # build a test case
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_file(entry_point)
        src.dump(src_dir, include_details=True)
    # bad 'target' entry in test_info.json
    entry_point.unlink()
    with raises(TestCaseLoadFailure, match="Entry point 'target.bin' not found in"):
        TestCase.load_single(src_dir)
    # bad 'env' entry in test_info.json
    entry_point.touch()
    with AssetManager(base_path=str(tmp_path)) as assets:
        (tmp_path / "example_asset").touch()
        assets.add("example", str(tmp_path / "example_asset"), copy=False)
        with TestCase("target.bin", None, "test-adapter") as src:
            src.assets = assets
            src.dump(src_dir, include_details=True)
    test_info = loads((src_dir / "test_info.json").read_text())
    test_info["env"] = {"bad": 1}
    (src_dir / "test_info.json").write_text(dumps(test_info))
    with raises(TestCaseLoadFailure, match="'env' contains invalid entries"):
        TestCase.load_single(src_dir)


def test_testcase_08(mocker, tmp_path):
    """test TestCase.load_single() using a directory"""
    # build a valid test case
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    asset_file = src_dir / "example_asset"
    asset_file.touch()
    (src_dir / "optional.bin").touch()
    (src_dir / "x.bin").touch()
    nested = src_dir / "nested"
    nested.mkdir()
    # overlap file name in different directories
    (nested / "x.bin").touch()
    (tmp_path / "src" / "nested" / "empty").mkdir()
    dst_dir = tmp_path / "dst"
    with AssetManager(base_path=str(tmp_path)) as assets:
        assets.add("example", str(asset_file))
        with TestCase("target.bin", None, "test-adapter") as src:
            src.env_vars["TEST_ENV_VAR"] = "100"
            src.add_from_file(entry_point)
            src.add_from_file(src_dir / "optional.bin", required=False)
            src.add_from_file(src_dir / "x.bin", required=False)
            src.add_from_file(
                nested / "x.bin",
                file_name=str((nested / "x.bin").relative_to(src_dir)),
                required=False,
            )
            src.assets = assets
            src.dump(dst_dir, include_details=True)
    # test loading test case from test_info.json
    with TestCase.load_single(dst_dir) as dst:
        asset = dst.pop_assets()
        assert asset
        with asset:
            assert "example" in asset.assets
        assert dst.landing_page == "target.bin"
        assert "target.bin" in (x.file_name for x in dst._files.required)
        assert "optional.bin" in (x.file_name for x in dst._files.optional)
        assert "x.bin" in (x.file_name for x in dst._files.optional)
        assert "nested/x.bin" in (x.file_name for x in dst._files.optional)
        assert dst.env_vars["TEST_ENV_VAR"] == "100"
        assert dst.timestamp > 0
    # test load with missing asset
    mocker.patch("grizzly.common.storage.AssetManager.load", side_effect=OSError)
    with raises(TestCaseLoadFailure):
        TestCase.load_single(dst_dir)


def test_testcase_09(tmp_path):
    """test TestCase.load_single() using a file"""
    # invalid entry_point specified
    with raises(TestCaseLoadFailure, match="Missing or invalid TestCase"):
        TestCase.load_single(tmp_path / "missing_file", adjacent=False)
    # valid test case
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    entry_point = src_dir / "target.bin"
    entry_point.touch()
    (src_dir / "optional.bin").touch()
    # load single file test case
    with TestCase.load_single(entry_point, adjacent=False) as tcase:
        assert tcase.assets is None
        assert not tcase.env_vars
        assert tcase.landing_page == "target.bin"
        assert "target.bin" in (x.file_name for x in tcase._files.required)
        assert "optional.bin" not in (x.file_name for x in tcase._files.optional)
        assert tcase.timestamp == 0
    # load full test case
    with TestCase.load_single(entry_point, adjacent=True) as tcase:
        assert tcase.landing_page == "target.bin"
        assert "target.bin" in (x.file_name for x in tcase._files.required)
        assert "optional.bin" in (x.file_name for x in tcase._files.optional)


def test_testcase_10(tmp_path):
    """test TestCase - dump, load and compare"""
    working = tmp_path / "working"
    working.mkdir()
    with TestCase("a.html", "b.html", "adpt") as org:
        # set non default values
        org.duration = 1.23
        org.env_vars = {"en1": "1", "en2": "2"}
        org.hang = True
        org.input_fname = "infile"
        org.time_limit = 10
        org.add_from_bytes(b"a", "a.html")
        with AssetManager(base_path=str(tmp_path)) as assets:
            fake = tmp_path / "fake_asset"
            fake.touch()
            assets.add("fake", str(fake))
            org.assets = assets
            org.dump(working, include_details=True)
        org.assets = None
        with TestCase.load_single(working, adjacent=False) as loaded:
            try:
                for prop in TestCase.__slots__:
                    if prop.startswith("_") or prop in ("assets", "redirect_page"):
                        continue
                    assert getattr(loaded, prop) == getattr(org, prop)
                assert not set(org.contents) ^ set(loaded.contents)
                assert loaded.assets
                assert "fake" in loaded.assets.assets
            finally:
                if loaded.assets:
                    loaded.assets.cleanup()


def test_testcase_11(tmp_path):
    """test TestCase.load() - missing file and empty directory"""
    # missing file
    with raises(TestCaseLoadFailure, match="Invalid TestCase path"):
        TestCase.load("missing")
    # empty path
    assert not TestCase.load(tmp_path, adjacent=True)


def test_testcase_12(tmp_path):
    """test TestCase.load() - single file"""
    tfile = tmp_path / "testcase.html"
    tfile.touch()
    testcases = TestCase.load(tfile, adjacent=False)
    try:
        assert len(testcases) == 1
        assert all(x.assets is None for x in testcases)
    finally:
        any(x.cleanup() for x in testcases)


def test_testcase_13(tmp_path):
    """test TestCase.load() - single directory"""
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_bytes(b"test", "target.bin")
        src.dump(tmp_path, include_details=True)
    testcases = TestCase.load(tmp_path)
    try:
        assert len(testcases) == 1
        assert all(x.assets is None for x in testcases)
    finally:
        any(x.cleanup() for x in testcases)


def test_testcase_14(tmp_path):
    """test TestCase.load() - multiple directories (with assets)"""
    nested = tmp_path / "nested"
    nested.mkdir()
    asset_file = tmp_path / "example_asset"
    asset_file.touch()
    with AssetManager(base_path=str(tmp_path)) as assets:
        assets.add("example", str(asset_file))
        with TestCase("target.bin", None, "test-adapter") as src:
            src.assets = assets
            src.add_from_bytes(b"test", "target.bin")
            src.dump(nested / "test-1", include_details=True)
            src.dump(nested / "test-2", include_details=True)
            src.dump(nested / "test-3", include_details=True)
    testcases = TestCase.load(nested)
    try:
        assert len(testcases) == 3
        assert all(x.assets is not None for x in testcases)
        asset = testcases[-1].pop_assets()
        assert asset is not None
        assert "example" in asset.assets
    finally:
        any(x.cleanup() for x in testcases)
        for test in testcases:
            if test.assets:
                test.assets.cleanup()
    # try loading testcases that are nested too deep
    assert not TestCase.load(tmp_path)


def test_testcase_15(tmp_path):
    """test TestCase.load() - archive"""
    archive = tmp_path / "testcase.zip"
    # bad archive
    archive.write_bytes(b"x")
    with raises(TestCaseLoadFailure, match="Testcase archive is corrupted"):
        TestCase.load(archive)
    # build archive containing multiple testcases
    with TestCase("target.bin", None, "test-adapter") as src:
        src.add_from_bytes(b"test", "target.bin")
        src.dump(tmp_path / "test-0", include_details=True)
        src.dump(tmp_path / "test-1", include_details=True)
        src.dump(tmp_path / "test-2", include_details=True)
    (tmp_path / "log_dummy.txt").touch()
    (tmp_path / "not_a_tc").mkdir()
    (tmp_path / "not_a_tc" / "file.txt").touch()
    with ZipFile(archive, mode="w", compression=ZIP_DEFLATED) as zfp:
        for entry in tmp_path.rglob("*"):
            if entry.is_file():
                zfp.write(str(entry), arcname=str(entry.relative_to(tmp_path)))
    testcases = TestCase.load(archive)
    try:
        assert len(testcases) == 3
        assert all(x.assets is None for x in testcases)
        assert all("target.bin" in x.contents for x in testcases)
    finally:
        any(x.cleanup() for x in testcases)


def test_testcase_16(tmp_path):
    """test TestCase.add_batch()"""
    include = tmp_path / "inc_path"
    include.mkdir()
    inc_1 = include / "file.bin"
    inc_1.write_bytes(b"a")
    (include / "nested").mkdir()
    inc_2 = include / "nested" / "nested.js"
    inc_2.write_bytes(b"a")
    other_path = tmp_path / "other_path"
    other_path.mkdir()
    (other_path / "no_include.bin").write_bytes(b"a")
    with TestCase("a.b", "a.b", "simple") as tcase:
        # missing directory
        tcase.add_batch("/missing/path/", tuple())
        assert not any(tcase.contents)
        # missing file
        with raises(IOError):
            tcase.add_batch(tmp_path, [tmp_path / "missing.bin"])
        assert not any(tcase.contents)
        # relative file name
        tcase.add_batch(include, ["file.bin"])
        assert not any(tcase.contents)
        # valid list
        tcase.add_batch(include, [inc_1, inc_2, tmp_path / "inc_path2" / "extra.bin"])
        assert "file.bin" in tcase.contents
        assert "nested/nested.js" in tcase.contents
        assert len(list(tcase.contents)) == 2
        # nested url
        tcase.add_batch(include, [inc_1], prefix="test")
        assert "test/file.bin" in tcase.contents
        assert len(list(tcase.contents)) == 3
        # collision
        with raises(TestFileExists, match="'file.bin' exists in test"):
            tcase.add_batch(include, [inc_1])


def test_testcase_17(tmp_path):
    """test TestCase.scan_path()"""
    # empty path
    (tmp_path / "not-test").mkdir()
    assert not any(TestCase.scan_path(tmp_path))
    # multiple test case directories
    paths = [tmp_path / ("test-%d" % i) for i in range(3)]
    with TestCase("test.htm", None, "test-adapter") as src:
        src.add_from_bytes(b"test", "test.htm")
        for path in paths:
            src.dump(path, include_details=True)
    tc_paths = list(TestCase.scan_path(tmp_path))
    assert len(tc_paths) == 3
    # single test case directory
    tc_paths = list(TestCase.scan_path(paths[0]))
    assert len(tc_paths) == 1


def test_testcase_18():
    """test TestCase.get_file()"""
    with TestCase("test.htm", None, "test-adapter") as src:
        src.add_from_bytes(b"test", "test.htm")
        assert src.get_file("missing") is None
        assert src.get_file("test.htm")


def test_testcase_19():
    """test TestCase.clone()"""
    with TestCase("a.htm", "b.htm", "adpt", input_fname="fn", time_limit=2) as src:
        src.duration = 1.2
        src.hang = True
        src.add_from_bytes(b"123", "test.htm", required=True)
        src.add_from_bytes(b"456", "opt.htm", required=False)
        src.env_vars["foo"] = "bar"
        with src.clone() as dst:
            for prop in TestCase.__slots__:
                if prop.startswith("_"):
                    continue
                assert getattr(src, prop) == getattr(dst, prop)
            assert src.data_size == dst.data_size
            for file, data in (
                ("test.htm", b"123"),
                ("opt.htm", b"456"),
            ):
                src_file = src.get_file(file).data_file
                dst_file = dst.get_file(file).data_file
                assert src_file.read_bytes() == data
                assert dst_file.read_bytes() == data
                assert not dst_file.samefile(src_file)
            assert dst.env_vars == {"foo": "bar"}
            assert not set(src.optional) ^ set(dst.optional)


@mark.parametrize(
    "path",
    [
        # empty file name
        "",
        # path (root) with missing file name
        "/",
        # path (root) with missing file name
        "/.",
        # path with missing file name
        "path/",
        # outside of wwwroot
        "../test",
        # outside of wwwroot
        "a/../../b",
        # outside of wwwroot
        "..",
        # outside of wwwroot
        "C:\\test",
        # cwd
        ".",
    ],
)
def test_testcase_20(path):
    """test TestCase.sanitize_path() with invalid paths"""
    with raises(ValueError, match="invalid path"):
        TestCase.sanitize_path(path)


@mark.parametrize(
    "path, expected_result",
    [
        ("a", "a"),
        ("file.bin", "file.bin"),
        ("a/file.bin", "a/file.bin"),
        ("/file.bin", "file.bin"),
        ("./file.bin", "file.bin"),
        ("path\\file", "path/file"),
        ("\\\\a\\b\\file.bin", "a/b/file.bin"),
        (".file", ".file"),
        ("a/../file.bin", "file.bin"),
        ("./a/./b/../c", "a/c"),
    ],
)
def test_testcase_21(path, expected_result):
    """test TestCase.sanitize_path()"""
    assert TestCase.sanitize_path(path) == expected_result
