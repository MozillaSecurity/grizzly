# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from json import dumps, loads

from pytest import mark, raises

from ..target import AssetManager
from .storage import TEST_INFO, TestCase, TestCaseLoadFailure, TestFileExists


def test_testcase_01(tmp_path):
    """test empty TestCase"""
    entry_point = "test.html"
    adpt_name = "test-adapter"
    with TestCase(entry_point, adpt_name) as tcase:
        assert tcase.entry_point == entry_point
        assert entry_point not in tcase
        assert not tcase.assets
        assert not tcase.assets_path
        assert tcase.adapter_name == adpt_name
        assert tcase.duration is None
        assert tcase.data_size == 0
        assert not tcase.https
        assert tcase.input_fname is None
        assert tcase.timestamp > 0
        assert not tcase.env_vars
        assert tcase.root
        assert not tcase._files.optional
        assert not tcase._files.required
        assert not tcase._in_place
        assert len(tcase) == 0
        assert not any(tcase)
        assert not any(tcase.optional)
        assert not any(tcase.required)
        tcase.dump(tmp_path)
        assert not any(tmp_path.iterdir())
        tcase.dump(tmp_path, include_details=True)
        assert (tmp_path / TEST_INFO).is_file()
        tcase.cleanup()
        assert not tcase.root.is_dir()


def test_testcase_02():
    """test TestCase.add_from_file() - add files with existing, in place data"""
    with TestCase("test.html", "adpt") as tcase:
        (tcase.root / "test.html").touch()
        (tcase.root / "opt.html").touch()
        tcase.add_from_file(tcase.root / "test.html", required=True)
        assert len(tcase) == 1
        assert "test.html" in tcase
        assert len(tuple(tcase.required)) == 1
        assert not any(tcase.optional)
        tcase.add_from_file(tcase.root / "opt.html", required=False)
        assert len(tcase) == 2
        assert "opt.html" in tcase
        assert len(tuple(tcase.required)) == 1
        assert len(tuple(tcase.optional)) == 1
        # add previously added file
        with raises(TestFileExists, match="'opt.html' exists in test"):
            tcase.add_from_file(tcase.root / "opt.html", required=False)


@mark.parametrize(
    "copy, required",
    [
        (True, True),
        (True, False),
        (False, True),
        (False, False),
    ],
)
def test_testcase_03(tmp_path, copy, required):
    """test TestCase.add_from_file()"""
    in_file = tmp_path / "file.bin"
    in_file.write_text("data")
    with TestCase("test.html", "adpt", input_fname="in.bin") as tcase:
        tcase.add_from_file(in_file, copy=copy, required=required)
        assert tcase.data_size == 4
        assert "file.bin" in tcase
        assert tcase["file.bin"].is_file()
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
def test_testcase_04(tmp_path, file_paths):
    """test TestCase.add_from_file()"""
    with TestCase("test.html", "adpt") as tcase:
        for file_path in file_paths:
            src_file = tmp_path / file_path
            src_file.parent.mkdir(exist_ok=True, parents=True)
            src_file.write_text("data")
            tcase.add_from_file(src_file, file_name=file_path, required=True)
            assert file_path in tcase
            assert file_path in tcase.required
            assert file_path not in tcase.optional
            assert (tcase.root / file_path).is_file()


def test_testcase_05():
    """test TestCase.add_from_bytes()"""
    with TestCase("a.html", "adpt") as tcase:
        tcase.add_from_bytes(b"foo", "a.html", required=True)
        tcase.add_from_bytes(b"foo", "b.html", required=False)
        assert "a.html" in tcase._files.required
        assert "b.html" in tcase._files.optional
        # add file with invalid file name
        with raises(ValueError, match="invalid path ''"):
            tcase.add_from_bytes(b"foo", "", required=False)


def test_testcase_06():
    """test TestCase.data_size"""
    with TestCase("test.html", "test-adapter") as tcase:
        assert tcase.data_size == 0
        tcase.add_from_bytes(b"1", "testfile1.bin", required=True)
        assert tcase.data_size == 1
        tcase.add_from_bytes(b"12", "testfile2.bin", required=False)
        assert tcase.data_size == 3


def test_testcase_07(tmp_path):
    """test TestCase.read_info()"""
    # missing test info file
    assert not TestCase.read_info(tmp_path)
    # invalid test info file
    (tmp_path / TEST_INFO).write_text("X")
    with raises(TestCaseLoadFailure, match=f"Invalid '{TEST_INFO}'"):
        TestCase.read_info(tmp_path)
    # test info file missing 'target' entry
    (tmp_path / TEST_INFO).write_text("{}")
    with raises(TestCaseLoadFailure, match=f"Invalid 'target' entry in '{TEST_INFO}'"):
        TestCase.read_info(tmp_path)
    # success
    (tmp_path / TEST_INFO).write_text('{"target": "foo"}')
    assert TestCase.read_info(tmp_path) == {"target": "foo"}


def test_testcase_08(tmp_path):
    """test TestCase._find_entry_point()"""
    # empty directory
    with raises(TestCaseLoadFailure, match="Could not determine entry point"):
        TestCase._find_entry_point(tmp_path)
    # missing potential entry point
    (tmp_path / TEST_INFO).touch()
    with raises(TestCaseLoadFailure, match="Could not determine entry point"):
        TestCase._find_entry_point(tmp_path)
    # success
    (tmp_path / "poc.html").touch()
    assert TestCase._find_entry_point(tmp_path) == (tmp_path / "poc.html")
    # Ambiguous entry point
    (tmp_path / "other.html").touch()
    with raises(TestCaseLoadFailure, match="Ambiguous entry point"):
        TestCase._find_entry_point(tmp_path)


def test_testcase_09(tmp_path):
    """test TestCase.load_meta()"""
    # empty directory
    with raises(TestCaseLoadFailure, match="Could not determine entry point"):
        TestCase.load_meta(tmp_path)
    # missing directory
    with raises(TestCaseLoadFailure, match="Missing or invalid TestCase"):
        TestCase.load_meta(tmp_path / "missing")
    # success (directory)
    (tmp_path / "test_01.html").touch()
    entry_point, info = TestCase.load_meta(tmp_path)
    assert entry_point == tmp_path / "test_01.html"
    assert not info
    # success (file)
    entry_point, info = TestCase.load_meta(tmp_path / "test_01.html")
    assert entry_point == tmp_path / "test_01.html"
    assert not info
    # success (with test info file)
    (tmp_path / TEST_INFO).write_text('{"target": "test_01.html"}')
    (tmp_path / "other.html").touch()
    entry_point, info = TestCase.load_meta(tmp_path)
    assert entry_point == (tmp_path / "test_01.html")
    assert info.get("target") == "test_01.html"
    # success (with test info file) override entry point
    entry_point, info = TestCase.load_meta(
        tmp_path, entry_point=(tmp_path / "other.html")
    )
    assert entry_point == tmp_path / "other.html"
    assert info.get("target") == "other.html"
    # invalid test info file (will fallback to searching for test)
    (tmp_path / "other.html").unlink()
    (tmp_path / TEST_INFO).write_text("{}")
    entry_point, info = TestCase.load_meta(tmp_path)
    assert entry_point == (tmp_path / "test_01.html")
    assert not info


def test_testcase_10(tmp_path):
    """test TestCase.load()"""
    data = tmp_path / "test-data"
    data.mkdir()
    # empty directory
    with raises(TestCaseLoadFailure, match="Could not determine entry point"):
        TestCase.load(tmp_path)
    # missing directory
    with raises(TestCaseLoadFailure, match="Missing or invalid TestCase"):
        TestCase.load(tmp_path / "missing")
    # directory with test case
    (data / "poc.html").touch()
    loaded = TestCase.load(data)
    assert loaded._in_place
    assert loaded.entry_point == "poc.html"
    assert loaded.root == data
    # directory with test case invalid entry point
    (tmp_path / "external.html").touch()
    with raises(TestCaseLoadFailure, match="Entry point must be in root of given path"):
        TestCase.load(data, entry_point=tmp_path / "external.html")
    # single file directory
    loaded = TestCase.load(data / "poc.html")
    assert loaded._in_place
    assert loaded.entry_point == "poc.html"
    assert loaded.root == data


def test_testcase_11(tmp_path):
    """test TestCase.load() existing test case with simple test info file"""
    # build a test case
    src = tmp_path / "src"
    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"", test.entry_point, required=True)
        test.dump(src, include_details=True)
    # successful load
    loaded = TestCase.load(src)
    assert loaded._in_place
    assert loaded.entry_point == "test.html"
    assert loaded.root.samefile(src)
    assert len(tuple(loaded.required)) == 1
    assert not any(loaded.optional)


@mark.parametrize("catalog", [False, True])
def test_testcase_12(tmp_path, catalog):
    """test TestCase.load() existing test case with test info file"""
    # build a test case
    asset_file = tmp_path / "asset.txt"
    asset_file.touch()
    src = tmp_path / "src"
    with AssetManager(base_path=tmp_path) as asset_mgr:
        asset_mgr.add("example", asset_file)
        with TestCase("test.html", "test-adapter") as test:
            test.add_from_bytes(b"", test.entry_point, required=True)
            test.add_from_bytes(b"", "optional.bin", required=False)
            test.add_from_bytes(b"", "nested/a.html", required=False)
            test.assets = dict(asset_mgr.assets)
            test.assets_path = asset_mgr.path
            test.env_vars["TEST_ENV_VAR"] = "100"
            test.dump(src, include_details=True)
    # successful load
    loaded = TestCase.load(src, catalog=catalog)
    assert loaded.entry_point == "test.html"
    assert loaded.root.samefile(src)
    assert (loaded.root / "optional.bin").is_file()
    assert (loaded.root / "nested" / "a.html").is_file()
    if catalog:
        assert "optional.bin" in loaded.optional
        assert "nested/a.html" in loaded.optional
        assert "_assets_/asset.txt" not in loaded.optional
        assert TEST_INFO not in loaded.optional
    else:
        assert not any(loaded.optional)
    assert loaded.assets == {"example": "asset.txt"}
    assert loaded.assets_path is not None
    assert (loaded.root / loaded.assets_path / "asset.txt").is_file()
    assert loaded.env_vars.get("TEST_ENV_VAR") == "100"
    assert len(tuple(loaded.required)) == 1
    # this should do nothing
    loaded.cleanup()
    assert loaded.root.is_dir()


def test_testcase_13(tmp_path):
    """test TestCase.load() test info file error cases"""
    # bad 'assets' entry in test info file
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    entry_point = src_dir / "target.html"
    entry_point.touch()
    with TestCase("target.html", "test-adapter") as src:
        src.dump(src_dir, include_details=True)
    test_info = loads((src_dir / TEST_INFO).read_text())
    test_info["assets"] = {"bad": 1}
    (src_dir / TEST_INFO).write_text(dumps(test_info))
    with raises(TestCaseLoadFailure, match="'assets' contains invalid entry"):
        TestCase.load(src_dir)
    # bad 'env' entry in test info file
    with TestCase("target.html", "test-adapter") as src:
        src.dump(src_dir, include_details=True)
    test_info = loads((src_dir / TEST_INFO).read_text())
    test_info["env"] = {"bad": 1}
    (src_dir / TEST_INFO).write_text(dumps(test_info))
    with raises(TestCaseLoadFailure, match="'env' contains invalid entry"):
        TestCase.load(src_dir)
    # missing asset data
    test_info["env"].clear()
    test_info["assets"] = {"a": "a"}
    test_info["assets_path"] = "missing"
    (src_dir / TEST_INFO).write_text(dumps(test_info))
    with TestCase.load(src_dir) as loaded:
        assert not loaded.assets
        assert loaded.assets_path is None


def test_testcase_14(tmp_path):
    """test TestCase.load() and TestCase.dump() with assets"""
    # build a test case
    asset_file = tmp_path / "asset.txt"
    asset_file.touch()
    src = tmp_path / "src"
    with AssetManager() as asset_mgr:
        asset_mgr.add("example", asset_file)
        with TestCase("test.html", "test-adapter") as test:
            test.add_from_bytes(b"", test.entry_point, required=True)
            test.assets = dict(asset_mgr.assets)
            test.assets_path = asset_mgr.path
            test.dump(src, include_details=True)
    # load
    loaded = TestCase.load(src)
    assert loaded.assets
    assert loaded.assets_path
    with AssetManager.load(loaded.assets, loaded.assets_path) as asset_mgr:
        # dump the AssetManager's assets (simulate how this works in replay)
        loaded.assets = dict(asset_mgr.assets)
        loaded.assets_path = asset_mgr.path
        # dump loaded test case
        dst = tmp_path / "dst"
        loaded.dump(dst, include_details=True)
    assert (dst / "test.html").is_file()
    assert (dst / "_assets_" / "asset.txt").is_file()


def test_testcase_15(tmp_path):
    """test TestCase - dump, load and compare"""
    asset_path = tmp_path / "assets"
    asset_path.mkdir()
    asset = asset_path / "asset_file.txt"
    asset.touch()
    working = tmp_path / "working"
    with TestCase("a.html", "adpt") as org:
        # set non default values
        org.duration = 1.23
        org.env_vars = {"en1": "1", "en2": "2"}
        org.https = not org.https
        org.hang = not org.hang
        org.input_fname = "infile"
        org.add_from_bytes(b"a", org.entry_point)
        org.assets = {"sample": asset.name}
        org.assets_path = asset_path
        org.version = "1.2.3"
        org.dump(working, include_details=True)
        assert (working / "_assets_" / asset.name).is_file()
        with TestCase.load(working) as loaded:
            for prop in TestCase.__slots__:
                if not prop.startswith("_") and prop != "assets_path":
                    assert getattr(loaded, prop) == getattr(org, prop)
            assert not set(org) ^ set(loaded)
            assert "sample" in loaded.assets
            assert loaded.assets["sample"] == asset.name


def test_testcase_16():
    """test TestCase.__getitem__()"""
    with TestCase("test.htm", "test-adapter") as src:
        src.add_from_bytes(b"test", src.entry_point)
        with raises(KeyError, match="missing"):
            src["missing"]  # pylint: disable=pointless-statement
        assert src["test.htm"]


@mark.parametrize(
    "remote_assets",
    [
        # No assets
        None,
        # Remote assets
        True,
        # Local assets (assets only exist in test case)
        False,
    ],
)
def test_testcase_17(tmp_path, remote_assets):
    """test TestCase.clone()"""
    with TestCase("test.htm", "adpt", input_fname="fn") as src:
        if remote_assets:
            src.assets = {"foo": "asset.file"}
            src.assets_path = tmp_path
            (tmp_path / "asset.file").touch()
        elif remote_assets is not None:
            src.assets = {"foo": "asset.file"}
            src.assets_path = src.root / "_assets_"
            src.assets_path.mkdir()
            (src.assets_path / "asset.file").touch()
        src.duration = 1.2
        src.hang = True
        src.https = True
        src.add_from_bytes(b"123", "test.htm", required=True)
        src.add_from_bytes(b"456", "opt.htm", required=False)
        src.env_vars["foo"] = "bar"
        with src.clone() as dst:
            for prop in TestCase.__slots__:
                if prop.startswith("_"):
                    continue
                if remote_assets is False and prop == "assets_path":
                    assert src.assets_path != dst.assets_path
                    continue
                assert getattr(src, prop) == getattr(dst, prop)
            assert src.data_size == dst.data_size
            for file, data in (
                ("test.htm", b"123"),
                ("opt.htm", b"456"),
            ):
                assert src[file].read_bytes() == data
                assert dst[file].read_bytes() == data
                assert not dst[file].samefile(src[file])
            assert dst.env_vars == {"foo": "bar"}
            assert not set(src.optional) ^ set(dst.optional)
            assert not set(src.required) ^ set(dst.required)
            if remote_assets is not None:
                assert dst.assets_path
                assert (dst.assets_path / dst.assets["foo"]).is_file()


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
def test_testcase_18(path):
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
def test_testcase_19(path, expected_result):
    """test TestCase.sanitize_path()"""
    assert TestCase.sanitize_path(path) == expected_result
