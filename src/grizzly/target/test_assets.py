# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from pathlib import Path
from shutil import rmtree

from pytest import raises

from .assets import AssetError, AssetManager


def test_asset_manager_01(tmp_path):
    """test AssetManager()"""
    with AssetManager(base_path=tmp_path) as asset_mgr:
        assert not asset_mgr.assets
        assert asset_mgr.path
        assert asset_mgr.is_empty()
        # add file (move)
        example = tmp_path / "example.txt"
        example.write_text("foo")
        asset_location = asset_mgr.add("example_file", example, copy=False)
        assert asset_mgr.assets["example_file"] == "example.txt"
        assert asset_mgr.path / "example.txt" == asset_location
        assert asset_mgr.get("example_file") == asset_location
        assert len(asset_mgr.assets) == 1
        assert not asset_mgr.is_empty()
        assert not example.is_file()
        assert (asset_mgr.path / "example.txt").is_file()
        # add existing asset - update asset (copy)
        example = tmp_path / "example_2.txt"
        example.write_text("foo")
        asset_mgr.add("example_file", example)
        assert example.is_file()
        assert len(asset_mgr.assets) == 1
        # add directory
        example = tmp_path / "example_path"
        example.mkdir()
        (example / "a").mkdir()
        (example / "a" / "1.txt").write_text("1")
        (example / "b").mkdir()
        (example / "b" / "2.txt").write_text("2")
        asset_mgr.add("example_path", example)
        rmtree(example)
        assert (asset_mgr.path / "example_path/a/1.txt").is_file()
        assert (asset_mgr.path / "example_path/b/2.txt").is_file()
        assert len(asset_mgr.assets) == 2
        # get
        example = asset_mgr.get("example_file")
        assert example
        assert (asset_mgr.path / "example_2.txt").samefile(example)
        example = asset_mgr.get("example_path")
        assert example
        assert (asset_mgr.path / "example_path").samefile(example)
        # remove directory
        asset_mgr.remove("example_path")
        assert len(asset_mgr.assets) == 1
        assert asset_mgr.path.is_dir()
        assert not (asset_mgr.path / "example_path").is_dir()
        # remove file
        asset_mgr.remove("example_file")
        assert len(asset_mgr.assets) == 0
        assert not any(asset_mgr.path.iterdir())
        # cleanup
        asset_mgr.cleanup()
        assert not asset_mgr.assets
        assert not asset_mgr.path.is_dir()


def test_asset_manager_02(tmp_path):
    """test AssetManager() failures"""
    with AssetManager(base_path=tmp_path) as asset_mgr:
        # get missing
        assert asset_mgr.get("missing") is None
        # add missing file
        with raises(OSError, match="'missing' does not exist"):
            asset_mgr.add("a", Path("missing"))
        assert not asset_mgr.assets
        # remove invalid asset
        asset_mgr.remove("missing")
        # add file
        example = tmp_path / "example.txt"
        example.touch()
        asset_mgr.add("example_file", example, copy=True)
        # add with asset with name and file collision
        asset_mgr.add("example_file", example, copy=True)
        # add with file name collision as different asset
        with raises(AssetError, match="collide: 'example.txt' already exists"):
            asset_mgr.add("collide", example)
        assert "collide" not in asset_mgr.assets


def test_asset_manager_03(tmp_path):
    """test AssetManager() load"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "b.txt").touch()

    with AssetManager.load({"a": "b.txt"}, src, base_path=tmp_path) as asset_mgr:
        assert len(asset_mgr.assets) == 1
        assert "a" in asset_mgr.assets
        assert asset_mgr.assets["a"] == "b.txt"
        assert (asset_mgr.path / asset_mgr.assets["a"]).is_file()


def test_asset_manager_04(tmp_path):
    """test AssetManager.add_batch()"""
    batch = []
    with AssetManager(base_path=tmp_path) as asset_mgr:
        # add file
        example = tmp_path / "example.txt"
        example.write_text("example")
        batch.append(["example_file", example])
        # add directory
        example = tmp_path / "example_path"
        example.mkdir()
        (example / "a").mkdir()
        (example / "a" / "1.txt").write_text("1")
        batch.append(["example_path", example])
        asset_mgr.add_batch(batch)
        assert len(asset_mgr.assets) == 2
