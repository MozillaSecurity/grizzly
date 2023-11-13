# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from pathlib import Path
from shutil import rmtree

from pytest import raises

from .assets import AssetError, AssetManager


def test_asset_manager_01(tmp_path):
    """test AssetManager()"""
    with AssetManager(base_path=tmp_path) as assets:
        assert not assets.assets
        assert assets.path
        assert assets.is_empty()
        # add file (move)
        example = tmp_path / "example.txt"
        example.write_text("foo")
        asset_location = assets.add("example_file", example, copy=False)
        assert assets.assets["example_file"] == "example.txt"
        assert assets.path / "example.txt" == asset_location
        assert assets.get("example_file") == asset_location
        assert len(assets.assets) == 1
        assert not assets.is_empty()
        assert not example.is_file()
        assert (assets.path / "example.txt").is_file()
        # add existing asset - update asset (copy)
        example = tmp_path / "example_2.txt"
        example.write_text("foo")
        assets.add("example_file", example)
        assert example.is_file()
        assert len(assets.assets) == 1
        # add directory
        example = tmp_path / "example_path"
        example.mkdir()
        (example / "a").mkdir()
        (example / "a" / "1.txt").write_text("1")
        (example / "b").mkdir()
        (example / "b" / "2.txt").write_text("2")
        assets.add("example_path", example)
        rmtree(example)
        assert (assets.path / "example_path/a/1.txt").is_file()
        assert (assets.path / "example_path/b/2.txt").is_file()
        assert len(assets.assets) == 2
        # get
        assert (assets.path / "example_2.txt").samefile(assets.get("example_file"))
        assert (assets.path / "example_path").samefile(assets.get("example_path"))
        # remove directory
        assets.remove("example_path")
        assert len(assets.assets) == 1
        assert assets.path.is_dir()
        assert not (assets.path / "example_path").is_dir()
        # remove file
        assets.remove("example_file")
        assert len(assets.assets) == 0
        assert not any(assets.path.iterdir())
        # cleanup
        assets.cleanup()
        assert not assets.assets
        assert assets.path is None


def test_asset_manager_02(tmp_path):
    """test AssetManager() failures"""
    with AssetManager(base_path=str(tmp_path)) as assets:
        # get missing
        assert assets.get("missing") is None
        # add missing file
        with raises(OSError, match="'missing' does not exist"):
            assets.add("a", Path("missing"))
        assert not assets.assets
        # remove invalid asset
        assets.remove("missing")
        # add file
        example = tmp_path / "example.txt"
        example.touch()
        assets.add("example_file", example, copy=True)
        # add with asset with name and file collision
        assets.add("example_file", example, copy=True)
        # add with file name collision as different asset
        with raises(AssetError, match="collide: 'example.txt' already exists"):
            assets.add("collide", example)
        assert "collide" not in assets.assets


def test_asset_manager_03(tmp_path):
    """test AssetManager() load"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "b.txt").touch()

    with AssetManager.load({"a": "b.txt"}, src, base_path=str(tmp_path)) as assets:
        assert len(assets.assets) == 1
        assert "a" in assets.assets
        assert assets.assets["a"] == "b.txt"
        assert (assets.path / assets.assets["a"]).is_file()


def test_asset_manager_04(tmp_path):
    """test AssetManager.add_batch()"""
    batch = []
    with AssetManager(base_path=str(tmp_path)) as assets:
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
        assets.add_batch(batch)
        assert len(assets.assets) == 2
