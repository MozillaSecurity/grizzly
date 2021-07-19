# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from os.path import isfile
from pathlib import Path
from shutil import rmtree

from pytest import raises

from .assets import AssetError, AssetManager


def test_asset_manager_01(tmp_path):
    """test AssetManager()"""
    with AssetManager(base_path=str(tmp_path)) as assets:
        assert not assets.assets
        assert assets.path
        assert assets.is_empty()
        # add file (move)
        example = tmp_path / "example.txt"
        example.write_text("example")
        asset_location = assets.add("example_file", str(example), copy=False)
        assert str(Path(assets.path) / "example.txt") == asset_location
        assert len(assets.assets) == 1
        assert not assets.is_empty()
        assert not example.is_file()
        assert any(Path(assets.path).glob("**/example.txt"))
        # add existing asset - update asset (copy)
        example.write_text("example")
        assets.add("example_file", str(example))
        assert example.is_file()
        # add directory
        example = tmp_path / "example_path"
        example.mkdir()
        (example / "a").mkdir()
        (example / "a" / "1.txt").write_text("1")
        (example / "b").mkdir()
        (example / "b" / "2.txt").write_text("2")
        assets.add("example_path", str(example))
        rmtree(str(example))
        assert any(Path(assets.path).glob("**/example_path/a/1.txt"))
        assert any(Path(assets.path).glob("**/example_path/b/2.txt"))
        assert len(assets.assets) == 2
        # get
        assert "example.txt" in assets.get("example_file")
        assert "example_path" in assets.get("example_path")
        # remove directory
        assets.remove("example_path")
        assert len(assets.assets) == 1
        assert not any(Path(assets.path).glob("**/example_path"))
        # remove file
        assets.remove("example_file")
        assert len(assets.assets) == 0
        assert not any(Path(assets.path).iterdir())
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
            assets.add("a", "missing")
        assert not assets.assets
        # remove invalid asset
        assets.remove("missing")
        # add file
        example = tmp_path / "example.txt"
        example.write_text("example")
        assets.add("example_file", str(example), copy=True)
        # add existing file under as different asset (collision)
        with raises(AssetError, match="'example.txt' is an existing asset"):
            assets.add("collide", str(example))
        assert "collide" not in assets.assets
        example.unlink()
        # add file from existing asset
        example = Path(assets.path) / "example.txt"
        with raises(AssetError, match="Cannot add existing asset content"):
            assets.add("existing", str(example))
        assert "existing" not in assets.assets
        # add file from existing asset with asset name collision
        example = Path(assets.path) / "example.txt"
        with raises(AssetError, match="Cannot add existing asset content"):
            assets.add("example_file", str(example))
        assert "example_file" in assets.assets


def test_asset_manager_03(tmp_path):
    """test AssetManager() dump/load"""
    # test dump()
    with AssetManager(base_path=str(tmp_path)) as assets:
        # add file
        example = tmp_path / "example.txt"
        example.write_text("example")
        assets.add("example_file", str(example), copy=False)
        # add directory
        example = tmp_path / "example_path"
        example.mkdir()
        (example / "a").mkdir()
        (example / "a" / "1.txt").write_text("1")
        assets.add("example_path", str(example))
        # invalid entry
        assets.assets["invalid"] = "bad/path"
        # dump
        dump_path = tmp_path / "dump"
        dumped = assets.dump(str(dump_path), subdir="sub")
    assert len(dumped) == 2
    assert (dump_path / "sub" / "example.txt").is_file()
    assert (dump_path / "sub" / "example_path" / "a" / "1.txt").is_file()
    # test load()
    with AssetManager.load(
        dumped, str(dump_path / "sub"), base_path=str(tmp_path)
    ) as assets:
        assert len(assets.assets) == 2
        assert isfile(assets.assets["example_file"])


def test_asset_manager_04(tmp_path):
    """test AssetManager.add_batch()"""
    batch = list()
    with AssetManager(base_path=str(tmp_path)) as assets:
        # add file
        example = tmp_path / "example.txt"
        example.write_text("example")
        batch.append(["example_file", str(example)])
        # add directory
        example = tmp_path / "example_path"
        example.mkdir()
        (example / "a").mkdir()
        (example / "a" / "1.txt").write_text("1")
        batch.append(["example_path", str(example)])
        assets.add_batch(batch)
        assert len(assets.assets) == 2
