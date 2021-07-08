# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from pathlib import Path
from shutil import rmtree

from pytest import raises

from .target import AssetManager, Target


class SimpleTarget(Target):
    def _cleanup(self):
        pass

    def close(self, force_close=False):
        pass

    @property
    def closed(self):
        pass

    def create_report(self, is_hang=False):
        pass

    def detect_failure(self, ignored):
        pass

    def handle_hang(self, ignore_idle=True):
        pass

    def launch(self, _location, _env_mod=None):
        pass

    @property
    def monitor(self):
        return self._monitor

    @property
    def prefs(self):
        pass

    def process_assets(self):
        pass

    def save_logs(self, *_args, **_kwargs):
        pass


def test_target_01(tmp_path):
    """test creating a simple Target"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with SimpleTarget(str(fake_file), 321, 2, 3) as target:
        assert target.binary == str(fake_file)
        assert target.assets
        assert not target.is_idle(0)
        assert target.launch_timeout == 321
        assert target.log_size() == 0
        assert target.log_limit == 2
        assert target.memory_limit == 3
        assert target.monitor is None
        # test stubs
        target.add_abort_token("none!")
        target.dump_coverage()
        target.reverse(1, 2)


def test_assert_manager_01(tmp_path):
    """test AssetManager()"""
    with AssetManager(base_path=str(tmp_path)) as assets:
        assert not assets.assets
        assert assets.path
        # get missing
        assert assets.get("missing") is None
        # add missing file
        with raises(OSError, match="Asset 'a' not found 'p'"):
            assets.add("a", "p")
        assert not assets.assets
        # remove invalid asset
        assets.remove("missing")
        # add file
        example = tmp_path / "example.txt"
        example.write_text("example")
        assets.add("example_file", str(example))
        assert len(assets.assets) == 1
        example.unlink()
        assert any(tmp_path.glob("**/example.txt"))
        # add directory
        example = tmp_path / "example_path"
        example.mkdir()
        (example / "a").mkdir()
        (example / "a" / "1.txt").write_text("1")
        (example / "b").mkdir()
        (example / "b" / "2.txt").write_text("2")
        assets.add("example_path", str(example))
        rmtree(str(example))
        assert any(tmp_path.glob("**/example_path/a/1.txt"))
        assert any(tmp_path.glob("**/example_path/b/2.txt"))
        assert len(assets.assets) == 2
        # get
        assert "example.txt" in assets.get("example_file")
        assert "example_path" in assets.get("example_path")
        # remove directory
        assets.remove("example_path")
        assert len(assets.assets) == 1
        assert not any(tmp_path.glob("**/example_path"))
        # remove file
        assets.remove("example_file")
        assert len(assets.assets) == 0
        assert not any(tmp_path.glob("**/example.txt"))
        assert not any(Path(assets.path).iterdir())
        # add in working path
        example = Path(assets.path) / "example.txt"
        example.write_text("test")
        assets.add("direct", str(example))
        # add existing
        example = tmp_path / "example.txt"
        example.write_text("example")
        with raises(OSError, match="Name collision in asset path"):
            assets.add("example_file", str(example))
        # cleanup
        assets.cleanup()
        assert not assets.assets
        assert assets.path is None
