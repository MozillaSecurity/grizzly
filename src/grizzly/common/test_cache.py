# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from pytest import raises

from .cache import _active_cache, add_cached, clear_cached, find_cached


def test_cache_active_cache(mocker, tmp_path):
    """test _active_cache()"""
    cache_path = tmp_path / "cache"
    cache_path.mkdir()
    mocker.patch("grizzly.common.cache.CACHE_PATH", new=cache_path)
    mocker.patch("grizzly.common.cache.LOCK_FILE", new=tmp_path / "cache.lock")
    # create path
    mocker.patch("grizzly.common.cache._ACTIVE_CACHE", new=None)
    new_path = _active_cache()
    assert any(cache_path.iterdir())
    assert cache_path in new_path.parents
    # find existing with expired entry
    mocker.patch("grizzly.common.cache._ACTIVE_CACHE", new=None)
    (cache_path / "0").mkdir()
    found_path = _active_cache()
    assert found_path == new_path


def test_cache_basic(mocker, tmp_path):
    """test basic cache functionality"""
    mocker.patch("grizzly.common.cache._ACTIVE_CACHE", new=None)
    (tmp_path / "cache").mkdir()
    mocker.patch("grizzly.common.cache.CACHE_PATH", new=tmp_path / "cache")
    mocker.patch("grizzly.common.cache.LOCK_FILE", new=tmp_path / "cache.lock")
    # attempt to clear empty cache
    clear_cached()
    # invalid keys
    with raises(ValueError, match="Key must be alphanumeric"):
        add_cached("", tmp_path / "foo")
    with raises(ValueError, match="Key must be alphanumeric"):
        find_cached("test/key")
    # look for non-existing entry
    assert find_cached("test-key") is None
    # add entry
    content = tmp_path / "content"
    content.mkdir()
    (content / "data.txt").write_text("123")
    cache_dir = add_cached("test-key", content)
    assert cache_dir.is_dir()
    assert not content.is_dir()
    assert (cache_dir / "content" / "data.txt").is_file()
    assert (cache_dir / "content" / "data.txt").read_text() == "123"
    # find existing entry
    cache_dir = find_cached("test-key")
    assert cache_dir is not None
    assert (cache_dir / "content" / "data.txt").is_file()
    assert (cache_dir / "content" / "data.txt").read_text() == "123"
    # look for missing entry when cache has data
    assert find_cached("missing") is None
    # add when entry exists (use existing)
    collision = add_cached("test-key", content)
    assert collision is not None
    assert (collision / "content" / "data.txt").samefile(
        cache_dir / "content" / "data.txt"
    )
    # clear with nothing expired
    clear_cached()
    assert find_cached("test-key") is not None
    # clear with everything expired
    clear_cached(max_age=0)
    assert find_cached("test-key") is None
