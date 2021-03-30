# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import pytest

from .adapter import Adapter, AdapterError


class SimpleAdapter(Adapter):
    def generate(self, testcase, server_map):
        pass


def test_adapter_01():
    """test a simple Adapter"""
    with pytest.raises(AdapterError, match="name must not be empty"):
        SimpleAdapter("")
    adpt = SimpleAdapter("simple")
    assert isinstance(adpt.fuzz, dict)
    assert not adpt.fuzz
    assert adpt.monitor is None
    assert adpt.name == "simple"
    assert adpt.remaining is None
    assert adpt.get_harness() is None
    adpt.setup(None, None)
    adpt.generate(None, None)
    adpt.on_served(None, None)
    adpt.on_timeout(None, None)
    adpt.pre_launch()
    adpt.cleanup()


def test_adapter_02(tmp_path):
    """test Adapter.enable_harness()"""
    adpt = SimpleAdapter("a")
    # built-in harness
    adpt.enable_harness()
    assert adpt.get_harness()
    # external harness
    ext_harness_file = tmp_path / "ext_harness.html"
    test_data = b"external_harness_data"
    ext_harness_file.write_bytes(test_data)
    adpt.enable_harness(str(ext_harness_file))
    assert adpt.get_harness() == test_data


def test_adapter_03(tmp_path):
    """test Adapter.scan_path()"""
    # empty path
    assert not any(SimpleAdapter.scan_path(str(tmp_path)))
    # missing path
    assert not any(SimpleAdapter.scan_path(str(tmp_path / "none")))
    # path to file
    file1 = tmp_path / "test1.txt"
    file1.touch()
    found = tuple(SimpleAdapter.scan_path(str(file1)))
    assert str(file1) in found
    assert len(found) == 1
    # path to directory
    assert len(tuple(SimpleAdapter.scan_path(str(tmp_path)))) == 1
    # path to directory (w/ ignored)
    (tmp_path / ".ignored").touch()
    nested = tmp_path / "nested"
    nested.mkdir()
    file2 = nested / "test2.bin"
    file2.touch()
    assert len(tuple(SimpleAdapter.scan_path(str(tmp_path)))) == 1
    # path to directory (recursive)
    found = tuple(SimpleAdapter.scan_path(str(tmp_path), recursive=True))
    assert str(file1) in found
    assert str(file2) in found
    assert len(found) == 2
