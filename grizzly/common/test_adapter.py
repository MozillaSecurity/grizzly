# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import pytest

from .adapter import Adapter, AdapterError


class SimpleAdapter(Adapter):
    NAME = "simple"

    def generate(self, testcase, server_map):
        pass


def test_adapter_01():
    """test a bad Adapter"""
    class BadAdapter(SimpleAdapter):
        NAME = None
    with pytest.raises(AdapterError, match="BadAdapter.NAME must be a string"):
        BadAdapter()

def test_adapter_02():
    """test a simple Adapter"""
    adpt = SimpleAdapter()
    assert isinstance(adpt.fuzz, dict)
    assert not adpt.fuzz
    assert adpt.monitor is None
    assert adpt.remaining is None
    assert adpt.get_harness() is None
    adpt.setup(None, None)
    adpt.generate(None, None)
    adpt.on_served(None, None)
    adpt.on_timeout(None, None)
    adpt.pre_launch()
    adpt.cleanup()

def test_adapter_03(tmp_path):
    """test Adapter.enable_harness()"""
    harness_file = tmp_path / "harness.html"
    adpt = SimpleAdapter()
    adpt.HARNESS_FILE = str(harness_file)
    test_data = b"fake_default_harness_data"
    harness_file.write_bytes(test_data)
    adpt.enable_harness()
    harness = adpt.get_harness()
    assert harness is not None
    harness.dump(str(tmp_path))
    dump_harness = tmp_path / "grizzly_fuzz_harness.html"
    assert dump_harness.is_file()
    assert dump_harness.read_bytes() == test_data
    harness_file.unlink()

    test_data = b"fake_external_harness_data"
    harness_file.write_bytes(test_data)
    adpt.enable_harness(str(harness_file))
    harness = adpt.get_harness()
    assert harness is not None
    harness.dump(str(tmp_path))
    assert dump_harness.is_file()
    assert dump_harness.read_bytes() == test_data
    adpt.cleanup()

def test_adapter_04(tmp_path):
    """test Adapter.scan_path()"""
    # empty path
    assert not any(SimpleAdapter.scan_path(str(tmp_path)))
    # missing path
    assert not any(SimpleAdapter.scan_path(str(tmp_path / "none")))
    # path to file
    file1 = (tmp_path / "test1.txt")
    file1.touch()
    found = tuple(SimpleAdapter.scan_path(str(tmp_path)))
    assert len(found) == 1
    assert str(file1) in found
    # path to directory
    assert len(tuple(SimpleAdapter.scan_path(str(tmp_path)))) == 1
    # path to directory (w/ ignored)
    (tmp_path / ".ignored").touch()
    nested = (tmp_path / "nested")
    nested.mkdir()
    file2 = (nested / "test2.bin")
    file2.touch()
    assert len(tuple(SimpleAdapter.scan_path(str(tmp_path)))) == 1
    # path to directory (recursive)
    found = tuple(SimpleAdapter.scan_path(str(tmp_path), recursive=True))
    assert len(found) == 2
    assert str(file1) in found
    assert str(file2) in found
