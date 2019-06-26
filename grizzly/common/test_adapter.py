# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .adapter import Adapter


class SimpleAdapter(Adapter):
    NAME = "simple"

    def generate(self, testcase, input_file, server_map):
        pass


def test_adapter_01():
    """test a simple Adapter"""
    adpt = SimpleAdapter()
    assert isinstance(adpt.fuzz, dict)
    assert not adpt.fuzz
    assert adpt.monitor is None
    assert adpt.get_harness() is None
    adpt.setup(None)
    adpt.generate(None, None, None)
    adpt.on_served(None, None)
    adpt.on_timeout(None, None)
    adpt.pre_launch()
    adpt.cleanup()

def test_adapter_02(tmp_path):
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
