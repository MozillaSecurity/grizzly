# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from importlib.metadata import EntryPoint

from pytest import raises

from ..target import Target
from .plugins import PluginLoadError, load_plugin, scan_plugins, scan_target_assets


class FakeType1:
    pass


class FakeType2:
    pass


def test_load_01(mocker):
    """test load() - nothing to load"""
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points", autospec=True, return_value=()
    )
    with raises(PluginLoadError, match="'test-name' not found in 'test-group'"):
        load_plugin("test-name", "test-group", FakeType1)


def test_load_02(mocker):
    """test load() - successful load"""
    entry = mocker.Mock(spec=EntryPoint)
    entry.name = "test-name"
    entry.load.return_value = FakeType1
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points",
        autospec=True,
        return_value=(entry,),
    )
    assert load_plugin("test-name", "test-group", FakeType1)


def test_load_03(mocker):
    """test load() - invalid type"""
    entry = mocker.Mock(spec=EntryPoint)
    entry.name = "test-name"
    entry.load.return_value = FakeType1
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points",
        autospec=True,
        return_value=(entry,),
    )
    with raises(PluginLoadError, match="'test-name' doesn't inherit from FakeType2"):
        load_plugin("test-name", "test-group", FakeType2)


def test_scan_01(mocker):
    """test scan() - no entries found"""
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points", autospec=True, return_value=()
    )
    assert not scan_plugins("test_group")


def test_scan_02(mocker):
    """test scan() - duplicate entry"""
    entry = mocker.Mock(spec=EntryPoint)
    entry.name = "test_entry"
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points",
        autospec=True,
        return_value=(entry, entry),
    )
    with raises(PluginLoadError, match="Duplicate entry 'test_entry' in 'test_group'"):
        scan_plugins("test_group")


def test_scan_03(mocker):
    """test scan() - success"""
    entry = mocker.Mock(spec=EntryPoint)
    entry.name = "test-name"
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points",
        autospec=True,
        return_value=(entry,),
    )
    assert "test-name" in scan_plugins("test_group")


def test_scan_target_assets_01(mocker):
    """test scan_target_assets() - success"""
    targ1 = mocker.Mock(spec=EntryPoint)
    targ1.name = "t1"
    targ1.load.return_value = mocker.Mock(spec_set=Target, SUPPORTED_ASSETS=())
    targ2 = mocker.Mock(spec=EntryPoint)
    targ2.name = "t2"
    targ2.load.return_value = mocker.Mock(spec_set=Target, SUPPORTED_ASSETS=("a", "B"))
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points",
        autospec=True,
        return_value=(targ1, targ2),
    )
    assets = scan_target_assets()
    assert "t1" in assets
    assert not assets["t1"]
    assert "t2" in assets
    assert "B" in assets["t2"]
