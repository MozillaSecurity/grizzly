# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from pkg_resources import EntryPoint
from pytest import raises

from .plugins import PluginLoadError, load, scan


class FakeType1:
    pass


class FakeType2:
    pass


def test_load_01(mocker):
    """test load() - nothing to load"""
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points", autospec=True, return_value=[]
    )
    with raises(PluginLoadError, match="'test-name' not found in 'test-group'"):
        load("test-name", "test-group", FakeType1)


def test_load_02(mocker):
    """test load() - successful load"""
    entry = mocker.Mock(set_spec=EntryPoint)
    entry.name = "test-name"
    entry.load.return_value = FakeType1
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points", autospec=True, return_value=[entry]
    )
    assert load("test-name", "test-group", FakeType1)


def test_load_03(mocker):
    """test load() - invalid type"""
    entry = mocker.Mock(set_spec=EntryPoint)
    entry.name = "test-name"
    entry.load.return_value = FakeType1
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points", autospec=True, return_value=[entry]
    )
    with raises(PluginLoadError, match="'test-name' doesn't inherit from FakeType2"):
        load("test-name", "test-group", FakeType2)


def test_scan_01(mocker):
    """test scan() - no entries found"""
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points", autospec=True, return_value=[]
    )
    assert not scan("test_group")


def test_scan_02(mocker):
    """test scan() - duplicate entry"""
    entry = mocker.Mock(set_spec=EntryPoint)
    entry.name = "test_entry"
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points",
        autospec=True,
        return_value=[entry, entry],
    )
    with raises(PluginLoadError, match="Duplicate entry 'test_entry' in 'test_group'"):
        scan("test_group")


def test_scan_03(mocker):
    """test scan() - success"""
    entry = mocker.Mock(set_spec=EntryPoint)
    entry.name = "test-name"
    mocker.patch(
        "grizzly.common.plugins.iter_entry_points",
        autospec=True,
        return_value=[entry],
    )
    assert "test-name" in scan("test_group")
