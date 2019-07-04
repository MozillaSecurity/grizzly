# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

import os

import pytest

from .iomanager import IOManager, ServerMap
from .storage import InputFile, TestFile


def test_iomanager_01():
    """test a simple IOManager"""
    iom = IOManager()
    try:
        assert not iom.input_files
        assert iom.active_input is None
        assert iom.server_map is not None
        assert not iom.input_files
        assert not iom._environ_files
        assert iom._generated == 0
        assert iom._mime is None
        assert iom._report_size == 1
    finally:
        iom.cleanup()

def test_iomanager_02(tmp_path):
    """test IOManager.scan_input()"""
    iom = IOManager()
    try:
        # pass empty directory path
        iom.scan_input(str(tmp_path))
        assert not iom.input_files
        # create a test corpus
        (tmp_path / "input_01.bin").write_bytes(b"foo")
        (tmp_path / ".should_be_ignored").write_bytes(b"ignored")
        (tmp_path / "empty.BIN").touch()
        (tmp_path / "input_02.txt").write_bytes(b"bar")
        (tmp_path / "desktop.ini").write_bytes(b"ignored")
        nested = tmp_path / "nested"
        nested.mkdir()
        test_file = nested / "input_03.txt"
        test_file.write_bytes(b"test")
        # pass directory path
        iom.scan_input(str(tmp_path), sort=True)
        assert len(iom.input_files) == 3
        # pass directory path with filter
        iom.input_files = list()
        iom.scan_input(str(tmp_path), ["Bin"])
        assert len(iom.input_files) == 1
        # pass file path
        iom.input_files = list()
        iom.scan_input(str(test_file))
        assert len(iom.input_files) == 1
    finally:
        iom.cleanup()

def test_iomanager_03(tmp_path, mocker):
    """test IOManager._rotation_required()"""
    iom = IOManager()
    try:
        # don't pick a file because we don't have inputs
        assert not iom._rotation_required(0)
        assert not iom._rotation_required(1)
        # create a test corpus
        (tmp_path / "input_01.bin").write_bytes(b"foo")
        iom.scan_input(str(tmp_path))
        assert len(iom.input_files) == 1
        # skip rotation because we only have one input file
        iom._generated = 1
        iom.active_input = mocker.Mock(spec=InputFile)
        assert not iom._rotation_required(1)
        # add to test corpus
        (tmp_path / "input_02.text").write_bytes(b"bar")
        iom.input_files = list()  # hack to enable rescan
        iom.scan_input(str(tmp_path))
        assert len(iom.input_files) == 2
        # pick a file
        iom.active_input = None
        assert iom._rotation_required(10)
        # don't pick a file because of rotation
        iom._generated = 3
        iom.active_input = mocker.Mock(spec=InputFile)
        assert not iom._rotation_required(10)
        # pick a file because of rotation
        iom._generated = 2
        iom.active_input = mocker.Mock(spec=InputFile)
        assert iom._rotation_required(2)
        # pick a file because of single pass
        iom._generated = 1
        iom.active_input = mocker.Mock(spec=InputFile)
        assert iom._rotation_required(0)
    finally:
        iom.cleanup()

def test_iomanager_04():
    """test IOManager.page_name() & IOManager.redirect_page()"""
    iom = IOManager()
    try:
        assert iom.page_name() != iom.page_name(offset=1)
        next_page = iom.page_name(offset=1)
        redirect_page = iom.redirect_page()
        iom._generated += 1
        assert iom.page_name() == next_page
        assert iom.page_name() == redirect_page
    finally:
        iom.cleanup()

def test_iomanager_05():
    """test IOManager.landing_page()"""
    iom = IOManager()
    try:
        assert iom.landing_page() == iom.page_name()
        iom.harness = TestFile.from_data(b"data", "h.htm")
        assert iom.landing_page() == "h.htm"
    finally:
        iom.cleanup()

def test_iomanager_06(tmp_path):
    """test IOManager._add_suppressions()"""
    supp_file = tmp_path / "supp_file.txt"
    supp_file.write_bytes(b"# test\n")
    iom = IOManager()
    try:
        os.environ["ASAN_OPTIONS"] = "blah=1:suppressions='%s':foo=2" % (str(supp_file),)
        assert not iom._environ_files
        iom._add_suppressions()
        assert "asan.supp" in (x.file_name for x in iom._environ_files)
    finally:
        os.environ.pop("ASAN_OPTIONS", None)
        iom.cleanup()

def test_iomanager_07(tmp_path, mocker):
    """test IOManager.create_testcase()"""
    iom = IOManager()
    try:
        assert iom._generated == 0
        assert iom._report_size == 1
        assert not iom.input_files
        assert iom.active_input is None
        assert not iom.tests
        iom._tracked_env = {"TEST": "1"}
        iom._environ_files = [TestFile.from_data(b"data", "e.txt")]
        # without a harness, no input files
        tcase = iom.create_testcase("test-adapter", rotation_period=1)
        assert tcase is not None
        assert iom._generated == 1
        assert len(iom.tests) == 1
        assert not list(tcase.optional)
        # with a harness
        iom.harness = TestFile.from_data(b"data", "h.htm")
        tcase = iom.create_testcase("test-adapter")
        assert tcase is not None
        assert len(iom.tests) == 1
        assert iom._generated == 2
        assert "h.htm" in tcase.optional
        # rotate active_input (single pass style)
        test_file = tmp_path / "input_01.bin"
        test_file.write_bytes(b"bar")
        iom.scan_input(str(tmp_path))
        assert len(iom.input_files) == 1
        iom.active_input = mocker.Mock(spec=InputFile)
        tcase = iom.create_testcase("test-adapter", rotation_period=0)
        assert tcase is not None
        assert iom._generated == 3
        assert iom.active_input.file_name == str(test_file)
        assert not iom.input_files
        # choose active_input (unset)
        iom.scan_input(str(tmp_path))
        iom.active_input = None
        tcase = iom.create_testcase("test-adapter")
        assert tcase is not None
        assert iom._generated == 4
        assert iom.active_input.file_name == str(test_file)
    finally:
        iom.cleanup()

def test_iomanager_08():
    """test IOManager.tracked_environ()"""
    try:
        org_tracked = IOManager.TRACKED_ENVVARS
        IOManager.TRACKED_ENVVARS = ()
        os.environ["ASAN_OPTIONS"] = "blah='z:/a':detect_leaks=1:foo=2"
        os.environ["LSAN_OPTIONS"] = "detect_leaks='x:\\a.1':a=1"
        os.environ["TEST_GOOD"] = "PASS"
        os.environ["TEST_BAD"] = "FAIL"
        assert not IOManager.tracked_environ()
        IOManager.TRACKED_ENVVARS = ("ASAN_OPTIONS", "LSAN_OPTIONS", "TEST_GOOD", "TEST_MISSING")
        tracked = IOManager.tracked_environ()
        assert "TEST_BAD" not in tracked
        assert "ASAN_OPTIONS" in tracked
        assert tracked["ASAN_OPTIONS"] == "detect_leaks=1"
        assert "LSAN_OPTIONS" in tracked
        assert tracked["LSAN_OPTIONS"] == "detect_leaks='x:\\a.1'"
        assert "TEST_GOOD" in tracked
        assert tracked["TEST_GOOD"] == "PASS"
        IOManager.TRACKED_ENVVARS = ("ASAN_OPTIONS",)
        os.environ["ASAN_OPTIONS"] = "ignored=x"
        assert not IOManager.tracked_environ()
    finally:
        IOManager.TRACKED_ENVVARS = org_tracked
        os.environ.pop("ASAN_OPTIONS", None)
        os.environ.pop("LSAN_OPTIONS", None)
        os.environ.pop("TEST_GOOD", None)
        os.environ.pop("TEST_BAD", None)

def test_servermap_01():
    """test empty ServerMap"""
    srv_map = ServerMap()
    assert not srv_map.dynamic_responses
    assert not srv_map.includes
    assert not srv_map.redirects
    with pytest.raises(AssertionError) as exc:
        srv_map.reset()
    assert "At least one kwarg should be True" in str(exc.value)

def test_servermap_02():
    """test ServerMap dynamic responses"""
    def fake_cb():
        pass
    srv_map = ServerMap()
    srv_map.set_dynamic_response("url_01", fake_cb, mime_type="test/type")
    assert len(srv_map.dynamic_responses) == 1
    assert srv_map.dynamic_responses[0]["url"] == "url_01"
    assert srv_map.dynamic_responses[0]["mime"] == "test/type"
    assert callable(srv_map.dynamic_responses[0]["callback"])
    srv_map.set_dynamic_response("url_02", fake_cb, mime_type="foo")
    assert len(srv_map.dynamic_responses) == 2
    srv_map.remove_dynamic_response("url_02")
    assert len(srv_map.dynamic_responses) == 1
    srv_map.reset(dynamic_response=True)
    assert not srv_map.dynamic_responses

def test_servermap_03(tmp_path):
    """test ServerMap includes"""
    srv_map = ServerMap()
    with pytest.raises(IOError) as exc:
        srv_map.set_include("test_url", "no_dir")
    assert "'no_dir' does not exist" in str(exc.value)
    assert not srv_map.includes
    srv_map.set_include("url_01", str(tmp_path))
    assert len(srv_map.includes) == 1
    assert srv_map.includes[0][0] == "url_01"
    assert srv_map.includes[0][1] == str(tmp_path)
    srv_map.set_include("url_02", str(tmp_path))
    assert len(srv_map.includes) == 2
    srv_map.remove_include("url_02")
    assert len(srv_map.includes) == 1
    srv_map.reset(include=True)
    assert not srv_map.includes

def test_servermap_04():
    """test ServerMap redirects"""
    srv_map = ServerMap()
    srv_map.set_redirect("url_01", "test_file", required=True)
    assert len(srv_map.redirects) == 1
    assert srv_map.redirects[0]["url"] == "url_01"
    assert srv_map.redirects[0]["file_name"] == "test_file"
    assert srv_map.redirects[0]["required"]
    srv_map.set_redirect("url_02", "test_file", required=False)
    assert len(srv_map.redirects) == 2
    srv_map.remove_redirect("url_02")
    assert len(srv_map.redirects) == 1
    srv_map.reset(redirect=True)
    assert not srv_map.redirects
