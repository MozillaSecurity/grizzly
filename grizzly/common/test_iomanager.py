# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from .iomanager import IOManager
from .storage import InputFile, TestFile


def test_iomanager_01():
    """test a simple IOManager"""
    with IOManager() as iom:
        assert not iom.input_files
        assert iom.active_input is None
        assert iom.server_map is not None
        assert not iom.input_files
        assert not iom._environ_files
        assert iom._generated == 0
        assert iom._mime is None
        assert iom._report_size == 1

def test_iomanager_02(tmp_path):
    """test IOManager.scan_input()"""
    with IOManager() as iom:
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

def test_iomanager_03(tmp_path, mocker):
    """test IOManager._rotation_required()"""
    with IOManager() as iom:
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

def test_iomanager_04():
    """test IOManager.page_name()"""
    with IOManager() as iom:
        assert iom.page_name() != iom.page_name(offset=1)
        next_page = iom.page_name(offset=1)
        iom._generated += 1
        assert iom.page_name() == next_page

def test_iomanager_05():
    """test IOManager.landing_page()"""
    with IOManager() as iom:
        assert iom.landing_page() == iom.page_name()
        iom.harness = TestFile.from_data(b"data", "h.htm")
        assert iom.landing_page() == "h.htm"

def test_iomanager_06(mocker, tmp_path):
    """test IOManager._add_suppressions()"""
    fake_os = mocker.patch("grizzly.common.iomanager.os", autospec=True)
    fake_os.environ = {}
    with IOManager() as iom:
        assert not iom._environ_files
        supp_file = tmp_path / "supp_file.txt"
        supp_file.touch()
        fake_os.environ = {
            "ASAN_OPTIONS": "blah=1:suppressions='%s':foo=2" % (str(supp_file),),
            "DEBUG": "1",
            "JUNK": "test"}
        iom._add_suppressions()
        assert "asan.supp" in (x.file_name for x in iom._environ_files)

def test_iomanager_07(tmp_path, mocker):
    """test IOManager.create_testcase()"""
    with IOManager() as iom:
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
        assert not any(tcase.optional)
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

def test_iomanager_08(mocker):
    """test IOManager.tracked_environ()"""
    fake_os = mocker.patch("grizzly.common.iomanager.os", autospec=True)
    fake_os.environ = {}
    assert not IOManager.tracked_environ()
    fake_os.environ = {
        "ASAN_OPTIONS": "blah='z:/a':detect_leaks=1:foo=2",
        "LSAN_OPTIONS": "detect_leaks='x:\\a.1':a=1",
        "TEST_BAD": "FAIL"}
    tracked = IOManager.tracked_environ()
    assert "TEST_BAD" not in tracked
    assert "ASAN_OPTIONS" in tracked
    assert tracked["ASAN_OPTIONS"] == "detect_leaks=1"
    assert "LSAN_OPTIONS" in tracked
    assert tracked["LSAN_OPTIONS"] == "detect_leaks='x:\\a.1'"
    fake_os.environ = {"ASAN_OPTIONS": "ignored=x"}
    assert not IOManager.tracked_environ()
