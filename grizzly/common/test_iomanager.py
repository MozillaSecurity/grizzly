# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from .iomanager import IOManager
from .storage import TestFile


def test_iomanager_01():
    """test a simple IOManager"""
    with IOManager() as iom:
        assert iom.server_map is not None
        assert not iom._environ_files
        assert iom._generated == 0
        assert iom._report_size == 1

def test_iomanager_02():
    """test IOManager.page_name()"""
    with IOManager() as iom:
        assert iom.page_name() != iom.page_name(offset=1)
        next_page = iom.page_name(offset=1)
        iom._generated += 1
        assert iom.page_name() == next_page

def test_iomanager_03(mocker, tmp_path):
    """test IOManager._add_suppressions()"""
    mocker.patch.dict("grizzly.common.iomanager.environ", values={})
    with IOManager() as iom:
        assert not iom._environ_files
        supp_file = tmp_path / "supp_file.txt"
        supp_file.touch()
        mocker.patch.dict(
            "grizzly.common.iomanager.environ",
            values={
                "ASAN_OPTIONS": "blah=1:suppressions='%s':foo=2" % (str(supp_file),),
                "DEBUG": "1",
                "LSAN_OPTIONS": "nothing=1",
                "JUNK": "test"})
        iom._add_suppressions()
        assert "asan.supp" in (x.file_name for x in iom._environ_files)

def test_iomanager_04():
    """test IOManager.create_testcase()"""
    with IOManager() as iom:
        assert iom._generated == 0
        assert iom._report_size == 1
        assert not iom.tests
        assert not iom.server_map.dynamic
        assert not iom.server_map.include
        assert not iom.server_map.redirect
        iom._tracked_env = {"TEST": "1"}
        iom._environ_files = [TestFile.from_data(b"data", "e.txt")]
        # without a harness, no input files
        tcase = iom.create_testcase("test-adapter")
        assert tcase is not None
        assert iom._generated == 1
        assert len(iom.tests) == 1
        assert not any(tcase.optional)
        assert "grz_current_test" in iom.server_map.redirect
        assert iom.server_map.redirect["grz_current_test"].target == tcase.landing_page
        assert "grz_next_test" in iom.server_map.redirect
        assert "grz_harness" not in iom.server_map.dynamic
        # with a harness
        iom.harness = b"harness-data"
        tcase = iom.create_testcase("test-adapter")
        assert tcase is not None
        assert len(iom.tests) == 1
        assert iom._generated == 2
        assert "grz_current_test" in iom.server_map.redirect
        assert iom.server_map.redirect["grz_current_test"].target == tcase.landing_page
        assert "grz_next_test" in iom.server_map.redirect
        assert "grz_harness" in iom.server_map.dynamic

def test_iomanager_05(mocker):
    """test IOManager.tracked_environ()"""
    mocker.patch.dict("grizzly.common.iomanager.environ", values={})
    assert not IOManager.tracked_environ()
    mocker.patch.dict(
        "grizzly.common.iomanager.environ",
        values={
            "ASAN_OPTIONS": "blah='z:/a':detect_leaks=1:foo=2",
            "LSAN_OPTIONS": "detect_leaks='x:\\a.1':a=1",
            # should be added since it is in IOManager.TRACKED_ENVVARS
            "MOZ_CHAOSMODE": "1",
            # this should be skipped because it uses the FFPuppet debug
            "XPCOM_DEBUG_BREAK": "warn",
            "TEST_BAD": "FAIL"},
        clear=True)
    tracked = IOManager.tracked_environ()
    assert "TEST_BAD" not in tracked
    assert "XPCOM_DEBUG_BREAK" not in tracked
    assert "ASAN_OPTIONS" in tracked
    assert "MOZ_CHAOSMODE" in tracked
    assert tracked["ASAN_OPTIONS"] == "detect_leaks=1"
    assert "LSAN_OPTIONS" in tracked
    assert tracked["LSAN_OPTIONS"] == "detect_leaks='x:\\a.1'"
    mocker.patch.dict(
        "grizzly.common.iomanager.environ",
        values={"ASAN_OPTIONS": "ignored=x"},
        clear=True)
    assert not IOManager.tracked_environ()
