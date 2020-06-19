# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from __future__ import unicode_literals
import json
import os.path
import zipfile
import pytest
from grizzly.reduce import exceptions, strategies
from grizzly.common import FuzzManagerReporter
from .test_common import BaseFakeReporter, TestReductionJob
from .test_common import TestReductionJobAlt, TestReductionJobKeepHarness, TestReductionJobSemiReliable


def test_config_testcase_0(tmp_path):
    """empty directory fails config_testcase"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        with pytest.raises(exceptions.NoTestcaseError) as exc:
            job.config_testcase(str(tmp_path))
        assert "No testcase recognized" in str(exc.value)
        assert job.result_code == FuzzManagerReporter.QUAL_NO_TESTCASE


def test_config_testcase_1(tmp_path):
    """non-zip file fails config_testcase"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        tmp_file = tmp_path / "test.txt"
        tmp_file.touch()
        with pytest.raises(exceptions.ReducerError) as exc:
            job.config_testcase(str(tmp_file))
        assert "Testcase must be zip, html, or directory" in str(exc.value)
        tmp_file.unlink()
        assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_2(tmp_path):
    """config_testcase can't be called twice"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        with pytest.raises(exceptions.ReducerError) as exc:
            job.config_testcase(str(tmp_path))
        with pytest.raises(exceptions.ReducerError) as exc:
            job.config_testcase(str(tmp_path))
        assert "Testcase already configured?" in str(exc.value)
        assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_3(tmp_path):
    """bad zip file fails config_testcase"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        test_zip = tmp_path / "test.zip"
        test_zip.touch()
        with pytest.raises(exceptions.CorruptTestcaseError):
            job.config_testcase(str(test_zip))
        assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_4(tmp_path):
    """missing landing page causes failure"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.json").write_text("{}")
        with pytest.raises(exceptions.ReducerError) as exc:
            job.config_testcase(str(tmp_path))
        assert "Could not find landing page" in str(exc.value)
        assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_4_legacy(tmp_path):
    """missing landing page causes failure"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.txt").touch()
        with pytest.raises(exceptions.ReducerError) as exc:
            job.config_testcase(str(tmp_path))
        assert "Could not find landing page" in str(exc.value)
        assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_5(tmp_path):
    """missing landing page causes failure"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.json").write_text("{\"target\":\"\",\"env\":{}}")
        with pytest.raises(exceptions.ReducerError) as exc:
            job.config_testcase(str(tmp_path))
        assert "does not exist" in str(exc.value)
        assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_5_legacy(tmp_path):
    """missing landing page causes failure"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.txt").write_text("landing page: ")
        with pytest.raises(exceptions.ReducerError) as exc:
            job.config_testcase(str(tmp_path))
        assert "does not exist" in str(exc.value)
        assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_6(tmp_path):
    """single testcase is loaded ok"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._testcase == os.path.join(job._tcroot, "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_config_testcase_6_legacy(tmp_path):
    """single testcase is loaded ok"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.txt").write_text("landing page: test.html")
        (tmp_path / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._testcase == os.path.join(job._tcroot, "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_config_testcase_7(tmp_path):
    """single testcase in numbered subdir is loaded ok"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "-0").mkdir()
        (tmp_path / "-0" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "-0" / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._testcase == os.path.join(job._tcroot, "-0", "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_config_testcase_7_legacy(tmp_path):
    """single testcase in numbered subdir is loaded ok"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "-0").mkdir()
        (tmp_path / "-0" / "test_info.txt").write_text("landing page: test.html")
        (tmp_path / "-0" / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._testcase == os.path.join(job._tcroot, "-0", "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_config_testcase_8(tmp_path):
    """multiple testcase in numbered subdir creates a harness"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        for subdir in ("-0", "-1"):
            (tmp_path / subdir).mkdir()
            (tmp_path / subdir / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
            (tmp_path / subdir / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._testcase.startswith(os.path.join(job._tcroot, "harness_"))
        assert job._testcase.endswith(".html")
        for subdir in ("-0", "-1"):
            with open(os.path.join(job._tcroot, subdir, "test.html")) as tc_fp:
                assert tc_fp.read() == "hello"
        with open(job._testcase) as tc_fp:
            harness = tc_fp.read()
        loc0 = harness.index("'/-0/test.html',")
        loc1 = harness.index("'/-1/test.html',")
        assert loc1 < loc0, "testcases should occur in harness in descending order"
        assert job.result_code is None


def test_config_testcase_8_legacy(tmp_path):
    """multiple testcase in numbered subdir creates a harness"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        for subdir in ("-0", "-1"):
            (tmp_path / subdir).mkdir()
            (tmp_path / subdir / "test_info.txt").write_text("landing page: test.html")
            (tmp_path / subdir / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._testcase.startswith(os.path.join(job._tcroot, "harness_"))
        assert job._testcase.endswith(".html")
        for subdir in ("-0", "-1"):
            with open(os.path.join(job._tcroot, subdir, "test.html")) as tc_fp:
                assert tc_fp.read() == "hello"
        with open(job._testcase) as tc_fp:
            harness = tc_fp.read()
        loc0 = harness.index("'/-0/test.html',")
        loc1 = harness.index("'/-1/test.html',")
        assert loc1 < loc0, "testcases should occur in harness in descending order"
        assert job.result_code is None


def test_config_testcase_9(tmp_path):
    """single testcase is loaded from zip ok"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "test.html").write_text("hello")
        with zipfile.ZipFile(str(tmp_path / "test.zip"), "w") as zip_fp:
            zip_fp.write(str(tmp_path / "test_info.json"), "test_info.json")
            zip_fp.write(str(tmp_path / "test.html"), "test.html")
        job.config_testcase(str(tmp_path / "test.zip"))
        assert job._testcase == os.path.join(job._tcroot, "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_config_testcase_9_legacy(tmp_path):
    """single testcase is loaded from zip ok"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.txt").write_text("landing page: test.html")
        (tmp_path / "test.html").write_text("hello")
        with zipfile.ZipFile(str(tmp_path / "test.zip"), "w") as zip_fp:
            zip_fp.write(str(tmp_path / "test_info.txt"), "test_info.txt")
            zip_fp.write(str(tmp_path / "test.html"), "test.html")
        job.config_testcase(str(tmp_path / "test.zip"))
        assert job._testcase == os.path.join(job._tcroot, "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_config_testcase_10(tmp_path):
    """prefs from testcase are used and take precedence over target prefs"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "orig_prefs.js").write_text("orig prefs")
        job.target.prefs = str(tmp_path / "orig_prefs.js")
        (tmp_path / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "test.html").write_text("hello")
        (tmp_path / "prefs.js").write_text("some prefs")
        job.config_testcase(str(tmp_path))
        assert os.path.normpath(job.target.prefs) \
            != os.path.normpath(str(tmp_path / "prefs.js"))
        with open(job.target.prefs) as prefs_fp:
            assert prefs_fp.read() == "some prefs"
        assert job.result_code is None


def test_config_testcase_10_legacy(tmp_path):
    """prefs from testcase are used and take precedence over target prefs"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "orig_prefs.js").write_text("orig prefs")
        job.target.prefs = str(tmp_path / "orig_prefs.js")
        (tmp_path / "test_info.txt").write_text("landing page: test.html")
        (tmp_path / "test.html").write_text("hello")
        (tmp_path / "prefs.js").write_text("some prefs")
        job.config_testcase(str(tmp_path))
        assert os.path.normpath(job.target.prefs) \
            != os.path.normpath(str(tmp_path / "prefs.js"))
        with open(job.target.prefs) as prefs_fp:
            assert prefs_fp.read() == "some prefs"
        assert job.result_code is None


def test_config_testcase_11(tmp_path):
    """env vars from testcase are used"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        with open(str(tmp_path / "test_info.json"), "w") as info:
            json.dump({
                "target": "test.html",
                "env": {
                    "foo": "bar",
                    "var": "value"
                }}, info)
        (tmp_path / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._env_mod == dict(var="value", foo="bar")
        assert job.result_code is None


def test_config_testcase_11_legacy(tmp_path):
    """env vars from testcase are used"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.txt").write_text("landing page: test.html")
        (tmp_path / "test.html").write_text("hello")
        (tmp_path / "env_vars.txt").write_text("var=value\nfoo=bar")
        job.config_testcase(str(tmp_path))
        assert job._env_mod == dict(var="value", foo="bar")
        assert job.result_code is None


def test_config_testcase_12(tmp_path):
    """html testcase is loaded ok"""
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path / "test.html"))
        assert job._testcase == os.path.join(job._tcroot, "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_config_testcase_13(tmp_path):
    """test test_info.json not test_info.txt is used"""
    # TODO: remove this test
    with TestReductionJob(tmp_path, create_binary=False) as job:
        (tmp_path / "test_info.txt").write_text("landing page: test_old.html")
        (tmp_path / "test_old.html").write_text("fail!")
        (tmp_path / "env_vars.txt").write_text("var=fail\nfoo=fail")
        with open(str(tmp_path / "test_info.json"), "w") as info:
            json.dump({
                "target": "test.html",
                "env": {
                    "foo": "bar",
                    "var": "value"
                }}, info)
        (tmp_path / "test.html").write_text("hello")
        job.config_testcase(str(tmp_path))
        assert job._env_mod == dict(var="value", foo="bar")
        assert job._testcase == os.path.join(job._tcroot, "test.html")
        with open(job._testcase) as tc_fp:
            assert tc_fp.read() == "hello"
        assert job.result_code is None


def test_run_01(tmp_path):
    """single required testcase is reduced and reported"""
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        with open(str(tmp_path / "tc" / "test_info.json"), "w") as info:
            json.dump({
                "target": "test.html",
                "env": {
                    "foo": "bar",
                    "var": "value"
                }}, info)
        (tmp_path / "tc" / "test.html").write_bytes(b"fluff\nrequired\n")
        (tmp_path / "tc" / "prefs.js").write_bytes(b"some prefs")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "too many test_files: %r" % (tc._files.required,)
                assert tc.landing_page == "test.html"
                assert tc._files.required[0].data == b"required\n"
                prefs_data = None
                for meta_file in tc._files.meta:
                    if meta_file.file_name == "prefs.js":
                        prefs_data = meta_file.data
                        break
                assert prefs_data == b"some prefs"
                assert tc.env_vars == dict(var="value", foo="bar")
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1


def test_run_02(tmp_path):
    """other crashes are reported as unreduced crashes"""
    with TestReductionJobAlt(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        with open(str(tmp_path / "tc" / "test_info.json"), "w") as info:
            json.dump({
                "target": "test.html",
                "env": {
                    "foo": "bar",
                    "var": "value"
                }}, info)
        (tmp_path / "tc" / "test.html").write_bytes(b"fluff\nrequired\n")
        (tmp_path / "tc" / "prefs.js").write_bytes(b"some prefs")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "too many test_files: %r" % (tc._files.required,)
                assert tc._files.required[0].data == b"required\n"
                assert tc.landing_page == "test.html"
                prefs_data = None
                for meta_file in tc._files.meta:
                    if meta_file.file_name == "prefs.js":
                        prefs_data = meta_file.data
                        break
                assert prefs_data == b"some prefs"
                assert tc.env_vars == dict(var="value", foo="bar")
                assert self.quality == FuzzManagerReporter.QUAL_UNREDUCED
                assert not self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert not job.run()
        assert report_data["num_reports"] == 1


def test_run_03(tmp_path):
    """other files in testcase are not reduced without DDBEGIN/END"""
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "tc" / "test.html").write_bytes(b"fluff\nrequired\n")
        (tmp_path / "tc" / "test2.html").write_bytes(b"fluff\nrequired\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "expecting 1 test_file: %r" % ({f.file_name for f in tc._files.required},)
                assert len(tc._files.optional) == 1, \
                    "expecting 1 test_file: %r" % ({f.file_name for f in tc._files.optional},)
                assert tc.landing_page == "test.html"
                assert {x.file_name: x.data for x in tc._files.required} \
                    == {"test.html": b"required\n"}
                assert {x.file_name: x.data for x in tc._files.optional} \
                    == {"test2.html": b"fluff\nrequired\n"}
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1


def test_run_04(tmp_path):
    """other files in testcase are reduced with DDBEGIN/END"""
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "tc" / "test.html").write_bytes(b"fluff\nrequired\n")
        (tmp_path / "tc" / "test2.html").write_bytes(b"DDBEGIN\nfluff\nrequired\nDDEND\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "expecting 1 test file: %r" % (tc._files.required,)
                assert len(tc._files.optional) == 1, \
                    "expecting 1 test file: %r" % (tc._files.optional,)
                assert tc.landing_page == "test.html"
                assert {x.file_name: x.data for x in tc._files.required} \
                    == {"test.html": b"required\n"}
                assert {x.file_name: x.data for x in tc._files.optional} \
                    == {"test2.html": b"DDBEGIN\nrequired\nDDEND\n"}
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1


def test_run_05(tmp_path):
    """multiple testcases result in harness being reported"""
    with TestReductionJobKeepHarness(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "-0").mkdir()
        (tmp_path / "tc" / "-1").mkdir()
        (tmp_path / "tc" / "-0" / "test_info.json").write_text("{\"target\":\"required.html\",\"env\":{}}")
        (tmp_path / "tc" / "-0" / "required.html").write_bytes(b"DDBEGIN\nfluff\nrequired\nDDEND\n")
        (tmp_path / "tc" / "-1" / "test_info.json").write_text("{\"target\":\"required.html\",\"env\":{}}")
        (tmp_path / "tc" / "-1" / "required.html").write_bytes(b"DDBEGIN\nfluff\nrequired\nDDEND\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "expecting 1 test file: %r" % (tc._files.required,)
                assert len(tc._files.optional) == 2, \
                    "expecting 2 test files: %r" % (tc._files.optional,)
                assert tc.landing_page.startswith("harness_")
                assert tc.landing_page.endswith(".html")
                assert {x.file_name: x.data for x in tc._files.optional} \
                    == {os.path.join("-0", "required.html"): b"DDBEGIN\nrequired\nDDEND\n",
                        os.path.join("-1", "required.html"): b"DDBEGIN\nrequired\nDDEND\n"}
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1


def test_run_06(tmp_path):
    """multiple testcases reducing to 1 file will have harness removed"""
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "-0").mkdir()
        (tmp_path / "tc" / "-1").mkdir()
        (tmp_path / "tc" / "-0" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "tc" / "-0" / "test.html").write_bytes(b"-0\nDDBEGIN\nfluff\nrequired\nDDEND\n")
        (tmp_path / "tc" / "-1" / "test_info.json").write_text("{\"target\":\"required.html\",\"env\":{}}")
        (tmp_path / "tc" / "-1" / "required.html").write_bytes(b"-1\nDDBEGIN\nfluff\nrequired\nDDEND\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "too many test_files: %r" % (tc._files.required,)
                assert tc.landing_page == "required.html"
                assert tc._files.required[0].data == b"-1\nDDBEGIN\nrequired\nDDEND\n"
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1


@pytest.mark.skipif(not strategies.HAVE_JSBEAUTIFIER, reason="jsbeautifier required")
def test_run_07(tmp_path):
    """test that jsbeautifier stage works"""
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.js\",\"env\":{}}")
        (tmp_path / "tc" / "test.js").write_text("try{'fluff';'required'}catch(e){}\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "too many test_files: %r" % (tc._files.required,)
                assert tc.landing_page == "test.js"
                result = tc._files.required[0].data.decode("UTF-8").lstrip(" ")
                assert result == "'required'%s" % (str(os.linesep),)
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1


@pytest.mark.skipif(not strategies.HAVE_CSSBEAUTIFIER, reason="cssbeautifier required")
def test_run_08(tmp_path):
    """test that cssbeautifier stage works with .css file"""
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.css\",\"env\":{}}")
        (tmp_path / "tc" / "test.css").write_text("*,#a{fluff:0;required:1}\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "too many test_files: %r" % (tc._files.required,)
                assert tc.landing_page == "test.css"
                result = tc._files.required[0].data.decode("UTF-8").rstrip()
                assert result == "  required: 1"
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1

@pytest.mark.skipif(not strategies.HAVE_CSSBEAUTIFIER, reason="cssbeautifier required")
def test_run_09(tmp_path):
    """test that cssbeautifier stage works with .html file"""
    # TODO: tests specifically targeting beautifiers should be created
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "tc" / "test.html").write_text("<style>*,#a{fluff:0;required:1}</style>\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "too many test_files: %r" % (tc._files.required,)
                assert tc.landing_page == "test.html"
                result = tc._files.required[0].data.decode("UTF-8").rstrip()
                assert result == "  required: 1"
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1

def test_run_10(tmp_path):
    """test that jschar stage works"""
    with TestReductionJob(tmp_path) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "test_info.json").write_bytes(b"{\"target\":\"test.js\",\"env\":{}}")
        (tmp_path / "tc" / "test.js").write_bytes(b"var x = 'xrequiredx'\n")
        job.config_testcase(str(tmp_path / "tc"))
        report_data = {"num_reports": 0}

        class FakeReporter(BaseFakeReporter):
            def _submit_report(self, _report, test_cases):
                assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
                tc = test_cases[0]
                assert len(tc._files.required) == 1, \
                    "too many test_files: %r" % (tc._files.required,)
                assert tc.landing_page == "test.js"
                # strip() is required because jsbeautifier stage removes the newline (if installed)
                result = tc._files.required[0].data.decode("UTF-8").strip()
                assert result == "var x = 'required'"
                assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
                assert self.force_report
                report_data["num_reports"] += 1
        job.set_reporter(FakeReporter())

        assert job.run()
        assert report_data["num_reports"] == 1


def test_run_11(tmp_path):
    """test that analyze stage works"""
    with TestReductionJobSemiReliable(tmp_path, skip_analysis=False) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "tc" / "test.html").write_text("fluff\nrequired\n")
        (tmp_path / "tc" / "prefs.js").write_text("some prefs")
        (tmp_path / "tc" / "env_vars.txt").write_text("var=value\nfoo=bar")
        job.config_testcase(str(tmp_path / "tc"))

        job.set_reporter(BaseFakeReporter())

        # try a 50% reliable testcase
        with job.analysis_mode() as params:
            job.test_set_n(5)
            job.run()
            assert params.min_crashes == 2
            assert params.repeat == 10
            assert not params.no_harness

        # try a 90% reliable testcase
        with job.analysis_mode() as params:
            job.test_set_n(9)
            job.run()
            assert params.min_crashes == 2
            assert params.repeat == 4
            assert not params.no_harness

        # try a 100% reliable testcase that doesn't repro with the harness
        with job.analysis_mode() as params:
            job.test_set_n(11, require_no_harness=True)
            job.run()
            assert params.min_crashes == 2
            assert params.repeat == 2
            assert params.no_harness


def test_run_12(tmp_path):
    """test that analyze stage works with multiple testcases"""
    with TestReductionJobSemiReliable(tmp_path, testcase_cache=True, skip_analysis=False) as job:
        (tmp_path / "tc").mkdir()
        (tmp_path / "tc" / "-0").mkdir()
        (tmp_path / "tc" / "-1").mkdir()
        (tmp_path / "tc" / "-0" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / "tc" / "-0" / "test.html").write_text("-0\nDDBEGIN\nfluff\nrequired\nDDEND\n")
        (tmp_path / "tc" / "-1" / "test_info.json").write_text("{\"target\":\"required.html\",\"env\":{}}")
        (tmp_path / "tc" / "-1" / "required.html").write_text("-1\nDDBEGIN\nfluff\nrequired\nDDEND\n")
        job.config_testcase(str(tmp_path / "tc"))

        job.set_reporter(BaseFakeReporter())

        with job.analysis_mode() as params:
            params.min_crashes = 1
            params.repeat = 1
            job.test_set_n(5)
            job.run()
            assert params.min_crashes == 2
            assert params.repeat == 10
            assert not params.no_harness
