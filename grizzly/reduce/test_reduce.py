# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import unicode_literals
import json
import os.path
import zipfile
import pytest
from grizzly.reduce import exceptions, interesting, strategies
from grizzly.common import FuzzManagerReporter
from .test_common import BaseFakeReporter, create_target_binary


class FakeInteresting(interesting.Interesting):
    """Stub to fake parts of grizzly.reduce.Interesting needed for testing the reduce loop"""

    def init(self, _):
        pass

    @property
    def location(self):
        return "127.0.0.1" if self.no_harness else "127.0.0.1/harness"

    def _run(self, _testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs, meta=True)
        with open(self.reduce_file) as fp:
            return "required" in fp.read()

    def cleanup(self, _):
        pass


class FakeInterestingAlt(FakeInteresting):
    """Version of FakeInteresting that only reports alternate crashes"""

    def init(self, _):
        self.__first_run = True

    def _run(self, testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs, meta=True)
        with open(self.reduce_file) as fp:
            if "required" in fp.read():
                self.alt_crash_cb(testcase, temp_prefix)
        if self.__first_run:
            self.__first_run = False
            return True
        return False


class FakeInterestingKeepHarness(FakeInteresting):
    """Version of FakeInteresting that keeps the entire harness"""

    def init(self, _):
        self.__init_data = None
        if os.path.basename(self.reduce_file).startswith("harness_"):
            with open(self.reduce_file) as harness_fp:
                self.__init_data = harness_fp.read()

    def _run(self, _testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs, meta=True)
        if self.__init_data is not None:
            with open(self.reduce_file) as fp:
                return self.__init_data == fp.read()
        else:
            with open(self.reduce_file) as fp:
                return "required" in fp.read()


class FakeInterestingSemiReliable(FakeInteresting):
    """Version of FakeInteresting that returns interesting N times only"""
    USE_ANALYZE = True

    def set_n(self, n, require_no_harness=False):
        self.interesting_times = n
        self.interesting_count = 0
        self.require_no_harness = require_no_harness

    def _run(self, _testcase, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs, meta=True)
        if self.require_no_harness and "harness" in self.location:
            return False
        self.interesting_count += 1
        return self.interesting_count <= self.interesting_times


class FakeInterestingSemiReliableWithCache(FakeInterestingSemiReliable):
    USE_TESTCASE_CACHE = True


def test_config_testcase_0(tmp_path, job):
    """empty directory fails config_testcase"""
    with pytest.raises(exceptions.NoTestcaseError) as exc:
        job.config_testcase(str(tmp_path))
    assert "No testcase recognized" in str(exc.value)
    assert job.result_code == FuzzManagerReporter.QUAL_NO_TESTCASE


def test_config_testcase_1(tmp_path, job):
    """non-zip file fails config_testcase"""
    tmp_file = tmp_path / "test.txt"
    tmp_file.touch()
    with pytest.raises(exceptions.ReducerError) as exc:
        job.config_testcase(str(tmp_file))
    assert "Testcase must be zip, html, or directory" in str(exc.value)
    tmp_file.unlink()
    assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_2(tmp_path, job):
    """config_testcase can't be called twice"""
    with pytest.raises(exceptions.ReducerError) as exc:
        job.config_testcase(str(tmp_path))
    with pytest.raises(exceptions.ReducerError) as exc:
        job.config_testcase(str(tmp_path))
    assert "Testcase already configured?" in str(exc.value)
    assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_3(tmp_path, job):
    """bad zip file fails config_testcase"""
    test_zip = tmp_path / "test.zip"
    test_zip.touch()
    with pytest.raises(exceptions.CorruptTestcaseError):
        job.config_testcase(str(test_zip))
    assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_4(tmp_path, job):
    """missing landing page causes failure"""
    (tmp_path / "test_info.json").write_text("{}")
    with pytest.raises(exceptions.ReducerError) as exc:
        job.config_testcase(str(tmp_path))
    assert "Could not find landing page" in str(exc.value)
    assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_4_legacy(tmp_path, job):
    """missing landing page causes failure"""
    # TODO: remove this test
    (tmp_path / "test_info.txt").touch()
    with pytest.raises(exceptions.ReducerError) as exc:
        job.config_testcase(str(tmp_path))
    assert "Could not find landing page" in str(exc.value)
    assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_5(tmp_path, job):
    """missing landing page causes failure"""
    (tmp_path / "test_info.json").write_text("{\"target\":\"\",\"env\":{}}")
    with pytest.raises(exceptions.ReducerError) as exc:
        job.config_testcase(str(tmp_path))
    assert "does not exist" in str(exc.value)
    assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_5_legacy(tmp_path, job):
    """missing landing page causes failure"""
    # TODO: remove this test
    (tmp_path / "test_info.txt").write_text("landing page: ")
    with pytest.raises(exceptions.ReducerError) as exc:
        job.config_testcase(str(tmp_path))
    assert "does not exist" in str(exc.value)
    assert job.result_code == FuzzManagerReporter.QUAL_REDUCER_ERROR


def test_config_testcase_6(tmp_path, job):
    """single testcase is loaded ok"""
    (tmp_path / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path))
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_config_testcase_6_legacy(tmp_path, job):
    """single testcase is loaded ok"""
    # TODO: remove this test
    (tmp_path / "test_info.txt").write_text("landing page: test.html")
    (tmp_path / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path))
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_config_testcase_7(tmp_path, job):
    """single testcase in numbered subdir is loaded ok"""
    (tmp_path / "-0").mkdir()
    (tmp_path / "-0" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "-0" / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path))
    assert job.testcase == os.path.join(job.tcroot, "-0", "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_config_testcase_7_legacy(tmp_path, job):
    """single testcase in numbered subdir is loaded ok"""
    # TODO: remove this test
    (tmp_path / "-0").mkdir()
    (tmp_path / "-0" / "test_info.txt").write_text("landing page: test.html")
    (tmp_path / "-0" / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path))
    assert job.testcase == os.path.join(job.tcroot, "-0", "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_config_testcase_8(tmp_path, job):
    """multiple testcase in numbered subdir creates a harness"""
    for subdir in ("-0", "-1"):
        (tmp_path / subdir).mkdir()
        (tmp_path / subdir / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
        (tmp_path / subdir / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path))
    assert job.testcase.startswith(os.path.join(job.tcroot, "harness_"))
    assert job.testcase.endswith(".html")
    for subdir in ("-0", "-1"):
        with open(os.path.join(job.tcroot, subdir, "test.html")) as tc_fp:
            assert tc_fp.read() == "hello"
    with open(job.testcase) as tc_fp:
        harness = tc_fp.read()
    loc0 = harness.index("'/-0/test.html',")
    loc1 = harness.index("'/-1/test.html',")
    assert loc1 < loc0, "testcases should occur in harness in descending order"
    assert job.result_code is None


def test_config_testcase_8_legacy(tmp_path, job):
    """multiple testcase in numbered subdir creates a harness"""
    # TODO: remove this test
    for subdir in ("-0", "-1"):
        (tmp_path / subdir).mkdir()
        (tmp_path / subdir / "test_info.txt").write_text("landing page: test.html")
        (tmp_path / subdir / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path))
    assert job.testcase.startswith(os.path.join(job.tcroot, "harness_"))
    assert job.testcase.endswith(".html")
    for subdir in ("-0", "-1"):
        with open(os.path.join(job.tcroot, subdir, "test.html")) as tc_fp:
            assert tc_fp.read() == "hello"
    with open(job.testcase) as tc_fp:
        harness = tc_fp.read()
    loc0 = harness.index("'/-0/test.html',")
    loc1 = harness.index("'/-1/test.html',")
    assert loc1 < loc0, "testcases should occur in harness in descending order"
    assert job.result_code is None


def test_config_testcase_9(tmp_path, job):
    """single testcase is loaded from zip ok"""
    (tmp_path / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "test.html").write_text("hello")
    with zipfile.ZipFile(str(tmp_path / "test.zip"), "w") as zip_fp:
        zip_fp.write(str(tmp_path / "test_info.json"), "test_info.json")
        zip_fp.write(str(tmp_path / "test.html"), "test.html")
    job.config_testcase(str(tmp_path / "test.zip"))
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_config_testcase_9_legacy(tmp_path, job):
    """single testcase is loaded from zip ok"""
    # TODO: remove this test
    (tmp_path / "test_info.txt").write_text("landing page: test.html")
    (tmp_path / "test.html").write_text("hello")
    with zipfile.ZipFile(str(tmp_path / "test.zip"), "w") as zip_fp:
        zip_fp.write(str(tmp_path / "test_info.txt"), "test_info.txt")
        zip_fp.write(str(tmp_path / "test.html"), "test.html")
    job.config_testcase(str(tmp_path / "test.zip"))
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_config_testcase_10(tmp_path, job):
    """prefs from testcase are used and take precedence over target prefs"""
    (tmp_path / "orig_prefs.js").write_text("orig prefs")
    job.interesting.target.prefs = str(tmp_path / "orig_prefs.js")
    (tmp_path / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "test.html").write_text("hello")
    (tmp_path / "prefs.js").write_text("some prefs")
    job.config_testcase(str(tmp_path))
    assert os.path.normpath(job.interesting.target.prefs) \
        != os.path.normpath(str(tmp_path / "prefs.js"))
    with open(job.interesting.target.prefs) as prefs_fp:
        assert prefs_fp.read() == "some prefs"
    assert job.result_code is None


def test_config_testcase_10_legacy(tmp_path, job):
    """prefs from testcase are used and take precedence over target prefs"""
    # TODO: remove this test
    (tmp_path / "orig_prefs.js").write_text("orig prefs")
    job.interesting.target.prefs = str(tmp_path / "orig_prefs.js")
    (tmp_path / "test_info.txt").write_text("landing page: test.html")
    (tmp_path / "test.html").write_text("hello")
    (tmp_path / "prefs.js").write_text("some prefs")
    job.config_testcase(str(tmp_path))
    assert os.path.normpath(job.interesting.target.prefs) \
        != os.path.normpath(str(tmp_path / "prefs.js"))
    with open(job.interesting.target.prefs) as prefs_fp:
        assert prefs_fp.read() == "some prefs"
    assert job.result_code is None


def test_config_testcase_11(tmp_path, job):
    """env vars from testcase are used"""
    with open(str(tmp_path / "test_info.json"), "w") as info:
        json.dump({
            "target": "test.html",
            "env": {
                "foo": "bar",
                "var": "value"
            }}, info)
    (tmp_path / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path))
    assert job.interesting.env_mod == dict(var="value", foo="bar")
    assert job.result_code is None


def test_config_testcase_11_legacy(tmp_path, job):
    """env vars from testcase are used"""
    # TODO: remove this test
    (tmp_path / "test_info.txt").write_text("landing page: test.html")
    (tmp_path / "test.html").write_text("hello")
    (tmp_path / "env_vars.txt").write_text("var=value\nfoo=bar")
    job.config_testcase(str(tmp_path))
    assert job.interesting.env_mod == dict(var="value", foo="bar")
    assert job.result_code is None


def test_config_testcase_12(tmp_path, job):
    """html testcase is loaded ok"""
    (tmp_path / "test.html").write_text("hello")
    job.config_testcase(str(tmp_path / "test.html"))
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_config_testcase_13(tmp_path, job):
    """test test_info.json not test_info.txt is used"""
    # TODO: remove this test
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
    assert job.interesting.env_mod == dict(var="value", foo="bar")
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"
    assert job.result_code is None


def test_run_0(tmp_path, job):
    """single required testcase is reduced and reported"""
    create_target_binary(job.interesting.target, tmp_path)
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
        def _submit(self, _report, test_cases):
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
            assert tc._env_vars == dict(var="value", foo="bar")
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


@pytest.mark.parametrize("job", [FakeInterestingAlt], indirect=["job"])
def test_run_1(tmp_path, job):
    """other crashes are reported as unreduced crashes"""
    create_target_binary(job.interesting.target, tmp_path)
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
        def _submit(self, _report, test_cases):
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
            assert tc._env_vars == dict(var="value", foo="bar")
            assert self.quality == FuzzManagerReporter.QUAL_UNREDUCED
            assert not self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert not job.run()
    assert report_data["num_reports"] == 1


def test_run_2(tmp_path, job):
    """other files in testcase are not reduced without DDBEGIN/END"""
    create_target_binary(job.interesting.target, tmp_path)
    (tmp_path / "tc").mkdir()
    (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "tc" / "test.html").write_bytes(b"fluff\nrequired\n")
    (tmp_path / "tc" / "test2.html").write_bytes(b"fluff\nrequired\n")
    job.config_testcase(str(tmp_path / "tc"))
    report_data = {"num_reports": 0}

    class FakeReporter(BaseFakeReporter):
        def _submit(self, _report, test_cases):
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
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


def test_run_3(tmp_path, job):
    """other files in testcase are reduced with DDBEGIN/END"""
    create_target_binary(job.interesting.target, tmp_path)
    (tmp_path / "tc").mkdir()
    (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "tc" / "test.html").write_bytes(b"fluff\nrequired\n")
    (tmp_path / "tc" / "test2.html").write_bytes(b"DDBEGIN\nfluff\nrequired\nDDEND\n")
    job.config_testcase(str(tmp_path / "tc"))
    report_data = {"num_reports": 0}

    class FakeReporter(BaseFakeReporter):
        def _submit(self, _report, test_cases):
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
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


@pytest.mark.parametrize("job", [FakeInterestingKeepHarness], indirect=["job"])
def test_run_4(tmp_path, job):
    """multiple testcases result in harness being reported"""
    create_target_binary(job.interesting.target, tmp_path)
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
        def _submit(self, _report, test_cases):
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
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


def test_run_5(tmp_path, job):
    """multiple testcases reducing to 1 file will have harness removed"""
    create_target_binary(job.interesting.target, tmp_path)
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
        def _submit(self, _report, test_cases):
            assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
            tc = test_cases[0]
            assert len(tc._files.required) == 1, \
                "too many test_files: %r" % (tc._files.required,)
            assert tc.landing_page == "required.html"
            assert tc._files.required[0].data == b"-1\nDDBEGIN\nrequired\nDDEND\n"
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


@pytest.mark.skipif(not strategies.HAVE_JSBEAUTIFIER, reason="jsbeautifier required")
def test_run_6(tmp_path, job):
    """test that jsbeautifier stage works"""
    create_target_binary(job.interesting.target, tmp_path)
    (tmp_path / "tc").mkdir()
    (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.js\",\"env\":{}}")
    (tmp_path / "tc" / "test.js").write_text("try{'fluff';'required'}catch(e){}\n")
    job.config_testcase(str(tmp_path / "tc"))
    report_data = {"num_reports": 0}

    class FakeReporter(BaseFakeReporter):
        def _submit(self, _report, test_cases):
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
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1

def test_run_7(tmp_path, job):
    """test that jschar stage works"""
    create_target_binary(job.interesting.target, tmp_path)
    (tmp_path / "tc").mkdir()
    (tmp_path / "tc" / "test_info.json").write_bytes(b"{\"target\":\"test.js\",\"env\":{}}")
    (tmp_path / "tc" / "test.js").write_bytes(b"var x = 'xrequiredx'\n")
    job.config_testcase(str(tmp_path / "tc"))
    report_data = {"num_reports": 0}

    class FakeReporter(BaseFakeReporter):
        def _submit(self, _report, test_cases):
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
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


@pytest.mark.parametrize("job", [FakeInterestingSemiReliable], indirect=["job"])
def test_run_8(tmp_path, job):
    """test that analyze stage works"""
    create_target_binary(job.interesting.target, tmp_path)
    (tmp_path / "tc").mkdir()
    (tmp_path / "tc" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "tc" / "test.html").write_text("fluff\nrequired\n")
    (tmp_path / "tc" / "prefs.js").write_text("some prefs")
    (tmp_path / "tc" / "env_vars.txt").write_text("var=value\nfoo=bar")
    job.config_testcase(str(tmp_path / "tc"))

    job.reporter = BaseFakeReporter()

    # try a 50% reliable testcase
    job.interesting.min_crashes = 1
    job.interesting.repeat = 1
    job.interesting.set_n(5)
    job.run()
    assert job.interesting.min_crashes == 2
    assert job.interesting.repeat == 10
    assert not job.interesting.no_harness

    # try a 90% reliable testcase
    job.interesting.min_crashes = 1
    job.interesting.repeat = 1
    job.interesting.set_n(9)
    job.run()
    assert job.interesting.min_crashes == 2
    assert job.interesting.repeat == 4
    assert not job.interesting.no_harness

    # try a 100% reliable testcase that doesn't repro with the harness
    job.interesting.min_crashes = 1
    job.interesting.repeat = 1
    job.interesting.set_n(11, require_no_harness=True)
    job.run()
    assert job.interesting.min_crashes == 2
    assert job.interesting.repeat == 2
    assert job.interesting.no_harness


@pytest.mark.parametrize("job", [FakeInterestingSemiReliableWithCache], indirect=["job"])
def test_run_9(tmp_path, job):
    """test that analyze stage works with multiple testcases"""
    create_target_binary(job.interesting.target, tmp_path)
    (tmp_path / "tc").mkdir()
    (tmp_path / "tc" / "-0").mkdir()
    (tmp_path / "tc" / "-1").mkdir()
    (tmp_path / "tc" / "-0" / "test_info.json").write_text("{\"target\":\"test.html\",\"env\":{}}")
    (tmp_path / "tc" / "-0" / "test.html").write_text("-0\nDDBEGIN\nfluff\nrequired\nDDEND\n")
    (tmp_path / "tc" / "-1" / "test_info.json").write_text("{\"target\":\"required.html\",\"env\":{}}")
    (tmp_path / "tc" / "-1" / "required.html").write_text("-1\nDDBEGIN\nfluff\nrequired\nDDEND\n")
    job.config_testcase(str(tmp_path / "tc"))

    job.reporter = BaseFakeReporter()

    job.interesting.min_crashes = 1
    job.interesting.repeat = 1
    job.interesting.set_n(5)
    job.run()
    assert job.interesting.min_crashes == 2
    assert job.interesting.repeat == 10
    assert not job.interesting.no_harness
