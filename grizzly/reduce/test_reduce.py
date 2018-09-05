# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import logging
import os.path
import zipfile
import pytest

from grizzly.reduce import interesting, reduce, strategies, ReducerError, ReductionJob
from grizzly.reporter import Reporter, FuzzManagerReporter
from grizzly.target import Target

from .test_common import FakeTarget, create_target_binary


logging.basicConfig(level=logging.DEBUG)


class FakeInteresting(interesting.Interesting):
    "Stub to fake parts of grizzly.reduce.Interesting needed for testing the reduce loop"

    def init(self, _):
        pass

    def _run(self, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs, meta=True)
        with open(self.reduce_file) as fp:
            return "required" in fp.read()

    def cleanup(self, _):
        pass


class FakeInterestingAlt(FakeInteresting):
    "Version of FakeInteresting that only reports alternate crashes"

    def init(self, _):
        self.__first_run = True

    def _run(self, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs, meta=True)
        with open(self.reduce_file) as fp:
            if "required" in fp.read():
                self.alt_crash_cb(temp_prefix)
        if self.__first_run:
            self.__first_run = False
            return True
        return False


class FakeInterestingKeepHarness(FakeInteresting):
    "Version of FakeInteresting that keeps the entire harness"

    def init(self, _):
        self.__init_data = None
        if os.path.basename(self.reduce_file).startswith("harness_"):
            with open(self.reduce_file) as harness_fp:
                self.__init_data = harness_fp.read()

    def _run(self, temp_prefix):
        result_logs = temp_prefix + "_logs"
        os.mkdir(result_logs)
        self.target.save_logs(result_logs, meta=True)
        if self.__init_data is not None:
            with open(self.reduce_file) as fp:
                return self.__init_data == fp.read()
        else:
            with open(self.reduce_file) as fp:
                return "required" in fp.read()


@pytest.fixture
def job(monkeypatch, request):
    "Pytest fixture to provide a ReductionJob object with dependencies stubbed and default values"
    interesting_cls = getattr(request, "param", FakeInteresting)
    monkeypatch.setattr(reduce, "Interesting", interesting_cls)
    result = ReductionJob([], FakeTarget(), 60, False, False, 0, 1, 1, 3, 25, 60, None, False)
    yield result
    result.close()


def test_config_testcase_0(tmpdir, job):
    "empty directory fails config_testcase"
    with pytest.raises(ReducerError) as exc:
        job.config_testcase(tmpdir.strpath)
    assert "No testcase recognized" in str(exc)


def test_config_testcase_1(tmpdir, job):
    "non-zip file fails config_testcase"
    file = tmpdir.join("test.txt")
    file.ensure(file=True)
    with pytest.raises(ReducerError) as exc:
        job.config_testcase(file.strpath)
    assert "Testcase must be zip, html, or directory" in str(exc)
    file.remove()


def test_config_testcase_2(tmpdir, job):
    "config_testcase can't be called twice"
    with pytest.raises(ReducerError) as exc:
        job.config_testcase(tmpdir.strpath)
    with pytest.raises(ReducerError) as exc:
        job.config_testcase(tmpdir.strpath)
    assert "Testcase already configured?" in str(exc)


def test_config_testcase_3(tmpdir, job):
    "bad zip file fails config_testcase"
    file = tmpdir.join("test.zip")
    file.ensure(file=True)
    with pytest.raises(zipfile.error):
        job.config_testcase(file.strpath)


def test_config_testcase_4(tmpdir, job):
    "missing landing page causes failure"
    file = tmpdir.join("test_info.txt")
    file.ensure(file=True)
    with pytest.raises(ReducerError) as exc:
        job.config_testcase(tmpdir.strpath)
    assert "Could not find landing page" in str(exc)


def test_config_testcase_5(tmpdir, job):
    "missing landing page causes failure"
    file = tmpdir.join("test_info.txt")
    file.write("landing page: ")
    with pytest.raises(ReducerError) as exc:
        job.config_testcase(tmpdir.strpath)
    assert "Landing page"
    assert "does not exist" in str(exc)


def test_config_testcase_6(tmpdir, job):
    "single testcase is loaded ok"
    file = tmpdir.join("test_info.txt")
    file.write("landing page: test.html")
    tmpdir.join("test.html").write("hello")
    job.config_testcase(tmpdir.strpath)
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"


def test_config_testcase_7(tmpdir, job):
    "single testcase in numbered subdir is loaded ok"
    tmpdir.join("-0").ensure(dir=True)
    file = tmpdir.join("-0", "test_info.txt")
    file.write("landing page: test.html")
    tmpdir.join("-0", "test.html").write("hello")
    job.config_testcase(tmpdir.strpath)
    assert job.testcase == os.path.join(job.tcroot, "-0", "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"


def test_config_testcase_8(tmpdir, job):
    "multiple testcase in numbered subdir creates a harness"
    for subdir in ("-0", "-1"):
        tmpdir.join(subdir).ensure(dir=True)
        file = tmpdir.join(subdir, "test_info.txt")
        file.write("landing page: test.html")
        tmpdir.join(subdir, "test.html").write("hello")
    job.config_testcase(tmpdir.strpath)
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


def test_config_testcase_9(tmpdir, job):
    "single testcase is loaded from zip ok"
    file = tmpdir.join("test_info.txt")
    file.write("landing page: test.html")
    tmpdir.join("test.html").write("hello")
    with zipfile.ZipFile(tmpdir.join("test.zip").strpath, "w") as zip_fp:
        zip_fp.write(tmpdir.join("test_info.txt").strpath, "test_info.txt")
        zip_fp.write(tmpdir.join("test.html").strpath, "test.html")
    job.config_testcase(tmpdir.join("test.zip").strpath)
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"


def test_config_testcase_10(tmpdir, job):
    "prefs from testcase are used and take precedence over target prefs"
    tmpdir.join("orig_prefs.js").write("orig prefs")
    job.interesting.target.prefs = tmpdir.join("orig_prefs.js").strpath
    file = tmpdir.join("test_info.txt")
    file.write("landing page: test.html")
    tmpdir.join("test.html").write("hello")
    tmpdir.join("prefs.js").write("some prefs")
    job.config_testcase(tmpdir.strpath)
    assert os.path.normpath(job.interesting.target.prefs) \
        != os.path.normpath(tmpdir.join("prefs.js").strpath)
    with open(job.interesting.target.prefs) as prefs_fp:
        assert prefs_fp.read() == "some prefs"


def test_config_testcase_11(tmpdir, job):
    "env vars from testcase are used"
    file = tmpdir.join("test_info.txt")
    file.write("landing page: test.html")
    tmpdir.join("test.html").write("hello")
    tmpdir.join("env_vars.txt").write("var=value\nfoo=bar")
    job.config_testcase(tmpdir.strpath)
    assert job.interesting.env_mod == dict(var="value", foo="bar")


def test_config_testcase_12(tmpdir, job):
    "html testcase is loaded ok"
    tmpdir.join("test.html").write("hello")
    job.config_testcase(tmpdir.join("test.html").strpath)
    assert job.testcase == os.path.join(job.tcroot, "test.html")
    with open(job.testcase) as tc_fp:
        assert tc_fp.read() == "hello"


def test_run_0(tmpdir, job):
    "single required testcase is reduced and reported"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc", "test_info.txt").write("landing page: test.html")
    tmpdir.join("tc", "test.html").write("fluff\nrequired\n")
    tmpdir.join("tc", "prefs.js").write("some prefs")
    tmpdir.join("tc", "env_vars.txt").write("var=value\nfoo=bar")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 1, \
                "too many test_files: %r" % (tc._files["required"],)
            assert tc.landing_page == "test.html"
            assert tc._files["required"][0].data == "required\n"
            prefs_data = None
            for meta_file in tc._files["meta"]:
                if meta_file.file_name == "prefs.js":
                    prefs_data = meta_file.data
                    break
            assert prefs_data == "some prefs"
            assert tc._env_vars == dict(var="value", foo="bar")
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


@pytest.mark.parametrize("job", [FakeInterestingAlt], indirect=["job"])
def test_run_1(tmpdir, job):
    "other crashes are reported as unreduced crashes"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc", "test_info.txt").write("landing page: test.html")
    tmpdir.join("tc", "test.html").write("fluff\nrequired\n")
    tmpdir.join("tc", "prefs.js").write("some prefs")
    tmpdir.join("tc", "env_vars.txt").write("var=value\nfoo=bar")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 1, \
                "too many test_files: %r" % (tc._files["required"],)
            assert tc._files["required"][0].data == "required\n"
            assert tc.landing_page == "test.html"
            prefs_data = None
            for meta_file in tc._files["meta"]:
                if meta_file.file_name == "prefs.js":
                    prefs_data = meta_file.data
                    break
            assert prefs_data == "some prefs"
            assert tc._env_vars == dict(var="value", foo="bar")
            assert self.quality == FuzzManagerReporter.QUAL_UNREDUCED
            assert not self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert not job.run()
    assert report_data["num_reports"] == 1


def test_run_2(tmpdir, job):
    "other files in testcase are not reduced without DDBEGIN/END"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc", "test_info.txt").write("landing page: test.html")
    tmpdir.join("tc", "test.html").write("fluff\nrequired\n")
    tmpdir.join("tc", "test2.html").write("fluff\nrequired\n")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 2, \
                "expecting 2 test_files: %r" % (tc._files["required"],)
            assert tc.landing_page == "test.html"
            assert {x.file_name: x.data for x in tc._files["required"]} \
                == {"test.html": "required\n",
                    "test2.html": "fluff\nrequired\n"}
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


def test_run_3(tmpdir, job):
    "other files in testcase are reduced with DDBEGIN/END"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc", "test_info.txt").write("landing page: test.html")
    tmpdir.join("tc", "test.html").write("fluff\nrequired\n")
    tmpdir.join("tc", "test2.html").write("DDBEGIN\nfluff\nrequired\nDDEND\n")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 2, \
                "expecting 2 test_files: %r" % (tc._files["required"],)
            assert tc.landing_page == "test.html"
            assert {x.file_name: x.data for x in tc._files["required"]} \
                == {"test.html": "required\n",
                    "test2.html": "DDBEGIN\nrequired\nDDEND\n"}
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


@pytest.mark.parametrize("job", [FakeInterestingKeepHarness], indirect=["job"])
def test_run_4(tmpdir, job):
    "multiple testcases result in harness being reported"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc").ensure("-0", dir=True)
    tmpdir.join("tc").ensure("-1", dir=True)
    tmpdir.join("tc", "-0", "test_info.txt").write("landing page: required.html")
    tmpdir.join("tc", "-0", "required.html").write("DDBEGIN\nfluff\nrequired\nDDEND\n")
    tmpdir.join("tc", "-1", "test_info.txt").write("landing page: required.html")
    tmpdir.join("tc", "-1", "required.html").write("DDBEGIN\nfluff\nrequired\nDDEND\n")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 3, \
                "expecting 3 test_files: %r" % (tc._files["required"],)
            assert tc.landing_page.startswith("harness_")
            assert tc.landing_page.endswith(".html")
            harness_idx = [x.file_name for x in tc._files["required"]].index(tc.landing_page)
            harness = tc._files["required"].pop(harness_idx)
            assert {x.file_name: x.data for x in tc._files["required"]} \
                == {"-0/required.html": "DDBEGIN\nrequired\nDDEND\n",
                    "-1/required.html": "DDBEGIN\nrequired\nDDEND\n"}
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


def test_run_5(tmpdir, job):
    "multiple testcases reducing to 1 file will have harness removed"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc").ensure("-0", dir=True)
    tmpdir.join("tc").ensure("-1", dir=True)
    tmpdir.join("tc", "-0", "test_info.txt").write("landing page: test.html")
    tmpdir.join("tc", "-0", "test.html").write("-0\nDDBEGIN\nfluff\nrequired\nDDEND\n")
    tmpdir.join("tc", "-1", "test_info.txt").write("landing page: required.html")
    tmpdir.join("tc", "-1", "required.html").write("-1\nDDBEGIN\nfluff\nrequired\nDDEND\n")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 1, \
                "too many test_files: %r" % (tc._files["required"],)
            assert tc.landing_page == "required.html"
            assert tc._files["required"][0].data == "-1\nDDBEGIN\nrequired\nDDEND\n"
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


@pytest.mark.skipif(not strategies.HAVE_JSBEAUTIFIER, reason="jsbeautifier required")
def test_run_6(tmpdir, job):
    "test that jsbeautifier stage works"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc", "test_info.txt").write("landing page: test.js")
    tmpdir.join("tc", "test.js").write("try{'fluff';'required'}catch(e){}\n")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 1, \
                "too many test_files: %r" % (tc._files["required"],)
            assert tc.landing_page == "test.js"
            assert tc._files["required"][0].data.lstrip(' ') == "'required'\n"
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1


def test_run_7(tmpdir, job):
    "test that jschar stage works"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.ensure("tc", dir=True)
    tmpdir.join("tc", "test_info.txt").write("landing page: test.js")
    tmpdir.join("tc", "test.js").write("var x = 'xrequiredx'\n")
    job.config_testcase(tmpdir.join("tc").strpath)
    report_data = {"num_reports": 0}

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            tc = self.test_cases[0]
            assert len(tc._files["required"]) == 1, \
                "too many test_files: %r" % (tc._files["required"],)
            assert tc.landing_page == "test.js"
            # strip() is required because jsbeautifier stage removes the newline (if installed)
            assert tc._files["required"][0].data.strip() == "var x = 'required'"
            assert self.quality == FuzzManagerReporter.QUAL_REDUCED_RESULT
            assert self.force_report
            report_data["num_reports"] += 1
    job.reporter = FakeReporter()

    assert job.run()
    assert report_data["num_reports"] == 1
