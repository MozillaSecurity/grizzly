import logging
import os.path
import zipfile
import pytest

from grizzly.reduce import reduce, ReducerError, ReductionJob
from grizzly.reporter import Reporter
from grizzly.target import Target


logging.basicConfig(level=logging.DEBUG)


class FakeInteresting(reduce.Interesting):

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


class FakeTarget(object):
    closed = True
    prefs = None

    class _puppet(object):

        @staticmethod
        def is_healthy():
            return False

    def save_logs(self, dest, **kwds):
        with open(os.path.join(dest, "log_stdout.txt"), "w") as log_fp:
            log_fp.write("STDOUT")
        with open(os.path.join(dest, "log_stderr.txt"), "w") as log_fp:
            log_fp.write("STDERR")

    def launch(self, *args, **kwds):
        pass

    def check_relaunch(self):
        pass

    def close(self):
        pass

    def cleanup(self):
        pass

    def detect_failure(self, *args, **kwds):
        return Target.RESULT_FAILURE


@pytest.fixture
def job(monkeypatch):
    monkeypatch.setattr(reduce, "Interesting", FakeInteresting)
    job = ReductionJob([], FakeTarget(), 60, False, False, 0, 1, 1, 3, 25, 60, False)
    yield job
    job.close()


def create_target_binary(target, tmpdir):
    tmpdir.join("firefox.fuzzmanagerconf").write(
        "[Main]\n"
        "platform = x86-64\n"
        "product = mozilla-central\n"
        "os = linux\n"
    )
    target.binary = tmpdir.join("firefox").strpath


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
    assert "Testcase must be zip or directory" in str(exc)
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


def test_run_0(tmpdir, job):
    "single required testcase is reduced and reported"
    create_target_binary(job.interesting.target, tmpdir)
    tmpdir.join("tc").ensure(dir=True)
    tmpdir.join("tc", "test_info.txt").write("landing page: test.html")
    tmpdir.join("tc", "test.html").write("fluff\nrequired\n")
    job.config_testcase(tmpdir.join("tc").strpath)

    class FakeReporter(Reporter):
        def _submit(self):
            assert len(self.test_cases) == 1, "too many test_cases: %r" % (self.test_cases,)
            assert len(self.test_cases[0]._test_files) == 1, \
                "too many test_files: %r" % (self.test_cases[0]._test_files,)
            assert self.test_cases[0]._test_files[0].data == "required\n"
    job.reporter = FakeReporter()

    assert job.run()
