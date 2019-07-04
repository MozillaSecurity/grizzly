# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import unicode_literals
import re
import zipfile
import pytest
from grizzly.reduce.args import ReducerArgs, ReducerFuzzManagerIDArgs, ReducerFuzzManagerIDQualityArgs
from grizzly.reduce import reduce, crash, bucket, ReductionJob
from grizzly.common import ReduceStatus, reporter
from .test_common import BaseFakeReporter, FakeTarget
from .test_reduce import FakeInteresting


def test_parse_args(capsys, tmp_path):
    "test that grizzly.reduce args are accepted and validated"
    exe = tmp_path / "binary"
    inp = tmp_path / "input"

    # missing arg tests
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([])
    _, err = capsys.readouterr()
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([str(exe)])
    _, err = capsys.readouterr()

    # invalid binary tests
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([str(exe), str(inp)])
    _, err = capsys.readouterr()
    assert "error: file not found: %r" % (str(exe),) in err
    exe.mkdir()
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([str(exe), str(inp)])
    _, err = capsys.readouterr()
    assert "error: file not found: %r" % (str(exe),) in err
    exe.rmdir()
    exe.touch()

    # invalid input tests
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([str(exe), str(inp)])
    _, err = capsys.readouterr()
    assert "error: %r does not exist" % (str(inp),) in err
    inp.touch()
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([str(exe), str(inp)])
    _, err = capsys.readouterr()
    assert "error: Testcase should be a folder, zip, or html file" in err
    inp.unlink()
    with pytest.raises(SystemExit):
        ReducerFuzzManagerIDArgs().parse_args([str(exe), str(inp)])
    _, err = capsys.readouterr()
    assert "invalid int value" in err

    # valid binary & inputs
    (tmp_path / "input.zip").touch()
    zipf = tmp_path / "input.zip"
    ReducerArgs().parse_args([str(exe), str(zipf)])
    zipf.unlink()
    inp.mkdir()
    (inp / "test_info.txt").touch()
    ReducerArgs().parse_args([str(exe), str(inp)])
    ReducerFuzzManagerIDArgs().parse_args([str(exe), '123'])

    # sig/environ tests
    fname = tmp_path / "file.txt"
    for arg in ("--sig", "--environ"):
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([str(exe), str(inp), arg, str(fname)])
        _, err = capsys.readouterr()
        assert "error: file not found: %r" % (str(fname),) in err
        fname.mkdir()
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([str(exe), str(inp), arg, str(fname)])
        _, err = capsys.readouterr()
        assert "error: file not found: %r" % (str(fname),) in err
        fname.rmdir()
        fname.touch()
        ReducerArgs().parse_args([str(exe), str(inp), arg, str(fname)])
        fname.unlink()

    # repeat/min-crashes tests
    for arg in ("--repeat", "--min-crashes"):
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([str(exe), str(inp), arg, "abc"])
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([str(exe), str(inp), arg, "-1"])
        _, err = capsys.readouterr()
        assert "'%s' value must be positive" % (arg,) in err
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([str(exe), str(inp), arg, "0"])
        _, err = capsys.readouterr()
        assert "'%s' value must be positive" % (arg,) in err
        ReducerArgs().parse_args([str(exe), str(inp), arg, "1"])
        ReducerArgs().parse_args([str(exe), str(inp), arg, "10"])


def test_main(job, monkeypatch, tmp_path):  # noqa pylint: disable=redefined-outer-name
    "simple test that main functions"
    # uses the job fixture from test_reduce which reduces testcases to the string "required\n"
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)

    (tmp_path / "binary").touch()
    exe = tmp_path / "binary"
    (tmp_path / "input").mkdir()
    inp = tmp_path / "input"
    (inp / "test_info.txt").write_text("landing page: test.html")
    (inp / "test.html").write_text("fluff\nrequired\n")
    args = ReducerArgs().parse_args([str(exe), str(inp)])
    assert reduce.main(args) == 0


def test_main_prefs(monkeypatch, tmp_path):
    "cmd line prefs should override prefs in the testcase"
    monkeypatch.setattr(reduce, "Interesting", FakeInteresting)
    run_called = [0]

    class MyReductionJob(ReductionJob):

        def run(self, *args, **kwds):
            result = ReductionJob.run(self, *args, **kwds)
            with open(self.interesting.target.prefs) as prefs_fp:
                assert "main prefs" == prefs_fp.read()
            run_called[0] += 1
            return result

    status = ReduceStatus.start()
    job = MyReductionJob([], FakeTarget(), 60, False, False, 0, 1, 1, 3, 25, 60, status, None, False)
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)

    (tmp_path / "binary").touch()
    exe = tmp_path / "binary"
    (tmp_path / "input").mkdir()
    inp = tmp_path / "input"
    (inp / "test_info.txt").write_text("landing page: test.html")
    (inp / "prefs.js").write_text("test prefs")
    (inp / "test.html").write_text("fluff\nrequired\n")
    (tmp_path / "prefs.js").write_text("main prefs")
    args = ReducerArgs().parse_args([str(exe), str(inp),
                                     "-p", str(tmp_path / "prefs.js")])
    assert reduce.main(args) == 0
    assert run_called[0] == 1


def test_main_strategies(job, monkeypatch, tmp_path):  # noqa pylint: disable=redefined-outer-name
    "strategies list should be respected"
    # uses the job fixture from test_reduce which reduces testcases to the string "required\n"
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)
    report_data = {"num_reports": 0}

    class FakeReporter(BaseFakeReporter):

        def __init__(self, *args, **kwds):
            super(FakeReporter, self).__init__(*args, **kwds)
            self.report_path = "foo"

        def _submit(self, _report, test_cases):
            assert len(test_cases) == 1, "too many test_cases: %r" % (test_cases,)
            tc = test_cases[0]
            assert len(tc._files.required) == 1, \
                "too many test_files: %r" % (tc._files.required,)
            assert tc.landing_page == "test.html"
            assert tc._files.required[0].data == b"'xxrequired'\n"
            report_data["num_reports"] += 1
    monkeypatch.setattr(reduce, "FilesystemReporter", FakeReporter)

    (tmp_path / "binary").touch()
    exe = tmp_path / "binary"
    (tmp_path / "input").mkdir()
    inp = tmp_path / "input"
    (inp / "test_info.txt").write_text("landing page: test.html")
    (inp / "test.html").write_bytes(b"fluff\n'xxrequired'\n")
    args = ReducerArgs().parse_args([str(exe), str(inp), "--strategy", "line"])
    assert reduce.main(args) == 0
    assert report_data["num_reports"] == 1


def test_bucket_main(job, monkeypatch, tmp_path):  # noqa pylint: disable=redefined-outer-name
    "bucket.main iterates using crash.main"
    main_called = [0]

    class FakeCollector(object):
        serverProtocol = 'https'
        serverHost = 'mozilla.org'
        serverPort = 8000

        def get(self, url, **kwds):
            class response(object):
                @staticmethod
                def json():
                    if "crashes" in url:
                        return {
                            "results": [
                                {"testcase": None, "id": 123},
                                {"testcase": True, "id": 456},
                            ],
                            "next": None,
                            "count": 2,
                        }
                    else:
                        return {
                            "signature": '{"symptoms": []}',
                        }
            return response

    def crash_main(args):
        assert args.input == 456
        main_called[0] += 1
        return 0

    monkeypatch.setattr(bucket, "Collector", FakeCollector)
    monkeypatch.setattr(bucket, "reduce_crash", crash_main)

    (tmp_path / "binary").touch()
    exe = tmp_path / "binary"
    args = ReducerFuzzManagerIDQualityArgs().parse_args([str(exe), '789'])
    assert bucket.main(args) == 0
    assert main_called[0] == 1


def test_crash_main_repro(job, monkeypatch, tmp_path):  # noqa pylint: disable=redefined-outer-name
    "crash.main --fuzzmanager updates quality"
    # expect Collector.patch to be called with these qualities
    expect_patch = [reporter.FuzzManagerReporter.QUAL_REPRODUCIBLE,
                    reporter.FuzzManagerReporter.QUAL_REDUCED_ORIGINAL]
    submitted = [False]

    class ReporterNoSubmit(reporter.FuzzManagerReporter):
        (tmp_path / ".fuzzmanagerconf").touch()
        FM_CONFIG = str(tmp_path / ".fuzzmanagerconf")

        def _submit(self, *_args, **_kwds):
            # check that the crash was already marked reproducible, but not yet marked reduced
            assert expect_patch == [reporter.FuzzManagerReporter.QUAL_REDUCED_ORIGINAL]
            submitted[0] = True

    class FakeCollector(object):
        serverProtocol = 'https'
        serverHost = 'mozilla.org'
        serverPort = 8000

        def get(self, _url, **kwds):

            class response(object):

                class headers(object):

                    @staticmethod
                    def get(value, default):
                        assert value.lower() == 'content-disposition'
                        return 'attachment; filename="test.zip"'

                @staticmethod
                def json():
                    return {
                        'testcase_quality': reporter.FuzzManagerReporter.QUAL_UNREDUCED,
                        'tool': 'test-tool'}
                content = (inp / "test.zip").read_bytes()
            return response

        def patch(self, _url, **kwds):
            data = kwds["data"]
            assert set(data.keys()) == {"testcase_quality"}
            assert expect_patch
            assert data["testcase_quality"] == expect_patch.pop(0)

    # uses the job fixture from test_reduce which reduces testcases to the string "required\n"
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)
    monkeypatch.setattr(reporter, "Collector", FakeCollector)
    monkeypatch.setattr(reduce, "FuzzManagerReporter", ReporterNoSubmit)
    monkeypatch.setattr(crash, "Collector", FakeCollector)

    (tmp_path / "binary").touch()
    exe = tmp_path / "binary"
    (tmp_path / "binary.fuzzmanagerconf").write_text(
        "[Main]\n"
        "platform = x86-64\n"
        "product = mozilla-central\n"
        "os = linux\n"
    )
    (tmp_path / "input").mkdir()
    inp = tmp_path / "input"
    (inp / "test_info.txt").write_text("landing page: test.html")
    (inp / "test.html").write_text("fluff\nrequired\n")
    with zipfile.ZipFile(str(inp / "test.zip"), "w") as zip_fp:
        zip_fp.write(str(inp / "test_info.txt"), "test_info.txt")
        zip_fp.write(str(inp / "test.html"), "test.html")
    args = ReducerFuzzManagerIDArgs().parse_args([str(exe), '1234', '--fuzzmanager'])
    assert crash.main(args) == 0
    assert not expect_patch
    assert submitted[0]


def test_crash_main_no_repro(job, monkeypatch, tmp_path):  # noqa pylint: disable=redefined-outer-name
    "crash.main --fuzzmanager updates quality"
    expect_patch = [reporter.FuzzManagerReporter.QUAL_REQUEST_SPECIFIC]

    class ReporterNoSubmit(reporter.FuzzManagerReporter):
        (tmp_path / ".fuzzmanagerconf").touch()
        FM_CONFIG = str(tmp_path / ".fuzzmanagerconf")

        def _reset(self):
            pass

        def _submit(self, *_args, **_kwds):
            # make sure _submit() is not called
            assert False

    class FakeCollector(object):
        serverProtocol = 'https'
        serverHost = 'mozilla.org'
        serverPort = 8000

        def get(self, _url, **kwds):

            class response(object):

                class headers(object):

                    @staticmethod
                    def get(value, default):
                        assert value.lower() == 'content-disposition'
                        return 'attachment; filename="test.zip"'

                @staticmethod
                def json():
                    return {
                        'testcase_quality': reporter.FuzzManagerReporter.QUAL_UNREDUCED,
                        'tool': 'test-tool'}
                content = (inp / "test.zip").read_bytes()
            return response

        def patch(self, _url, **kwds):
            data = kwds["data"]
            assert set(data.keys()) == {"testcase_quality"}
            assert expect_patch
            assert data["testcase_quality"] == expect_patch.pop(0)

    # uses the job fixture from test_reduce which reduces testcases to the string "required\n"
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)
    monkeypatch.setattr(reporter, "Collector", FakeCollector)
    monkeypatch.setattr(reduce, "FuzzManagerReporter", ReporterNoSubmit)
    monkeypatch.setattr(crash, "Collector", FakeCollector)

    (tmp_path / "binary").touch()
    exe = tmp_path / "binary"
    (tmp_path / "binary.fuzzmanagerconf").write_text(
        "[Main]\n"
        "platform = x86-64\n"
        "product = mozilla-central\n"
        "os = linux\n"
    )
    (tmp_path / "input").mkdir()
    inp = tmp_path / "input"
    (inp / "test_info.txt").write_text("landing page: test.html")
    (inp / "test.html").write_text("fluff\n")
    with zipfile.ZipFile(str(inp / "test.zip"), "w") as zip_fp:
        zip_fp.write(str(inp / "test_info.txt"), "test_info.txt")
        zip_fp.write(str(inp / "test.html"), "test.html")
    args = ReducerFuzzManagerIDArgs().parse_args([str(exe), '1234', '--fuzzmanager'])
    assert crash.main(args) == 1
    assert not expect_patch


def test_crash_main_no_repro_specific(job, monkeypatch, tmp_path):  # noqa pylint: disable=redefined-outer-name
    "crash.main --fuzzmanager updates quality"
    expect_patch = [reporter.FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE]

    class ReporterNoSubmit(reporter.FuzzManagerReporter):
        (tmp_path / ".fuzzmanagerconf").touch()
        FM_CONFIG = str(tmp_path / ".fuzzmanagerconf")

        def _reset(self):
            pass

        def _submit(self, *_args, **_kwds):
            # make sure _submit() is not called
            assert False

    class FakeCollector(object):
        serverProtocol = 'https'
        serverHost = 'mozilla.org'
        serverPort = 8000

        def get(self, _url, **kwds):

            class response(object):

                class headers(object):

                    @staticmethod
                    def get(value, default):
                        assert value.lower() == 'content-disposition'
                        return 'attachment; filename="test.zip"'

                @staticmethod
                def json():
                    return {
                        'testcase_quality': reporter.FuzzManagerReporter.QUAL_REQUEST_SPECIFIC,
                        'tool': 'test-tool'}
                content = (inp / "test.zip").read_bytes()
            return response

        def patch(self, _url, **kwds):
            data = kwds["data"]
            assert set(data.keys()) == {"testcase_quality"}
            assert expect_patch
            assert data["testcase_quality"] == expect_patch.pop(0)

    # uses the job fixture from test_reduce which reduces testcases to the string "required\n"
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)
    monkeypatch.setattr(reporter, "Collector", FakeCollector)
    monkeypatch.setattr(reduce, "FuzzManagerReporter", ReporterNoSubmit)
    monkeypatch.setattr(crash, "Collector", FakeCollector)

    (tmp_path / "binary").touch()
    exe = tmp_path / "binary"
    (tmp_path / "binary.fuzzmanagerconf").write_text(
        "[Main]\n"
        "platform = x86-64\n"
        "product = mozilla-central\n"
        "os = linux\n"
    )
    (tmp_path / "input").mkdir()
    inp = tmp_path / "input"
    (inp / "test_info.txt").write_text("landing page: test.html")
    (inp / "test.html").write_text("fluff\n")
    with zipfile.ZipFile(str(inp / "test.zip"), "w") as zip_fp:
        zip_fp.write(str(inp / "test_info.txt"), "test_info.txt")
        zip_fp.write(str(inp / "test.html"), "test.html")
    args = ReducerFuzzManagerIDArgs().parse_args([str(exe), '1234', '--fuzzmanager'])
    assert crash.main(args) == 1
    assert not expect_patch


def test_environ_and_suppressions(monkeypatch, tmpdir):
    ""
    run_called = [0]

    class MyReductionJob(ReductionJob):

        def run(self, *args, **kwds):
            assert len(self.interesting.env_mod) == 2
            assert "GRZ_FORCED_CLOSE" in self.interesting.env_mod
            assert self.interesting.env_mod["GRZ_FORCED_CLOSE"] == "0"
            assert not self.interesting.target.forced_close
            assert "LSAN_OPTIONS" in self.interesting.env_mod
            assert len(re.split(r":(?![\\|/])", self.interesting.env_mod["LSAN_OPTIONS"])) == 2
            assert "detect_leaks=1" in self.interesting.env_mod["LSAN_OPTIONS"]
            assert "lsan.supp" in self.interesting.env_mod["LSAN_OPTIONS"]
            run_called[0] += 1

    status = ReduceStatus.start()
    job = MyReductionJob([], FakeTarget(), 60, False, False, 0, 1, 1, 3, 25, 60, status, None, False)
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)
    assert job.interesting.target.forced_close

    exe = tmpdir.ensure("binary")
    inp = tmpdir.ensure("input", dir=True)
    inp.ensure("env_vars.txt").write("LSAN_OPTIONS=detect_leaks=1\nGRZ_FORCED_CLOSE=0")
    inp.ensure("test_info.txt").write("landing page: test.html")
    inp.ensure("lsan.supp").write("foo")
    inp.ensure("test.html").write("fluff\nrequired\n")
    args = ReducerArgs().parse_args([exe.strpath, inp.strpath])
    reduce.main(args)
    assert run_called[0] == 1
