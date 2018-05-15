# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import pytest

from grizzly.reduce.args import ReducerArgs
from grizzly.reduce import reduce
from .test_reduce import job  # noqa pylint: disable=unused-import


def test_parse_args(capsys, tmpdir):
    "test that grizzly.reduce args are accepted and validated"
    exe = tmpdir.join("binary")
    inp = tmpdir.join("input")

    # missing arg tests
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([])
    _, err = capsys.readouterr()
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([exe.strpath])
    _, err = capsys.readouterr()

    # invalid binary tests
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([exe.strpath, inp.strpath])
    _, err = capsys.readouterr()
    assert "error: file not found: '%s'" % (exe.strpath,) in err
    exe.ensure(dir=True)
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([exe.strpath, inp.strpath])
    _, err = capsys.readouterr()
    assert "error: file not found: '%s'" % (exe.strpath,) in err
    exe.remove()
    exe.ensure()

    # invalid input tests
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([exe.strpath, inp.strpath])
    _, err = capsys.readouterr()
    assert "error: '%s' does not exist" % (inp.strpath,) in err
    inp.ensure()
    with pytest.raises(SystemExit):
        ReducerArgs().parse_args([exe.strpath, inp.strpath])
    _, err = capsys.readouterr()
    assert "error: Testcase should be a folder or zip" in err
    inp.remove()

    # valid binary & inputs
    zipf = tmpdir.ensure("input.zip")
    ReducerArgs().parse_args([exe.strpath, zipf.strpath])
    zipf.remove()
    inp.ensure(dir=True).ensure("test_info.txt")
    ReducerArgs().parse_args([exe.strpath, inp.strpath])

    # sig/environ tests
    fname = tmpdir.join("file.txt")
    for arg in ("--sig", "--environ"):
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, fname.strpath])
        _, err = capsys.readouterr()
        assert "error: file not found: '%s'" % (fname.strpath,) in err
        fname.ensure(dir=True)
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, fname.strpath])
        _, err = capsys.readouterr()
        assert "error: file not found: '%s'" % (fname.strpath,) in err
        fname.remove()
        fname.ensure()
        ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, fname.strpath])
        fname.remove()

    # repeat/min-crashes tests
    for arg in ("--repeat", "--min-crashes"):
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, "abc"])
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, "-1"])
        _, err = capsys.readouterr()
        assert "'%s' value must be positive" % (arg,) in err
        with pytest.raises(SystemExit):
            ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, "0"])
        _, err = capsys.readouterr()
        assert "'%s' value must be positive" % (arg,) in err
        ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, "1"])
        ReducerArgs().parse_args([exe.strpath, inp.strpath, arg, "10"])


def test_main(job, monkeypatch, tmpdir):  # noqa pylint: disable=redefined-outer-name
    # uses the job fixture from test_reduce which reduces testcases to the string "required\n"
    monkeypatch.setattr(reduce, "ReductionJob", lambda *a, **kw: job)

    exe = tmpdir.ensure("binary")
    inp = tmpdir.ensure("input", dir=True)
    inp.ensure("test_info.txt").write("landing page: test.html")
    inp.ensure("test.html").write("fluff\nrequired\n")
    args = ReducerArgs().parse_args([exe.strpath, inp.strpath])
    assert reduce.main(args) == 0
