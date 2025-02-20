# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from importlib.metadata import PackageNotFoundError
from itertools import chain, count, repeat
from multiprocessing import Event, Process
from sqlite3 import IntegrityError

from pytest import mark, raises

from .utils import grz_tmp, interprocess_lock, package_version


def test_grz_tmp_01(mocker, tmp_path):
    """test grz_tmp()"""
    fake_tmp = tmp_path / "grizzly"
    mocker.patch("grizzly.common.utils.GRZ_TMP", new=fake_tmp)
    # create temp path
    assert not fake_tmp.is_dir()
    path = grz_tmp()
    assert path == fake_tmp
    assert path.is_dir()
    # create temp path (exists)
    assert grz_tmp() == fake_tmp
    # create temp path with sub directory
    path = grz_tmp("test1", "test2")
    assert path == fake_tmp / "test1" / "test2"
    assert path.is_dir()


def test_interprocess_lock_basic(mocker, tmp_path):
    """test interprocess_lock()"""
    mocker.patch("grizzly.common.utils.perf_counter", side_effect=count())
    mocker.patch("grizzly.common.utils.sleep", autospec=True)
    mocker.patch("grizzly.common.utils.LOCK_DB", new=tmp_path / "lock.db")

    # acquire and release
    with interprocess_lock("test"):
        pass

    fake_conn = mocker.patch("grizzly.common.utils.connect", autospec=True).return_value
    fake_conn.execute.side_effect = chain([None], repeat(IntegrityError))
    # fail to acquire
    with raises(RuntimeError, match="Failed to acquire"), interprocess_lock("test"):
        pass


# NOTE: this function must be at the top level to work on Windows
def _count(count_file, start_gate, steps):
    start_gate.wait()
    for _ in range(steps):
        with interprocess_lock("test"):
            value = int(count_file.read_text()) + 1
            count_file.write_text(str(value))


def test_interprocess_lock_multi_proc(mocker, tmp_path):
    """test interprocess_lock() with multiple processes"""
    mocker.patch("grizzly.common.utils.LOCK_DB", new=tmp_path / "lock.db")

    count_file = tmp_path / "count.txt"
    count_file.write_text("0")
    procs_steps = 20
    procs_count = 5
    start_gate = Event()
    procs = []
    for _ in range(procs_count):
        procs.append(Process(target=_count, args=(count_file, start_gate, procs_steps)))
        procs[-1].start()
    start_gate.set()
    for proc in procs:
        proc.join()
    assert int(count_file.read_text()) == procs_count * procs_steps


@mark.parametrize(
    "version, expected",
    [
        # missing package
        (PackageNotFoundError(), "unknown"),
        # success
        (("1.2.3",), "1.2.3"),
    ],
)
def test_package_version_01(mocker, version, expected):
    """test package_version()"""
    mocker.patch("grizzly.common.utils.version", autospec=True, side_effect=version)
    assert package_version("foo", default="unknown") == expected
