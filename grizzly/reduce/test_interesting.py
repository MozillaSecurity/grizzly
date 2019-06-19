# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import unicode_literals
import os
import time
import pytest
import ffpuppet
import sapphire
from grizzly.reduce.interesting import Interesting
from grizzly.target.target import Target
from .test_common import FakeTarget, FakeReduceStatus, create_target_binary


class FakeServer(object):
    _last_timeout = None

    def __init__(self, **kwds):
        FakeServer._last_timeout = kwds.get("timeout")

    def close(self):
        pass

    def get_port(self):
        return 8000

    def add_dynamic_response(self, *args, **kwds):
        pass

    def set_redirect(self, *args, **kwds):
        pass

    def serve_testcase(self, *args, **kwds):
        return sapphire.SERVED_ALL, []

    def serve_path(self, *args, **kwds):
        return sapphire.SERVED_ALL, []


@pytest.fixture
def fake_sapphire(monkeypatch):
    monkeypatch.setattr(sapphire, "Sapphire", FakeServer)
    FakeServer._last_timeout = None


@pytest.fixture
def fake_timesleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda x: None)


pytestmark = pytest.mark.usefixtures("fake_sapphire", "fake_timesleep")


def test_interesting(tmp_path):
    "simple case where the test is interesting"
    obj = Interesting([], FakeTarget(), 30, False, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus())
    create_target_binary(obj.target, tmp_path)
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    (tmp_path / "lithium").mkdir()
    assert obj.interesting(None, str(tmp_path / "lithium"))
    assert obj.server is None
    assert obj.target._calls["close"] == 1
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0
    assert obj.target._calls["detect_failure"] == 1


def test_not_interesting(tmp_path):
    "simple case where the test is not interesting"

    class MyTarget(FakeTarget):

        def detect_failure(self, *args, **kwds):
            FakeTarget.detect_failure(self, *args, **kwds)
            return Target.RESULT_NONE

    obj = Interesting([], MyTarget(), 30, False, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus())
    create_target_binary(obj.target, tmp_path)
    obj.target._is_healthy = True
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    (tmp_path / "lithium").mkdir()
    assert not obj.interesting(None, str(tmp_path / "lithium"))
    assert obj.server is not None
    assert obj.target._calls["close"] == 0
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0
    assert obj.target._calls["detect_failure"] == 1


def test_ignored(tmp_path):
    "if target says ignored, it's not interesting"

    class MyTarget(FakeTarget):

        def detect_failure(self, ignored, *args, **kwds):
            FakeTarget.detect_failure(self, *args, **kwds)
            assert ignored == ["foo", "bar"]
            return Target.RESULT_IGNORED

    obj = Interesting(["foo", "bar"], MyTarget(), 30, False, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus())
    create_target_binary(obj.target, tmp_path)
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    (tmp_path / "lithium").mkdir()
    assert not obj.interesting(None, str(tmp_path / "lithium"))
    assert obj.server is not None
    assert obj.target._calls["close"] == 1
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0
    assert obj.target._calls["detect_failure"] == 1


def test_target_relaunch(tmp_path):
    "target should be launched more than once on error"

    class MyTarget(FakeTarget):

        def launch(self, *args, **kwds):
            FakeTarget.launch(self, *args, **kwds)
            raise ffpuppet.LaunchError()

    obj = Interesting([], MyTarget(), 30, False, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus())
    create_target_binary(obj.target, tmp_path)
    prefix = tmp_path / "lithium"
    prefix.mkdir()
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    with pytest.raises(ffpuppet.LaunchError):
        obj.interesting(None, str(prefix))
    assert obj.server is not None
    assert obj.target._calls["launch"] > 1
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_no_harness(tmp_path):
    "simple case where harness is not used"
    obj = Interesting([], FakeTarget(), 30, True, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus())
    create_target_binary(obj.target, tmp_path)
    prefix = tmp_path / "lithium"
    prefix.mkdir()
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    assert obj.interesting(None, str(prefix))
    assert obj.server is None
    assert obj.target._calls["close"] == 1
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0
    assert obj.target._calls["detect_failure"] == 1


def test_skip(tmp_path):
    "skip should assume interesting for the first n calls, without launching the target"
    obj = Interesting([], FakeTarget(), 30, False, False, 7, 1, 1, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    # first call is real, regardless of skip, since that is the initial repro
    prefix = tmp_path / "lithium0"
    prefix.mkdir()
    assert obj.interesting(None, str(prefix))
    assert obj.target._calls["launch"] == 1
    assert obj.target._calls["close"] == 1
    assert obj.server is None
    for _ in range(7):
        assert not obj.interesting(None, None)
    assert obj.target._calls["launch"] == 1
    prefix = tmp_path / "lithium1"
    prefix.mkdir()
    assert obj.interesting(None, str(prefix))
    assert obj.target._calls["launch"] == 2
    assert obj.target._calls["close"] == 2
    assert obj.server is not None
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_any_crash_false(tmp_path):
    "subsequent crashes must match the original if any_crash is False"
    stderr = "Assertion failure: bad thing happened, at test.c:123"

    class MyTarget(FakeTarget):

        def save_logs(self, dest, **kwds):
            FakeTarget.save_logs(self, dest, **kwds)
            with open(os.path.join(dest, "log_stderr.txt"), "w") as log_fp:
                log_fp.write(stderr)

    obj = Interesting([], MyTarget(), 30, False, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    # first call is real, regardless of skip, since that is the initial repro
    prefix = tmp_path / "lithium0"
    prefix.mkdir()
    assert obj.interesting(None, str(prefix))
    assert obj.target._calls["launch"] == 1
    assert obj.target._calls["close"] == 1
    assert obj.server is None
    prefix = tmp_path / "lithium1"
    prefix.mkdir()
    stderr = "Assertion failure: some other thing happened, at test.c:456"
    assert not obj.interesting(None, str(prefix))  # doesn't match original sig
    assert obj.target._calls["launch"] == 2
    assert obj.target._calls["close"] == 2
    assert obj.server is not None
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_any_crash_true(tmp_path):
    "subsequent crashes need not match the original if any_crash is True"
    stderr = "Assertion failure: bad thing happened, at test.c:123"

    class MyTarget(FakeTarget):

        def save_logs(self, dest, **kwds):
            FakeTarget.save_logs(self, dest, **kwds)
            with open(os.path.join(dest, "log_stderr.txt"), "w") as log_fp:
                log_fp.write(stderr)

    obj = Interesting([], MyTarget(), 30, False, True, 0, 1, 1, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    # first call is real, regardless of skip, since that is the initial repro
    prefix = tmp_path / "lithium0"
    prefix.mkdir()
    assert obj.interesting(None, str(prefix))
    assert obj.target._calls["launch"] == 1
    assert obj.target._calls["close"] == 1
    assert obj.server is None
    prefix = tmp_path / "lithium1"
    prefix.mkdir()
    stderr = "Assertion failure: some other thing happened, at test.c:456"
    assert obj.interesting(None, str(prefix))
    assert obj.target._calls["launch"] == 2
    assert obj.target._calls["close"] == 2
    assert obj.server is not None
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_min_crashes_repro(tmp_path):
    "min_crashes will force n iterations if crash repros"
    obj = Interesting([], FakeTarget(), 30, False, False, 0, 4, 1, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    prefix = tmp_path / "lithium"
    prefix.mkdir()
    assert obj.interesting(None, str(prefix))
    assert obj.target._calls["launch"] == 4
    assert obj.target._calls["close"] == 4
    assert obj.server is not None
    assert obj.target._calls["detect_failure"] == 4
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_min_crashes_norepro(tmp_path):
    "min_crashes will return uninteresting if crash repros n-1 times"

    class MyTarget(FakeTarget):
        repros = 0

        def detect_failure(self, *args, **kwds):
            FakeTarget.detect_failure(self, *args, **kwds)
            if self.repros == 3:
                return Target.RESULT_NONE
            self.repros += 1
            return Target.RESULT_FAILURE

    obj = Interesting([], MyTarget(), 30, False, False, 0, 4, 1, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    prefix = tmp_path / "lithium"
    prefix.mkdir()
    assert not obj.interesting(None, str(prefix))
    assert obj.target._calls["launch"] == 4
    assert obj.target._calls["close"] == 3
    assert obj.server is not None
    assert obj.target._calls["detect_failure"] == 4
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_repeat_repro(tmp_path):
    "repeat will stop at min_crashes if crash repros"
    obj = Interesting([], FakeTarget(), 30, False, False, 0, 4, 17, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    prefix = tmp_path / "lithium"
    prefix.mkdir()
    assert obj.interesting(None, str(prefix))
    assert obj.server is not None
    assert obj.target._calls["detect_failure"] == 4
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_repeat_norepro(tmp_path):
    "repeat will force repeat - min_crashes + 1 iterations if crash doesn't repro"

    class MyTarget(FakeTarget):

        def detect_failure(self, *args, **kwds):
            FakeTarget.detect_failure(self, *args, **kwds)
            return Target.RESULT_NONE

    obj = Interesting([], MyTarget(), 30, False, False, 0, 4, 17, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    reduce_file = tmp_path / "test.html"
    reduce_file.touch()
    obj.reduce_file = str(reduce_file)
    obj.init(None)
    prefix = tmp_path / "lithium"
    prefix.mkdir()
    assert not obj.interesting(None, str(prefix))
    assert obj.server is not None
    assert obj.target._calls["detect_failure"] == 17 - 4 + 1
    obj.cleanup(None)
    assert obj.target._calls["cleanup"] == 0


def test_cache(tmp_path):
    "cache will be hit if same file is given twice"
    obj = Interesting([], FakeTarget(), 30, False, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus())
    create_target_binary(obj.target, tmp_path)
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    (tmp_path / "lithium0").mkdir()
    assert obj.interesting(None, tmp_path / "lithium0")
    (tmp_path / "lithium1").mkdir()
    assert obj.interesting(None, tmp_path / "lithium1")
    assert obj.target._calls["detect_failure"] == 1
    obj.cleanup(None)


def test_no_cache(tmp_path):
    "testcase_cache=False will disable cache"
    obj = Interesting([], FakeTarget(), 30, False, False, 0, 1, 1, 0, 0, 0, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    (tmp_path / "lithium0").mkdir()
    assert obj.interesting(None, tmp_path / "lithium0")
    (tmp_path / "lithium1").mkdir()
    assert obj.interesting(None, tmp_path / "lithium1")
    assert obj.target._calls["detect_failure"] == 2
    obj.cleanup(None)


def test_timeout_update(monkeypatch, tmp_path):
    "timeout will be updated based on time to crash"
    monkeypatch.setattr(time, "time", lambda: 0)  # run time will be calculated as 0
    failure_result = Target.RESULT_NONE

    class MyTarget(FakeTarget):

        def detect_failure(self, *args, **kwds):
            FakeTarget.detect_failure(self, *args, **kwds)
            return failure_result

    obj = Interesting([], MyTarget(), 30, False, False, 0, 1, 1, 0, 0, 30, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    assert obj.idle_timeout == 30
    (tmp_path / "lithium0").mkdir()
    assert not obj.interesting(None, tmp_path / "lithium0")
    assert obj.idle_timeout == 30
    assert obj.server is not None
    last_timeout = FakeServer._last_timeout
    assert last_timeout >= 30
    failure_result = Target.RESULT_FAILURE
    (tmp_path / "lithium1").mkdir()
    assert obj.interesting(None, tmp_path / "lithium1")
    assert obj.idle_timeout < 30
    idle_timeout = obj.idle_timeout
    assert obj.server is None  # killed to update timeout
    assert FakeServer._last_timeout == last_timeout
    last_timeout = FakeServer._last_timeout
    (tmp_path / "lithium2").mkdir()
    assert obj.interesting(None, tmp_path / "lithium2")
    assert obj.idle_timeout == idle_timeout
    assert FakeServer._last_timeout  # assert that there is actually a timeout
    assert FakeServer._last_timeout < last_timeout
    last_timeout = FakeServer._last_timeout
    assert obj.server is not None
    (tmp_path / "lithium3").mkdir()
    assert obj.interesting(None, tmp_path / "lithium3")
    assert obj.idle_timeout == idle_timeout
    assert FakeServer._last_timeout == last_timeout
    assert obj.server is not None
    obj.cleanup(None)


def test_idle_timeout(monkeypatch, tmp_path):
    "idle is not polled until idle_timeout has passed, and idle_poll results in timeout"
    now = [0]
    first_poll = []

    def mytime():
        now[0] += 1
        return now[0]

    class MyTarget(FakeTarget):

        def poll_for_idle(self, *args, **kwds):
            if not first_poll:
                first_poll.append(now[0])
            FakeTarget.poll_for_idle(self, *args, **kwds)
            return time.time() >= 45

    class MyServer(FakeServer):

        def serve_testcase(self, *args, **kwds):
            continue_cb = kwds["continue_cb"]
            while continue_cb():
                pass
            return sapphire.SERVED_ALL, []

    monkeypatch.setattr(time, "time", mytime)
    monkeypatch.setattr(sapphire, "Sapphire", MyServer)

    obj = Interesting([], MyTarget(), 30, False, False, 0, 1, 1, 10, 25, 30, FakeReduceStatus(), False)
    create_target_binary(obj.target, tmp_path)
    (tmp_path / "test.html").touch()
    obj.reduce_file = str(tmp_path / "test.html")
    obj.init(None)
    (tmp_path / "lithium0").mkdir()
    assert obj.interesting(None, tmp_path / "lithium0")
    assert abs(first_poll[0] - 30) <= 5, "polling started at %d" % (first_poll[0],)
    assert now[0] >= 45  # interesting did not return until poll_for_idle returned True
    obj.cleanup(None)
