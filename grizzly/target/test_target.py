# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
import pytest

from .target import sanitizer_opts, Target, TargetError
from .target_monitor import TargetMonitor

class SimpleTarget(Target):
    def cleanup(self):
        pass
    def close(self):
        pass
    @property
    def closed(self):
        pass
    def detect_failure(self, ignored, was_timeout):
        pass
    def launch(self, location, env_mod=None):
        pass
    @property
    def monitor(self):
        return self._monitor
    def save_logs(self, *args, **kwargs):
        pass

def test_target_01(tmp_path):
    """test creating a simple Target"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with pytest.raises(TargetError):
        SimpleTarget(str(fake_file), None, 321, 2, 3, "no_prefs", 25)
    target = SimpleTarget(str(fake_file), str(fake_file), 321, 2, 3, str(fake_file), 25)
    assert target.binary == str(fake_file)
    assert target.extension == str(fake_file)
    assert target.forced_close
    assert not target.is_idle(0)
    assert target.launch_timeout == 321
    assert target.log_size() == 0
    assert target.log_limit == 2
    assert target.memory_limit == 3
    assert target.rl_countdown == 0
    assert target.rl_reset == 25
    assert target.prefs == str(fake_file)
    assert not target.expect_close
    # test stubs
    target.add_abort_token("none!")
    target.dump_coverage()
    target.reverse(1, 2)

def test_target_02(mocker, tmp_path):
    """test setting Target.forced_close"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    getenv = mocker.patch("grizzly.target.target.getenv", autospec=True, return_value="0")
    with SimpleTarget(str(fake_file), None, 300, 25, 5000, None, 25) as target:
        assert not target.forced_close
        assert target.extension is None
        assert target.prefs is None
        target.rl_countdown = 1
        assert not target.expect_close
        target.rl_countdown = 0
        assert target.expect_close
    getenv.assert_called_with("GRZ_FORCED_CLOSE")

def test_target_03(mocker, tmp_path):
    """test Target.check_relaunch() and Target.step()"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with SimpleTarget(str(fake_file), None, 300, 25, 5000, None, 1) as target:
        target._monitor = mocker.Mock(spec=TargetMonitor)
        target._monitor.is_healthy.return_value = True
        # test skipping relaunch
        target.rl_countdown = 2
        target.step()
        assert target.rl_countdown == 1
        target.check_relaunch(wait=60)
        # test triggering relaunch
        target.rl_countdown = 1
        target.step()
        assert target.rl_countdown == 0
        target.check_relaunch(wait=0)
        # test with "crashed" process
        target._monitor.is_healthy.side_effect = (True, False)
        target.rl_countdown = 0
        target.step()
        mocker.patch("grizzly.target.target.sleep", autospec=True)
        target.check_relaunch(wait=5)

def test_sanitizer_opts_01(tmp_path):
    """test sanitizer_opts()"""
    # test empty string
    assert not sanitizer_opts("")
    # test single value
    opts = sanitizer_opts("test_value=true")
    assert len(opts) == 1
    assert opts["test_value"] == "true"
    # test multiple values
    opts = sanitizer_opts("a=1:b=-2:C=3")
    assert len(opts) == 3
    assert opts["a"] == "1"
    assert opts["b"] == "-2"
    assert opts["C"] == "3"
    # path parsing
    opts = sanitizer_opts("p1='z:/a':p2='x:\\a.1':p3='/test/path/':p4='':p5=\"x:/a.a\"")
    assert opts["p1"] == "'z:/a'"
    assert opts["p2"] == "'x:\\a.1'"
    assert opts["p3"] == "'/test/path/'"
    assert opts["p4"] == "''"
    assert opts["p5"] == "\"x:/a.a\""
    # platform specific parsing
    fake_file = tmp_path / "fake.log"
    opts = sanitizer_opts("bar=1:file='%s':foo=2" % (str(fake_file),))
    assert len(opts) == 3
    assert opts["file"] == "'%s'" % (str(fake_file),)
