# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from .target import sanitizer_opts, Target

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
    def launch(self):
        pass
    @property
    def monitor(self):
        return self._monitor
    @property
    def prefs(self):
        pass
    def save_logs(self, *args, **kwargs):
        pass

def test_target_01(tmp_path):
    """test creating a simple Target"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = SimpleTarget(str(fake_file), str(fake_file), 321, 2, 3)
    assert target.binary == str(fake_file)
    assert target.extension == str(fake_file)
    assert not target.is_idle(0)
    assert target.launch_timeout == 321
    assert target.log_size() == 0
    assert target.log_limit == 2
    assert target.memory_limit == 3
    assert target.monitor is None
    # test stubs
    target.add_abort_token("none!")
    target.dump_coverage()
    target.reverse(1, 2)

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
