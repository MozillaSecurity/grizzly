# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

from .target import Target


class SimpleTarget(Target):
    def cleanup(self):
        pass

    def close(self):
        pass

    @property
    def closed(self):
        pass

    def create_report(self, is_hang=False):
        pass

    def detect_failure(self, ignored):
        pass

    def handle_hang(self, ignore_idle=True):
        pass

    def launch(self, _location, _env_mod=None):
        pass

    @property
    def monitor(self):
        return self._monitor

    @property
    def prefs(self):
        pass

    def save_logs(self, *_args, **_kwargs):
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
