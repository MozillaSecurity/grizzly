# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from .assets import AssetManager
from .target import Target


class SimpleTarget(Target):
    TRACKED_ENVVARS = ("TEST_INC",)

    def _cleanup(self):
        pass

    def check_result(self, ignored):
        pass

    def close(self, force_close=False):
        pass

    @property
    def closed(self):
        return True

    def create_report(self, is_hang=False, unstable=False):
        pass

    def dump_coverage(self, timeout=0):
        pass

    def handle_hang(self, ignore_idle=True, ignore_timeout=False):
        return False

    def https(self):
        return self._https

    def launch(self, location):
        pass

    def log_size(self):
        return 0

    @property
    def monitor(self):
        return self._monitor

    def merge_environment(self, extra):
        pass

    def process_assets(self):
        pass

    def save_logs(self, dst):
        pass


def test_target_01(tmp_path):
    """test creating a simple Target"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with SimpleTarget(fake_file, 10, 2, 3) as target:
        assert target.binary == fake_file
        assert target.asset_mgr
        org_path = target.asset_mgr.path
        target.asset_mgr = AssetManager(base_path=tmp_path)
        assert target.asset_mgr.path != org_path
        assert not target.environ
        assert not target.filtered_environ()
        assert target.launch_timeout == 10
        assert target.log_size() == 0
        assert target.log_limit == 2
        assert target.memory_limit == 3
        assert target.monitor is None
        # test stubs
        target.reverse(1, 2)


def test_target_02(mocker, tmp_path):
    """test loading TRACKED_ENVVARS"""
    mocker.patch.dict("grizzly.target.target.environ", {"SKIP": "x", "TEST_INC": "1"})
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with SimpleTarget(fake_file, 321, 2, 3) as target:
        assert target.environ
        assert "SKIP" not in target.environ
        assert target.environ["TEST_INC"] == "1"
        filtered = target.filtered_environ()
        assert filtered
        assert "SKIP" not in filtered
        assert filtered["TEST_INC"] == "1"


def test_target_03():
    """test Target.scan_environment()"""
    assert not Target.scan_environment({"a": "1"}, ())
    assert not Target.scan_environment({}, ("a",))
    assert Target.scan_environment({"a": "1", "b": "2"}, ("a",)) == {"a": "1"}
