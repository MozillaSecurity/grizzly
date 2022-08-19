# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from itertools import count
from os.path import isfile
from platform import system

from ffpuppet import BrowserTerminatedError, BrowserTimeoutError, Debugger, Reason
from pytest import mark, raises

from .puppet_target import PuppetTarget
from .target import AssetManager, Result, TargetLaunchError, TargetLaunchTimeout


def test_puppet_target_01(mocker, tmp_path):
    """test creating a PuppetTarget"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_ffp.return_value.reason = Reason.CLOSED
    fake_ffp.return_value.log_length.return_value = 562
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        assert target.assets
        assert target.closed
        assert target.launch_timeout == 300
        assert target.log_limit == 25
        assert target.memory_limit == 5000
        assert target.check_result([]) == Result.NONE
        assert target.log_size() == 1124
        fake_ffp.return_value.log_length.assert_any_call("stderr")
        fake_ffp.return_value.log_length.assert_any_call("stdout")
        assert target.monitor is not None
        target.save_logs("fake_dest")
        assert fake_ffp.return_value.save_logs.call_count == 1
    assert fake_ffp.return_value.clean_up.call_count == 1
    # with extra args
    with PuppetTarget(str(fake_file), 1, 1, 1, rr=True, fake=1) as target:
        pass


def test_puppet_target_02(mocker, tmp_path):
    """test PuppetTarget.launch()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    # test providing prefs.js
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        # launch success
        target.launch("launch_target_page")
        assert fake_ffp.return_value.launch.call_count == 1
        assert fake_ffp.return_value.close.call_count == 0
        target.close()
        # launch timeout
        fake_ffp.reset_mock()
        fake_ffp.return_value.launch.side_effect = BrowserTimeoutError("timeout")
        with raises(TargetLaunchTimeout, match="timeout"):
            target.launch("launch_target_page")
        assert fake_ffp.return_value.save_logs.call_count == 0
        # launch failure
        fake_ffp.reset_mock()
        (tmp_path / "log_stderr.txt").write_text("fake log")
        (tmp_path / "log_stdout.txt").write_text("fake log")
        mocker.patch(
            "grizzly.target.puppet_target.mkdtemp",
            autospec=True,
            return_value=str(tmp_path),
        )
        fake_ffp.return_value.launch.side_effect = BrowserTerminatedError("fail")
        with raises(TargetLaunchError, match="fail"):
            target.launch("launch_target_page")
        assert fake_ffp.return_value.save_logs.call_count == 1


@mark.parametrize(
    "healthy, reason, ignore, result, closes",
    [
        # running as expected - no failures
        (True, None, [], Result.NONE, 0),
        # browser process closed
        (False, Reason.CLOSED, [], Result.NONE, 1),
        # browser process crashed
        (False, Reason.ALERT, [], Result.FOUND, 1),
        # browser exit with no crash logs
        (False, Reason.EXITED, [], Result.NONE, 1),
        # ffpuppet check failed
        (False, Reason.WORKER, [], Result.FOUND, 1),
        # ffpuppet check ignored (memory)
        (False, Reason.WORKER, ["memory"], Result.IGNORED, 1),
        # ffpuppet check ignored (log-limit)
        (False, Reason.WORKER, ["log-limit"], Result.IGNORED, 1),
    ],
)
def test_puppet_target_03(mocker, tmp_path, healthy, reason, ignore, result, closes):
    """test PuppetTarget.check_result()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    if "memory" in ignore:
        fake_ffp.return_value.available_logs.return_value = "ffp_worker_memory_usage"
    elif "log-limit" in ignore:
        fake_ffp.return_value.available_logs.return_value = "ffp_worker_log_size"
    fake_ffp.return_value.is_healthy.return_value = healthy
    fake_ffp.return_value.reason = reason
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        assert target.check_result(ignore) == result
    assert fake_ffp.return_value.close.call_count == closes


@mark.parametrize(
    "healthy, usage, os_name, killed",
    [
        # skip sending SIGABRT on unsupported OSs
        (True, [(1234, 90)], "Windows", 0),
        # skip idle check if target is in a bad state
        (False, [], "Linux", 0),
        # send SIGABRT to hung process
        (True, [(234, 10), (236, 75), (238, 60)], "Linux", 1),
        # ignore idle timeout (close don't abort)
        (True, [(234, 10)], "Linux", 0),
    ],
)
def test_puppet_target_04(mocker, tmp_path, healthy, usage, os_name, killed):
    """test PuppetTarget.handle_hang()"""
    mocker.patch(
        "grizzly.target.puppet_target.system", autospec=True, return_value=os_name
    )
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_kill = mocker.patch("grizzly.target.puppet_target.kill", autospec=True)
    # raise OSError for code coverage
    fake_kill.side_effect = OSError
    fake_file = tmp_path / "fake"
    fake_file.touch()
    fake_ffp.return_value.cpu_usage.return_value = usage
    fake_ffp.return_value.is_healthy.return_value = healthy
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        target.handle_hang()
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    assert fake_ffp.return_value.cpu_usage.call_count == (1 if usage else 0)
    assert fake_kill.call_count == fake_ffp.return_value.wait.call_count == killed


@mark.skipif(system() == "Windows", reason="Unsupported on Windows")
def test_puppet_target_05(mocker, tmp_path):
    """test PuppetTarget.dump_coverage()"""
    mocker.patch("grizzly.target.puppet_target.wait_procs", autospec=True)
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    child_proc = mocker.Mock(pid=101)
    child_proc.exe.return_value = "firefox-bin"
    fake_proc = mocker.patch("grizzly.target.puppet_target.Process", autospec=True)
    fake_proc.return_value.pid = 100
    fake_proc.return_value.children.return_value = (child_proc,)
    fake_proc.return_value.exe.return_value = "firefox-bin"
    fake_proc_iter = mocker.patch(
        "grizzly.target.puppet_target.process_iter", autospec=True
    )
    mocker.patch("grizzly.target.puppet_target.sleep", autospec=True)
    fake_time = mocker.patch("grizzly.target.puppet_target.time", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    target = PuppetTarget(str(fake_file), 300, 25, 5000)
    fake_kill = mocker.patch("grizzly.target.puppet_target.kill", autospec=True)
    # not running
    fake_ffp.return_value.get_pid.return_value = None
    target.dump_coverage()
    assert not fake_kill.call_count
    assert fake_ffp.return_value.get_pid.call_count == 1
    assert fake_proc_iter.call_count == 0
    # gcda not found
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.get_pid.return_value = 100
    fake_time.side_effect = (0, 1, 10)
    target.dump_coverage()
    assert fake_kill.call_count == 2
    assert fake_proc_iter.call_count == 2
    assert fake_ffp.return_value.is_healthy.call_count == 2
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    # browser crashes
    fake_ffp.return_value.is_healthy.side_effect = (True, False)
    fake_time.side_effect = None
    fake_time.return_value = 1.0
    target.dump_coverage()
    assert fake_kill.call_count == 2
    assert fake_proc_iter.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 2
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    # timeout while waiting for files
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.is_healthy.side_effect = None
    fake_ffp.return_value.get_pid.return_value = 100
    fake_proc_iter.return_value = (
        mocker.Mock(info={"pid": 101, "open_files": (mocker.Mock(path="a.gcda"),)}),
    )
    fake_time.side_effect = (0, 1, 20)
    target.dump_coverage(timeout=15)
    assert fake_kill.call_count == 3
    assert fake_proc_iter.call_count == 2
    assert fake_ffp.return_value.is_healthy.call_count == 2
    assert fake_ffp.return_value.close.call_count == 1
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    # wait for files (success)
    fake_ffp.return_value.get_pid.return_value = 100
    fake_time.side_effect = None
    fake_time.return_value = 1.0
    fake_proc_iter.side_effect = (
        # 1st call
        (
            mocker.Mock(
                info={
                    "pid": 100,
                    "open_files": (
                        mocker.Mock(path="a.bin"),
                        mocker.Mock(path="/a/s/d"),
                    ),
                }
            ),
            mocker.Mock(info={"pid": 101, "open_files": None}),
            mocker.Mock(info={"pid": 999, "open_files": None}),
        ),
        # 2nd call
        (mocker.Mock(info={"pid": 100, "open_files": (mocker.Mock(path="a.gcda"),)}),),
        # 3rd call
        (
            mocker.Mock(info={"pid": 100, "open_files": (mocker.Mock(path="a.bin"),)}),
            mocker.Mock(
                info={"pid": 999, "open_files": (mocker.Mock(path="ignore.gcda"),)}
            ),
        ),
    )
    target.dump_coverage()
    assert fake_ffp.return_value.close.call_count == 0
    assert fake_proc_iter.call_count == 3
    assert fake_kill.call_count == 2
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    # kill calls raise OSError
    fake_kill.side_effect = OSError
    fake_ffp.return_value.is_healthy.return_value = True
    fake_ffp.return_value.get_pid.return_value = 100
    fake_proc_iter.side_effect = None
    fake_time.side_effect = count()
    target.dump_coverage()
    assert fake_kill.call_count == 2
    fake_ffp.reset_mock()
    fake_kill.reset_mock()
    fake_proc_iter.reset_mock()
    target.cleanup()


def test_puppet_target_06(mocker, tmp_path):
    """test PuppetTarget.is_idle()"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_ffp.return_value.cpu_usage.return_value = [(999, 30), (998, 20), (997, 10)]
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        assert not target.is_idle(0)
        assert not target.is_idle(25)
        assert target.is_idle(50)


def test_puppet_target_07(mocker, tmp_path):
    """test PuppetTarget.monitor"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        fake_ffp.return_value.is_running.return_value = False
        fake_ffp.return_value.is_healthy.return_value = False
        assert target.monitor is not None
        assert not target.monitor.is_healthy()
        assert not target.monitor.is_running()
        fake_ffp.return_value.is_running.return_value = True
        fake_ffp.return_value.is_healthy.return_value = True
        assert target.monitor.is_healthy()
        assert target.monitor.is_running()
        fake_ffp.return_value.launches = 123
        assert target.monitor.launches == 123
        fake_ffp.return_value.log_length.return_value = 100
        assert target.monitor.log_length("stdout") == 100
        target.monitor.clone_log("somelog")
        assert fake_ffp.return_value.clone_log.call_count == 1


def test_puppet_target_08(mocker, tmp_path):
    """test PuppetTarget.process_assets()"""
    mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.write_text("1\n2\n")
    # no prefs file provided
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        assert target.assets.get("prefs") is None
        target.process_assets()
        assert isfile(target.assets.get("prefs"))
        assert target.assets.get("prefs").endswith("prefs.js")
    # prefs file provided
    with AssetManager(base_path=str(tmp_path)) as assets:
        assets.add("prefs", str(fake_file))
        with PuppetTarget(str(fake_file), 300, 25, 5000, assets=assets) as target:
            target.process_assets()
            assert isfile(target.assets.get("prefs"))
            assert target.assets.get("prefs").endswith("fake")
    # abort tokens file provided
    with AssetManager(base_path=str(tmp_path)) as assets:
        assets.add("abort-tokens", str(fake_file))
        with PuppetTarget(str(fake_file), 300, 25, 5000, assets=assets) as target:
            # ignore E1101: (pylint 2.9.3 bug?)
            #    Method 'add_abort_token' has no 'call_count' member (no-member)
            # pylint: disable=no-member
            assert target._puppet.add_abort_token.call_count == 0
            target.process_assets()
            assert isfile(target.assets.get("abort-tokens"))
            assert target.assets.get("abort-tokens").endswith("fake")
            assert target._puppet.add_abort_token.call_count == 2


@mark.parametrize(
    "pernosco, rr, valgrind",
    [
        # No debugger selected
        (False, False, False),
        # Pernosco selected
        (True, False, False),
        # rr selected
        (False, True, False),
        # Valgrind selected
        (False, False, True),
    ],  # pylint: disable=invalid-name
)
def test_puppet_target_09(mocker, tmp_path, pernosco, rr, valgrind):
    """test PuppetTarget debugger args"""
    fake_ffp = mocker.patch("grizzly.target.puppet_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(
        str(fake_file), 30, 25, 500, pernosco=pernosco, rr=rr, valgrind=valgrind
    ) as _:
        pass
    if pernosco:
        assert fake_ffp.call_args[-1]["debugger"] == Debugger.PERNOSCO
    elif rr:
        assert fake_ffp.call_args[-1]["debugger"] == Debugger.RR
    elif valgrind:
        assert fake_ffp.call_args[-1]["debugger"] == Debugger.VALGRIND
    else:
        assert fake_ffp.call_args[-1]["debugger"] == Debugger.NONE


@mark.parametrize(
    "asset, env",
    [
        # suppressions via asset
        (True, False),
        # suppressions via env
        (False, True),
        # suppressions via both asset and env (asset should be preferred)
        (True, True),
        # missing suppressions file
        (False, False),
    ],
)
def test_puppet_target_10(tmp_path, asset, env):
    """test PuppetTarget.process_assets() - configure sanitizer suppressions"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with AssetManager(base_path=str(tmp_path)) as assets:
        assets.add("prefs", str(fake_file))
        if asset:
            supp_asset = tmp_path / "supp_asset"
            supp_asset.touch()
            assets.add("lsan-suppressions", str(supp_asset))
        with PuppetTarget(str(fake_file), 300, 25, 5000, assets=assets) as target:
            if env:
                supp_env = tmp_path / "supp_env"
                supp_env.touch()
                target.environ["LSAN_OPTIONS"] = "suppressions='%s'" % (str(supp_env),)
            else:
                target.environ["LSAN_OPTIONS"] = "suppressions='missing'"
            target.process_assets()
            if asset:
                assert supp_asset.name in target.environ["LSAN_OPTIONS"]
            elif env:
                assert supp_env.name in target.environ["LSAN_OPTIONS"]
                assert assets.get("lsan-suppressions")
            else:
                assert not assets.get("lsan-suppressions")


def test_puppet_target_11(tmp_path):
    """test PuppetTarget.filtered_environ()"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with PuppetTarget(str(fake_file), 300, 25, 5000) as target:
        target.environ = {
            "TRACKED": "1",
            "ASAN_OPTIONS": "external_symbolizer_path='a':no_remove='b'",
            "LSAN_OPTIONS": "suppressions='a'",
            "EMPTY": "",
        }
        assert "EMPTY" not in target.filtered_environ()
        assert "TRACKED" in target.filtered_environ()
        assert "ASAN_OPTIONS" in target.filtered_environ()
        assert "LSAN_OPTIONS" not in target.filtered_environ()
