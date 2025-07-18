# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from hashlib import sha1
from itertools import chain
from platform import system

from ffpuppet import BrowserTerminatedError, BrowserTimeoutError, Debugger, Reason
from pytest import mark, raises

from sapphire import CertificateBundle

from .assets import AssetManager
from .firefox_target import FirefoxTarget, merge_sanitizer_options
from .target import Result, TargetLaunchError, TargetLaunchTimeout


def test_firefox_target_01(mocker, tmp_path):
    """test creating a FirefoxTarget"""
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_ffp.return_value.reason = Reason.CLOSED
    fake_ffp.return_value.log_length.return_value = 562
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        assert target.asset_mgr
        assert target.closed
        assert target.launch_timeout == 300
        assert target.log_limit == 25
        assert target.memory_limit == 5000
        assert target.check_result(set()) == Result.NONE
        assert not target.https()
        assert target.log_size() == 1124
        fake_ffp.return_value.log_length.assert_any_call("stderr")
        fake_ffp.return_value.log_length.assert_any_call("stdout")
        assert target.monitor is not None
        target.save_logs(tmp_path / "fake_dest")
        assert fake_ffp.return_value.save_logs.call_count == 1
    assert fake_ffp.return_value.clean_up.call_count == 1
    # with extra args
    with FirefoxTarget(fake_file, 1, 1, 1, rr=True, fake=1) as target:
        pass


def test_firefox_target_02(mocker, tmp_path):
    """test FirefoxTarget.launch()"""
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    # test providing prefs.js
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
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
            "grizzly.target.firefox_target.mkdtemp",
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
def test_firefox_target_03(mocker, tmp_path, healthy, reason, ignore, result, closes):
    """test FirefoxTarget.check_result()"""
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    if "memory" in ignore:
        fake_ffp.return_value.available_logs.return_value = {"ffp_worker_memory_usage"}
    elif "log-limit" in ignore:
        fake_ffp.return_value.available_logs.return_value = {"ffp_worker_log_size"}
    fake_ffp.return_value.is_healthy.return_value = healthy
    fake_ffp.return_value.reason = reason
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        assert target.check_result(ignore) == result
    assert fake_ffp.return_value.close.call_count == closes


@mark.parametrize(
    "healthy, usage, os_name, killed, debugger",
    [
        # skip sending SIGABRT on unsupported OSs
        (True, [(1234, 90)], "Windows", 0, Debugger.NONE),
        # skip idle check if target is in a bad state
        (False, [], "Linux", 0, Debugger.NONE),
        # send SIGABRT to hung process
        (True, [(234, 10), (236, 75), (238, 60)], "Linux", 1, Debugger.NONE),
        # Don't send SIGABRT when using a debugger
        (True, [(236, 75)], "Linux", 0, Debugger.RR),
        # ignore idle timeout (close don't abort)
        (True, [(234, 10)], "Linux", 0, Debugger.NONE),
    ],
)
def test_firefox_target_04(mocker, tmp_path, healthy, usage, os_name, killed, debugger):
    """test FirefoxTarget.handle_hang()"""
    mocker.patch(
        "grizzly.target.firefox_target.system", autospec=True, return_value=os_name
    )
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_kill = mocker.patch("grizzly.target.firefox_target.kill", autospec=True)
    # raise OSError for code coverage
    fake_kill.side_effect = OSError
    fake_file = tmp_path / "fake"
    fake_file.touch()
    fake_ffp.return_value.cpu_usage.return_value = usage
    fake_ffp.return_value.is_healthy.return_value = healthy
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        target._debugger = debugger
        target.handle_hang()
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    assert fake_ffp.return_value.cpu_usage.call_count == (1 if usage else 0)
    assert fake_kill.call_count == fake_ffp.return_value.wait.call_count == killed


@mark.skipif(system() != "Linux", reason="Linux only")
def test_firefox_target_05(mocker, tmp_path):
    """test FirefoxTarget.dump_coverage()"""
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        target.dump_coverage()
    assert fake_ffp.return_value.dump_coverage.call_count == 1


def test_firefox_target_06(mocker, tmp_path):
    """test FirefoxTarget.monitor"""
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
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


def test_firefox_target_07(mocker, tmp_path):
    """test FirefoxTarget.monitor.is_idle()"""
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_ffp.return_value.cpu_usage.return_value = [(999, 30), (998, 20), (997, 10)]
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        assert not target.monitor.is_idle(0)
        assert not target.monitor.is_idle(25)
        assert target.monitor.is_idle(50)


def test_firefox_target_08(mocker, tmp_path):
    """test FirefoxTarget.process_assets()"""
    mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.write_text("1\n2\n")
    # no prefs file provided
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        assert target.asset_mgr.get("prefs") is None
        target.process_assets()
        asset = target.asset_mgr.get("prefs")
        assert asset
        assert asset.is_file()
        assert asset.name == "prefs.js"
    # prefs file provided
    with AssetManager(base_path=tmp_path) as asset_mgr:
        asset_mgr.add("prefs", fake_file)
        with FirefoxTarget(fake_file, 300, 25, 5000) as target:
            target.asset_mgr = asset_mgr
            target.process_assets()
            asset = target.asset_mgr.get("prefs")
            assert asset
            assert asset.name == "fake"
    # abort tokens file provided
    with AssetManager(base_path=tmp_path) as asset_mgr:
        asset_mgr.add("abort-tokens", fake_file)
        with FirefoxTarget(fake_file, 300, 25, 5000) as target:
            # ignore E1101: (pylint 2.9.3 bug?)
            #    Method 'add_abort_token' has no 'call_count' member (no-member)
            # pylint: disable=no-member
            assert target._puppet.add_abort_token.call_count == 0
            target.asset_mgr = asset_mgr
            target.process_assets()
            asset = target.asset_mgr.get("abort-tokens")
            assert asset
            assert asset.is_file()
            assert asset.name == "fake"
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
    ],
)
def test_firefox_target_09(
    mocker,
    tmp_path,
    pernosco,
    rr,  # pylint: disable=invalid-name
    valgrind,
):
    """test FirefoxTarget debugger args"""
    fake_ffp = mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(
        fake_file, 30, 25, 500, pernosco=pernosco, rr=rr, valgrind=valgrind
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
def test_firefox_target_10(tmp_path, asset, env):
    """test FirefoxTarget.process_assets() - configure sanitizer suppressions"""
    fake_file = tmp_path / "fake"
    fake_file.touch()
    supp_asset = tmp_path / "supp_asset"
    supp_env = tmp_path / "supp_env"
    with AssetManager(base_path=tmp_path) as asset_mgr:
        asset_mgr.add("prefs", fake_file)
        if asset:
            supp_asset.touch()
            asset_mgr.add("lsan-suppressions", supp_asset)
        with FirefoxTarget(fake_file, 300, 25, 5000) as target:
            target.environ["TSAN_OPTIONS"] = "a=1"
            if env:
                supp_env.touch()
                target.environ["LSAN_OPTIONS"] = f"suppressions='{supp_env}'"
            else:
                target.environ["LSAN_OPTIONS"] = "suppressions='missing'"
            target.asset_mgr = asset_mgr
            target.process_assets()
            if asset:
                assert (
                    f"suppressions='{target.asset_mgr.path / supp_asset.name}'"
                    in target.environ["LSAN_OPTIONS"]
                )
            elif env:
                assert (
                    f"suppressions='{target.asset_mgr.path / supp_env.name}'"
                    in target.environ["LSAN_OPTIONS"]
                )
            else:
                assert not asset_mgr.get("lsan-suppressions")


def test_firefox_target_11(mocker, tmp_path):
    """test FirefoxTarget.filtered_environ()"""
    mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
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


@mark.parametrize(
    "base, extra, result",
    [
        # empty
        ({}, {}, {}),
        # empty extra
        ({"a": "1"}, {}, {"a": "1"}),
        # empty base
        ({}, {"a": "1"}, {"a": "1"}),
        # merge
        ({"a": "1"}, {"b": "2"}, {"a": "1", "b": "2"}),
        # name collision, favor base
        ({"a": "1"}, {"a": "2"}, {"a": "1"}),
        # name collision and merge
        ({"a": "1"}, {"a": "2", "b": "2"}, {"a": "1", "b": "2"}),
        # sanitizer options
        (
            {"ASAN_OPTIONS": "a=1", "b": "2"},
            {"c": "3"},
            {"ASAN_OPTIONS": "a=1", "b": "2", "c": "3"},
        ),
    ],
)
def test_firefox_target_12(mocker, tmp_path, base, extra, result):
    """test FirefoxTarget.merge_environment()"""
    mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        target.environ = base
        target.merge_environment(extra)
        assert target.environ == result


@mark.parametrize(
    "base, extra, result",
    [
        # nothing to add
        ({}, {}, {}),
        # nothing to add
        (
            {"ASAN_OPTIONS": "a=1"},
            {},
            {"ASAN_OPTIONS": frozenset(("a=1",))},
        ),
        # add to empty base
        (
            {},
            {"ASAN_OPTIONS": "a=1"},
            {"ASAN_OPTIONS": frozenset(("a=1",))},
        ),
        # add to base with unrelated variables
        (
            {"UNRELATED": "1"},
            {"ASAN_OPTIONS": "a=1"},
            {"ASAN_OPTIONS": frozenset(("a=1",))},
        ),
        # collision with existing option
        (
            {"ASAN_OPTIONS": "a=1"},
            {"ASAN_OPTIONS": "a=2"},
            {"ASAN_OPTIONS": frozenset(("a=1",))},
        ),
        # add option from extra
        (
            {"ASAN_OPTIONS": "a=1"},
            {"ASAN_OPTIONS": "b=2:c=3"},
            {"ASAN_OPTIONS": frozenset(("a=1", "b=2", "c=3"))},
        ),
        # add option from extra
        (
            {"ASAN_OPTIONS": "a=1:c=3"},
            {"ASAN_OPTIONS": "b=2"},
            {"ASAN_OPTIONS": frozenset(("a=1", "b=2", "c=3"))},
        ),
        (
            {"ASAN_OPTIONS": "a=1"},
            {"UBSAN_OPTIONS": "a=2"},
            {"ASAN_OPTIONS": frozenset(("a=1",)), "UBSAN_OPTIONS": frozenset(("a=2",))},
        ),
    ],
)
def test_firefox_target_13(base, extra, result):
    """test merge_sanitizer_environment() - merge sanitizer options"""
    merged = merge_sanitizer_options(base, extra)
    assert all(x.endswith("SAN_OPTIONS") for x in merged)
    for sanitizer in (x for x in chain(base, extra) if x.endswith("SAN_OPTIONS")):
        assert sanitizer in merged
        assert frozenset(merged[sanitizer].split(":")) == result[sanitizer]


def test_firefox_target_14(mocker, tmp_path):
    """test FirefoxTarget.dump_coverage() - skip on unsupported platform"""
    mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)
    mocker.patch("grizzly.target.firefox_target.system", return_value="foo")
    fake_file = tmp_path / "fake"
    fake_file.touch()
    with FirefoxTarget(fake_file, 300, 25, 5000) as target:
        target.dump_coverage()


@mark.parametrize(
    "certutil, certs",
    [
        # certutil and cert bundle available
        (True, True),
        # missing certutil
        (False, True),
        # no cert bundle
        (True, False),
    ],
)
def test_firefox_target_15(mocker, tmp_path, certutil, certs):
    """test FirefoxTarget - HTTPS support"""
    mocker.patch(
        "grizzly.target.firefox_target.certutil_available", return_value=certutil
    )
    mocker.patch("grizzly.target.firefox_target.certutil_find", autospec=True)
    mocker.patch("grizzly.target.firefox_target.FFPuppet", autospec=True)

    fake_file = tmp_path / "fake"
    fake_file.touch()

    bundle = mocker.Mock(spec_set=CertificateBundle).return_value if certs else None
    mocker.patch.object(FirefoxTarget, "_get_certdb", return_value=tmp_path)
    with FirefoxTarget(fake_file, 300, 25, 5000, certs=bundle) as target:
        assert target.https() == (certutil and certs)
        assert target._profile_template == (tmp_path if (certutil and certs) else None)


def test_firefox_target_16(mocker, tmp_path):
    """test FirefoxTarget._get_certdb()"""
    (tmp_path / "grz_tmp").mkdir()
    mocker.patch(
        "grizzly.target.firefox_target.grz_tmp", return_value=tmp_path / "grz_tmp"
    )
    mocker.patch("grizzly.target.firefox_target.Profile", autospec=True)
    mocker.patch(
        "grizzly.target.firefox_target.find_cached", autospec=True, return_value=None
    )
    (tmp_path / "root.pem").touch()
    cert_hash = sha1(
        (tmp_path / "root.pem").read_bytes(), usedforsecurity=False
    ).hexdigest()
    certdb = tmp_path / f"certdb_{cert_hash}"
    certdb.mkdir()
    fake_add = mocker.patch(
        "grizzly.target.firefox_target.add_cached", autospec=True, return_value=tmp_path
    )
    FirefoxTarget._get_certdb(tmp_path / "root.pem", "fake-certutil")
    assert fake_add.call_count == 1
