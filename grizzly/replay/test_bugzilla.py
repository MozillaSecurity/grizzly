# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Unit tests for `grizzly.replay.bugzilla`"""
from base64 import b64encode

from bugsy import Bug

from .args import ReplayFuzzBugzillaArgs
from .bugzilla import main


def test_crash_main_no_bug(mocker, tmp_path):
    """test main() - failed to get bug"""
    bugzilla = mocker.patch("grizzly.replay.bugzilla.BugzillaBug", autospec=True)
    bugzilla.load.return_value = None
    file = tmp_path / "file"
    file.touch()
    args = ReplayFuzzBugzillaArgs().parse_args([str(file), "123"])
    assert main(args) == 1


def test_crash_main(mocker, tmp_path):
    """test main()"""
    fake_bugsy = mocker.patch("grizzly.common.bugzilla.Bugsy", autospec=True)
    fake_replay = mocker.patch("grizzly.replay.bugzilla.ReplayManager", autospec=True)
    fake_replay.main.return_value = 0
    file = tmp_path / "file"
    file.touch()

    # no test cases
    fake_bugsy.return_value.get.return_value = mocker.MagicMock(spec=Bug, id=123)
    args = ReplayFuzzBugzillaArgs().parse_args([str(file), "123"])
    assert main(args) == 1
    assert fake_bugsy.return_value.get.call_count == 1
    fake_bugsy.reset_mock()

    # test case and asset
    bugsy_bug = mocker.Mock(spec=Bug, id=123)
    bugsy_bug.get_attachments.return_value = [
        mocker.Mock(is_obsolete=False, data=b64encode(b"foo"), file_name="test.html"),
        mocker.Mock(is_obsolete=False, data=b64encode(b"foo"), file_name="prefs.js"),
    ]
    fake_bugsy.return_value.get.return_value = bugsy_bug
    args = ReplayFuzzBugzillaArgs().parse_args([str(file), "123"])
    assert main(args) == 0
    assert fake_bugsy.return_value.get.call_count == 1
    assert args.input != "123"
    assert args.asset
    assert "prefs" in args.asset[-1]
