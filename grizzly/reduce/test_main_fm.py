# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Unit tests for `grizzly.reduce.crash` and `grizzly.reduce.bucket`."""
from copy import deepcopy
from logging import getLogger

import pytest

from .crash import main as crash_main
from .bucket import main as bucket_main


LOG = getLogger(__name__)
pytestmark = pytest.mark.usefixtures("tmp_path_fm_config")


@pytest.mark.parametrize(
    "arg_sig, arg_tool, crash_bucket, result_sig, result_tool",
    [
        # crash id is downloaded and core.main is called with the path
        (None, None, None, None, "test-tool"),
        # crash in bucket, bucket will be downloaded and passed to --sig
        (None, None, 789, "test_sig.json", "test-tool"),
        # crash in bucket, --sig is respected
        ("arg_sig.json", None, 789, "arg_sig.json", "test-tool"),
        # --tool respected
        (None, "tool2", None, None, "tool2"),

    ]
)
def test_crash_main(mocker, arg_sig, arg_tool, crash_bucket, result_sig, result_tool):
    """tests for `grizzly.reduce.crash.main`"""
    mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    crash = mocker.patch("grizzly.reduce.crash.CrashEntry", autospec=True)
    bucket = mocker.patch("grizzly.reduce.crash.Bucket", autospec=True)
    mocker.patch("grizzly.reduce.crash.ReduceManager", autospec=True)
    crash.return_value.testcase_path.return_value = "test_path.zip"
    crash.return_value.bucket = crash_bucket
    crash.return_value.testcase_quality = 5
    crash.return_value.tool = "test-tool"
    bucket.return_value.signature_path.return_value = "test_sig.json"

    args = mocker.Mock(
        input=12345,
        sig=arg_sig,
        tool=arg_tool,
    )
    crash_main(args)
    assert args.input == "test_path.zip"
    assert args.sig == result_sig
    assert args.tool == result_tool


@pytest.mark.parametrize(
    "mgr_exit_code, pre_quality, post_quality",
    [
        (0, 5, 1),
        (1, 5, 9),
        (2, 6, 5),
        (3, 4, 5),
        (3, 0, 0),
        (4, 6, 5),
        (5, 5, 10),
    ]
)
def test_crash_main_quality(mocker, mgr_exit_code, pre_quality, post_quality):
    """test that quality is updated"""
    mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    crash = mocker.patch("grizzly.reduce.crash.CrashEntry", autospec=True)
    mocker.patch("grizzly.reduce.crash.Bucket", autospec=True)
    mgr = mocker.patch("grizzly.reduce.crash.ReduceManager", autospec=True)
    crash.return_value.testcase_path.return_value = "test_path.zip"
    crash.return_value.testcase_quality = pre_quality
    crash.return_value.bucket = None
    crash.return_value.tool = "test-tool"
    mgr.main.return_value = mgr_exit_code

    args = mocker.Mock(
        input=12345,
        sig=None,
        tool=None,
    )
    assert crash_main(args) == mgr_exit_code
    assert crash.return_value.testcase_quality == post_quality


@pytest.mark.parametrize(
    "crashes, main_exit_codes, result, arg_sig, arg_tool",
    [
        # no crashes -> success
        ([], [], 0, None, None),
        # 1 crash fails -> no success
        ([(123, "test-tool")], [1], 1, None, None),
        # second of 3 succeeds -> success
        ([(123, "test-tool"), (456, "test-tool2")], [1, 0], 0, None, None),
        # --sig is respected
        ([(123, "test-tool")], [0], 0, "test_sig2.json", None),
        # --tool is respected
        ([(123, "test-tool")], [0], 0, None, "test-tool-arg"),
    ]
)
def test_bucket_main(mocker, crashes, main_exit_codes, result, arg_sig, arg_tool):
    """tests for `grizzly.reduce.crash.main`"""
    call_args = []

    def copy_args(args):
        call_args.append(deepcopy(args))
        return main_exit_codes[main.call_count - 1]
    mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    bucket = mocker.patch("grizzly.reduce.bucket.Bucket", autospec=True)
    main = mocker.patch("grizzly.reduce.bucket.crash_main", autospec=True,
                        side_effect=copy_args)
    bucket.return_value.signature_path.return_value = "test_sig.json"
    bucket.return_value.iter_crashes.return_value = [
        mocker.Mock(crash_id=crash, tool=tool) for crash, tool in crashes
    ]

    args = mocker.Mock(
        input=789,
        sig=arg_sig,
        tool=arg_tool,
    )
    bucket_main(args)
    assert main.call_count == len(main_exit_codes)
    for idx, (crash, tool) in enumerate(crashes[:main.call_count]):
        assert call_args[idx].input == crash
        if arg_tool is not None:
            assert call_args[idx].tool == arg_tool
        else:
            assert call_args[idx].tool is None
        if arg_sig is not None:
            assert call_args[idx].sig == arg_sig
        else:
            assert call_args[idx].sig == "test_sig.json"
