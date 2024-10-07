# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Unit tests for `grizzly.replay.crash` and `grizzly.replay.bucket`."""
from copy import deepcopy

from pytest import mark

from ..common.fuzzmanager import Bucket, CrashEntry
from ..common.utils import Exit
from .bucket import bucket_main
from .bucket import main as main_wrapper
from .crash import main as crash_main
from .crash import modify_args


def test_crash_main(mocker):
    """test main()"""
    replay_main = mocker.patch(
        "grizzly.replay.crash.ReplayManager.main",
        return_value=0,
    )
    crash = mocker.Mock(spec=CrashEntry, crash_id=1, tool="tool-name")
    crash.create_signature.side_effect = RuntimeError("no sig to create")
    load_fm_data = mocker.patch("grizzly.replay.crash.load_fm_data")
    load_fm_data.return_value.__enter__ = mocker.Mock(return_value=(crash, None))
    args = mocker.Mock(input=12345, sig=None, tool=None)
    assert crash_main(args) == 0
    assert replay_main.call_args[0][0].sig is None


@mark.parametrize("arg_tool", [None, "arg_tool"])
@mark.parametrize("signature", [None, "bucket_sig", "crash_auto_sig"])
def test_modify_args(tmp_path, mocker, arg_tool, signature):
    """test modify_args()"""
    args = mocker.Mock(input="org_input", tool=arg_tool, sig=None)
    crash = mocker.Mock(spec=CrashEntry, tool="crash_tool")
    crash.testcases.return_value = [tmp_path / "foo-0"]
    if signature == "bucket_sig":
        bucket = mocker.Mock(spec=Bucket, bucket_id=1234)
        bucket.signature_path.return_value = signature
        crash.create_signature.side_effect = RuntimeError("no sig to create")
    elif signature == "crash_auto_sig":
        bucket = None
        sig_path = tmp_path / "sig.signature"
        sig_path.write_text("{}")
        sig_path.with_suffix(".metadata").write_text(
            '{"shortDescription":"ERROR: AddressSanitizer: SEGV on address 0x14 '
            '(pc 0x123 sp 0x456 bp 0x789 T0)"}'
        )
        crash.create_signature.return_value = sig_path
        signature = sig_path
    else:
        bucket = None
        crash.create_signature.side_effect = RuntimeError("no sig to create")
    mod = modify_args(args, crash, bucket)
    assert mod.original_crash_id == "org_input"
    assert mod.input == [tmp_path / "foo-0"]
    assert mod.tool == ("crash_tool" if arg_tool is None else arg_tool)
    assert mod.sig == signature


@mark.parametrize(
    "no_harness, org_index, expected",
    [
        # no harness default
        (True, [], [-1]),
        # no harness user specified
        (True, [1], [1]),
        # harness default
        (False, [], []),
        # harness user specified
        (False, [1], [1]),
    ],
)
def test_modify_args_test_index(mocker, no_harness, org_index, expected):
    """test modify_args()"""
    args = mocker.Mock(no_harness=no_harness, test_index=org_index)
    crash = mocker.Mock(spec=CrashEntry, tool="crash_tool")
    assert modify_args(args, crash, None).test_index == expected


@mark.parametrize(
    "crashes, main_exit_codes, result, arg_sig, arg_tool",
    [
        # no crashes -> success
        ([], [], Exit.SUCCESS, None, None),
        # 1 crash fails -> no success
        ([(123, "test-tool")], [Exit.ERROR], Exit.ERROR, None, None),
        # second of 3 succeeds -> success
        (
            [(123, "test-tool"), (456, "test-tool2")],
            [Exit.ERROR, Exit.SUCCESS],
            Exit.SUCCESS,
            None,
            None,
        ),
        # --sig is respected
        ([(123, "test-tool")], [Exit.SUCCESS], Exit.SUCCESS, "test_sig2.json", None),
        # --tool is respected
        ([(123, "test-tool")], [Exit.SUCCESS], Exit.SUCCESS, None, "test-tool-arg"),
        # abort in crash main should also abort bucket main
        ([(123, "test-tool")], [Exit.ABORT], Exit.ABORT, None, None),
    ],
)
def test_bucket_main(mocker, crashes, main_exit_codes, result, arg_sig, arg_tool):
    """tests for `grizzly.replay.bucket.bucket_main`"""
    call_args = []

    def copy_args(args):
        call_args.append(deepcopy(args))
        return main_exit_codes[main.call_count - 1]

    bucket = mocker.Mock(spec=Bucket)
    bucket.signature_path.return_value = "test_sig.json"
    bucket.iter_crashes.return_value = (
        mocker.Mock(crash_id=crash, tool=tool) for crash, tool in crashes
    )
    fake_bucket = mocker.patch("grizzly.replay.bucket.Bucket", autospec=True)
    fake_bucket.return_value.__enter__.return_value = bucket

    main = mocker.Mock(side_effect=copy_args)

    args = mocker.Mock(input=789, sig=arg_sig, tool=arg_tool)
    assert bucket_main(args, main) == result
    assert main.call_count == len(main_exit_codes)
    for idx, (crash, _tool) in enumerate(crashes[: main.call_count]):
        assert call_args[idx].input == crash
        if arg_tool is not None:
            assert call_args[idx].tool == arg_tool
        else:
            assert call_args[idx].tool is None
        if arg_sig is not None:
            assert call_args[idx].sig == arg_sig
        else:
            assert call_args[idx].sig == "test_sig.json"


def test_bucket_main_wrapper_coverage(mocker):
    """test is for coverage of the wrapper function"""
    mocker.patch("grizzly.replay.bucket.bucket_main", return_value=0)
    mocker.patch("grizzly.replay.bucket.ReplayFuzzManagerIDQualityArgs")
    assert main_wrapper() == 0
