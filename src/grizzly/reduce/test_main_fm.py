# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Unit tests for `grizzly.reduce.crash` and `grizzly.reduce.bucket`."""

from pytest import mark
from Reporter.Reporter import ServerError

from ..common.frontend import Exit
from ..common.reporter import Quality
from .bucket import main as main_wrapper
from .crash import main as crash_main

pytestmark = mark.usefixtures("tmp_path_status_db_reduce")


@mark.parametrize(
    "exit_code, pre_quality, post_quality",
    [
        (Exit.SUCCESS, Quality.UNREDUCED, Quality.ORIGINAL),
        (Exit.ERROR, Quality.UNREDUCED, Quality.REDUCER_ERROR),
        (Exit.ARGS, Quality.REQUEST_SPECIFIC, Quality.UNREDUCED),
        (Exit.ABORT, Quality.REDUCING, Quality.UNREDUCED),
        (Exit.ABORT, Quality.REDUCED, Quality.REDUCED),
        (Exit.LAUNCH_FAILURE, Quality.REQUEST_SPECIFIC, Quality.UNREDUCED),
        (Exit.FAILURE, Quality.UNREDUCED, Quality.NOT_REPRODUCIBLE),
        (Exit.FAILURE, Quality.UNREDUCED, Quality.REQUEST_SPECIFIC),
    ],
)
def test_crash_main_quality(mocker, exit_code, pre_quality, post_quality):
    """test that quality is updated"""
    reduce_main = mocker.patch(
        "grizzly.reduce.crash.reduce_main",
        return_value=exit_code,
    )
    crash = mocker.Mock(testcase_quality=pre_quality, crash_id=1)
    crash.create_signature.side_effect = RuntimeError("no sig to create")
    load_fm_data = mocker.patch("grizzly.reduce.crash.load_fm_data")
    load_fm_data.return_value.__enter__ = mocker.Mock(return_value=(crash, None))
    args = mocker.Mock(
        input=12345,
        no_repro_quality=post_quality.value,
        sig=None,
        tool=None,
    )
    assert crash_main(args) == exit_code
    # verify testcase quality was updated
    assert crash.testcase_quality == post_quality
    assert reduce_main.call_args[0][0].sig is None


def test_crash_main_server_error(mocker):
    """test that ServerError when updating quality is handled gracefully"""
    exit_code = Exit.SUCCESS
    mocker.patch(
        "grizzly.reduce.crash.reduce_main",
        return_value=exit_code,
    )
    crash = mocker.Mock(crash_id=1)
    crash.create_signature.side_effect = RuntimeError("no sig to create")
    quality_prop = mocker.PropertyMock(return_value=Quality.UNREDUCED.value)
    quality_prop.__set__ = mocker.Mock(side_effect=ServerError("server error"))
    type(crash).testcase_quality = quality_prop
    load_fm_data = mocker.patch("grizzly.reduce.crash.load_fm_data")
    load_fm_data.return_value.__enter__ = mocker.Mock(return_value=(crash, None))
    args = mocker.Mock(
        input=12345,
        no_repro_quality=Quality.NOT_REPRODUCIBLE.value,
        sig=None,
        tool=None,
    )
    assert crash_main(args) == exit_code
    assert quality_prop.__set__.call_count == 1


def test_bucket_main_wrapper_coverage(mocker):
    """test is for coverage of the wrapper function"""
    mocker.patch("grizzly.reduce.bucket.bucket_main", return_value=0)
    mocker.patch("grizzly.reduce.bucket.ReduceFuzzManagerIDQualityArgs")
    assert main_wrapper() == 0
