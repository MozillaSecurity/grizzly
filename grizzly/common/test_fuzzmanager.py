# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Tests for interface for getting Crash and Bucket data from CrashManager API"""
import json

from pytest import mark, raises

from .fuzzmanager import Bucket, CrashEntry, load_fm_data


def test_bucket_1(mocker):
    """bucket getattr uses data from get"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.get.return_value.json.return_value = {"testcase": "data"}
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    bucket = Bucket(123)
    assert coll.return_value.get.call_count == 0
    assert bucket.testcase == "data"
    with raises(AttributeError):
        getattr(bucket, "other")
    assert coll.return_value.get.call_count == 1


def test_bucket_2(mocker):
    """bucket setattr raises"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    bucket = Bucket(123)
    with raises(AttributeError):
        bucket.other = "data"
    assert coll.return_value.get.call_count == 0


def test_bucket_3(mocker):
    """bucket iter_crashes flattens across pages"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value.json.side_effect = [
        {
            "count": 2,
            "next": "url",
            "results": [
                {"id": 234, "testcase": "test1"},
                {"id": 345, "testcase": None},
            ],
        },
        {
            "count": 1,
            "next": None,
            "results": [
                {"id": 456, "testcase": "test2"},
            ],
        },
    ]
    bucket = Bucket(123)
    assert coll.return_value.get.call_count == 0
    crashes = list(bucket.iter_crashes(quality_filter=5))
    assert coll.return_value.get.call_count == 2
    assert coll.return_value.get.call_args_list[0][1]["params"]["include_raw"] == "0"
    assert json.loads(
        coll.return_value.get.call_args_list[0][1]["params"]["query"]
    ) == {
        "op": "AND",
        "bucket": 123,
        "testcase__quality": 5,
    }
    assert len(crashes) == 2
    assert crashes[0].crash_id == 234
    assert crashes[1].crash_id == 456


def test_bucket_4(mocker):
    """bucket signature_path writes and returns sig json and metadata"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value.json.return_value = {
        "signature": "sigdata",
        "size": 10,
        "frequent": True,
        "shortDescription": "sig desc",
        "best_quality": 0,
    }
    with Bucket(123) as bucket:
        assert coll.return_value.get.call_count == 0
        sig_path = bucket.signature_path()
        assert sig_path.is_file()
        assert sig_path.with_suffix(".metadata").is_file()
        assert sig_path.read_text() == "sigdata"
        assert json.loads(sig_path.with_suffix(".metadata").read_text()) == {
            "size": 10,
            "frequent": True,
            "shortDescription": "sig desc",
            "testcase__quality": 0,
        }
        assert coll.return_value.get.call_count == 1
        # second call returns same path
        assert bucket.signature_path() == sig_path
    assert coll.return_value.get.call_count == 1


def test_crash_1(mocker):
    """crash getattr uses data from get"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.get.return_value.json.return_value = {"testcase": "data"}
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    crash = CrashEntry(123)
    assert coll.return_value.get.call_count == 0
    assert crash.testcase == "data"
    with raises(AttributeError):
        getattr(crash, "other")
    assert coll.return_value.get.call_count == 1
    assert coll.return_value.get.call_args[1]["params"] == {"include_raw": "0"}

    # crash getattr for raw field re-gets
    coll.return_value.get.return_value.json.return_value = {"rawStderr": "stderr"}
    assert crash.rawStderr == "stderr"
    assert coll.return_value.get.call_count == 2
    assert coll.return_value.get.call_args[1]["params"] == {"include_raw": "1"}


def test_crash_2(mocker):
    """crash setattr raises except testcase_quality"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.get.return_value.json.return_value = {"testcase": "data"}
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    crash = CrashEntry(123)

    # crash setattr raises for other field
    with raises(AttributeError):
        crash.other = "data"
    assert coll.return_value.get.call_count == 0

    # crash setattr for testcase_quality works and updates data if set
    assert coll.return_value.patch.call_count == 0
    crash.testcase_quality = 5
    assert coll.return_value.get.call_count == 0
    assert coll.return_value.patch.call_count == 1
    with raises(AttributeError):
        getattr(crash, "testcase_quality")
    assert coll.return_value.get.call_count == 1
    getattr(crash, "testcase")
    assert coll.return_value.get.call_count == 1
    crash.testcase_quality = 10
    assert coll.return_value.patch.call_count == 2
    assert crash.testcase_quality == 10
    assert coll.return_value.get.call_count == 1


def test_crash_3(mocker):
    """crash testcase_path writes and returns testcase zip"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value.json.return_value = {
        "id": 234,
        "testcase": "test.bz2",
    }
    with CrashEntry(234) as crash:
        assert crash.testcase == "test.bz2"  # pre-load data dict so I can re-patch get
        coll.return_value.get.return_value = mocker.Mock(
            content=b"\x01\x02\x03",
            headers={"content-disposition"},
        )
        assert coll.return_value.get.call_count == 1
        tc_path = crash.testcase_path()
        assert tc_path.is_file()
        assert tc_path.suffix == ".bz2"
        assert tc_path.read_bytes() == b"\x01\x02\x03"
        assert coll.return_value.get.call_count == 2
        # second call returns same path
        assert crash.testcase_path() == tc_path
    assert coll.return_value.get.call_count == 2


@mark.parametrize(
    "bucket_id, load_bucket",
    [
        # Nothing to load, don't try
        (None, False),
        # Nothing to load, try
        (None, True),
        # Bucket exists, don't load it
        (111, False),
        # Bucket exists, load it
        (111, True),
    ],
)
def test_load_fm_data_1(mocker, bucket_id, load_bucket):
    """test load_fm_data()"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value = mocker.Mock(
        content=b"\x01\x02\x03",
        headers={"content-disposition"},
    )
    coll.return_value.get.return_value.json.return_value = {"bucket": bucket_id}

    with load_fm_data(123, load_bucket) as (crash, bucket):
        assert isinstance(crash, CrashEntry)
        if load_bucket and bucket_id:
            assert isinstance(bucket, Bucket)
        else:
            assert bucket is None
