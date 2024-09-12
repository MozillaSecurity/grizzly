# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Tests for interface for getting Crash and Bucket data from CrashManager API"""
import json
from zipfile import ZipFile

from FTB.ProgramConfiguration import ProgramConfiguration
from pytest import mark, raises

from .fuzzmanager import Bucket, CrashEntry, load_fm_data
from .storage import TEST_INFO


def test_bucket_01(mocker):
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


def test_bucket_02(mocker):
    """bucket setattr raises"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    bucket = Bucket(123)
    with raises(AttributeError):
        bucket.other = "data"
    assert coll.return_value.get.call_count == 0


def test_bucket_03(mocker):
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


def test_bucket_04(mocker):
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


def test_crash_01(mocker):
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


def test_crash_02(mocker):
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


@mark.parametrize(
    "file_name, passed_ext, expected",
    [
        # using existing name
        ("foo.html", None, "test.html"),
        # use default extension
        ("foo", None, "test.html"),
        # use default extension
        ("foo.", None, "test.html"),
        # add missing extension
        ("foo", "svg", "test.svg"),
        # overwrite extension
        ("foo.zip", "svg", "test.svg"),
        # bad zipfile
        ("foo.zip", None, None),
    ],
)
def test_crash_03(mocker, tmp_path, file_name, passed_ext, expected):
    """test case is not zipfile"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value.json.return_value = {
        "id": 234,
        "testcase": file_name,
    }
    with (tmp_path / file_name).open("w") as zip_fp:
        zip_fp.write("data")
    with CrashEntry(234) as crash:
        assert crash.testcase == file_name  # pre-load data dict so I can re-patch get
        coll.return_value.get.return_value = mocker.Mock(
            content=(tmp_path / file_name).read_bytes(),
            headers={"content-disposition": f'attachment; filename="bar/{file_name}"'},
        )
        assert coll.return_value.get.call_count == 1
        tests = crash.testcases(ext=passed_ext)
        assert crash._contents is not None
        if expected is not None:
            assert tests
            assert tests[-1].name == expected
        else:
            assert not tests


def test_crash_04(mocker, tmp_path):
    """crash testcase_path writes and returns testcase zip"""
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value.json.return_value = {
        "id": 234,
        "testcase": "test.zip",
    }
    # build archive containing test cases
    with ZipFile(tmp_path / "test.zip", "w") as zip_fp:
        # add files out of order
        for i in (1, 3, 2, 0):
            test = tmp_path / f"test-{i}"
            test.mkdir()
            (test / TEST_INFO).touch()
            zip_fp.write(test / TEST_INFO, arcname=f"test-{i}/{TEST_INFO}")
    with CrashEntry(234) as crash:
        assert crash.testcase == "test.zip"  # pre-load data dict so I can re-patch get
        coll.return_value.get.return_value = mocker.Mock(
            content=(tmp_path / "test.zip").read_bytes(),
            headers={"content-disposition": 'attachment; filename="tests/test.zip"'},
        )
        assert coll.return_value.get.call_count == 1
        tests = crash.testcases()
        assert len(tests) == 4
        # check order
        assert tests[0].name == "test-3"
        assert tests[1].name == "test-2"
        assert tests[2].name == "test-1"
        assert tests[3].name == "test-0"
        assert coll.return_value.get.call_count == 2
        # second call returns same path
        assert crash.testcases() == tests
        # subsets
        assert crash.testcases(subset=[0]) == [tests[0]]
        # remove second oldest test case (oldest = 0, most recent = n-1)
        tests = crash.testcases(subset=[0, 2, 3])
        assert len(tests) == 3
        assert tests[0].name == "test-3"
        assert tests[1].name == "test-1"
        assert tests[2].name == "test-0"
    assert coll.return_value.get.call_count == 2


def test_crash_05(mocker):
    """crash create_signature writes and returns signature path"""
    cfg = ProgramConfiguration("product", "platform", "os")
    mocker.patch(
        "grizzly.common.fuzzmanager.ProgramConfiguration"
    ).fromBinary.return_value = cfg
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value.json.return_value = {
        "rawStdout": "",
        "rawStderr": "",
        "rawCrashData": "ERROR: AddressSanitizer: SEGV on address 0x14 "
        "(pc 0x123 sp 0x456 bp 0x789 T0)",
    }
    with CrashEntry(123) as crash:
        assert coll.return_value.get.call_count == 0
        sig_path = crash.create_signature(None)
        assert sig_path.is_file()
        assert sig_path.with_suffix(".metadata").is_file()
        assert "AddressSanitizer" in sig_path.read_text()
        assert json.loads(sig_path.with_suffix(".metadata").read_text()) == {
            "size": 1,
            "frequent": False,
            "shortDescription": "AddressSanitizer: SEGV",
            "testcase__quality": 5,
        }
        assert coll.return_value.get.call_count == 1
        # second call returns same path
        assert crash.create_signature(None) == sig_path
    assert coll.return_value.get.call_count == 1


def test_crash_06(mocker):
    """crash create_signature raises when it can't create a signature"""
    cfg = ProgramConfiguration("product", "platform", "os")
    mocker.patch(
        "grizzly.common.fuzzmanager.ProgramConfiguration"
    ).fromBinary.return_value = cfg
    coll = mocker.patch("grizzly.common.fuzzmanager.Collector", autospec=True)
    coll.return_value.serverProtocol = "http"
    coll.return_value.serverPort = 123
    coll.return_value.serverHost = "allizom.org"
    coll.return_value.get.return_value.json.return_value = {
        "rawStdout": "",
        "rawStderr": "",
        "rawCrashData": "",
    }
    with raises(RuntimeError) as exc:
        with CrashEntry(123) as crash:
            crash.create_signature(None)
    assert "insufficient data to generate" in str(exc).lower()
    assert coll.return_value.get.call_count == 1


def test_crash_07(tmp_path):
    """test CrashEntry._subset()"""
    # test single entry
    paths = [tmp_path / "0"]
    assert CrashEntry._subset(paths.copy(), [0]) == paths
    assert CrashEntry._subset(paths.copy(), [-1]) == paths
    # out of range (should be min/max'ed)
    assert CrashEntry._subset(paths.copy(), [1]) == paths
    # duplicate index
    assert CrashEntry._subset(paths.copy(), [1, 1]) == paths
    # test multiple entries select single
    paths = [tmp_path / "0", tmp_path / "1", tmp_path / "2"]
    assert CrashEntry._subset(paths.copy(), [0]) == [paths[0]]
    assert CrashEntry._subset(paths.copy(), [1]) == [paths[1]]
    assert CrashEntry._subset(paths.copy(), [2]) == [paths[2]]
    # out of range (should be min/max'ed)
    assert CrashEntry._subset(paths.copy(), [3]) == [paths[2]]
    assert CrashEntry._subset(paths.copy(), [-3]) == [paths[0]]
    # test multiple entries select multiple
    assert CrashEntry._subset(paths.copy(), [0, 1]) == paths[:2]
    assert CrashEntry._subset(paths.copy(), [2, 1]) == paths[1:]
    assert CrashEntry._subset(paths.copy(), [0, -1]) == [paths[0], paths[-1]]
    assert CrashEntry._subset(paths.copy(), [0, 1, -1]) == paths


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
def test_load_fm_data_01(mocker, bucket_id, load_bucket):
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
