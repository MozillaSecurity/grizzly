# coding: utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from random import choice, getrandbits
from struct import pack
from tempfile import SpooledTemporaryFile

from pytest import mark, raises

from .args import parse_args
from .loki import Loki


@mark.parametrize(
    "in_size, aggression, byte_order",
    [
        (1, 0.1, ">"),
        (2, 0.1, "<"),
        (3, 0.1, None),
        (4, 0.1, None),
        (5, 0.5, None),
        (100, 0.2, None),
    ],
)
def test_loki_fuzz_file(tmp_path, in_size, aggression, byte_order):
    """test Loki.fuzz_file() with different file sizes"""
    in_data = b"A" * in_size
    tmp_fn = tmp_path / "input"
    tmp_fn.write_bytes(in_data)

    out_path = tmp_path / "out"
    out_path.mkdir()

    fuzzer = Loki(aggression=aggression, byte_order=byte_order)
    for _ in range(100):
        assert fuzzer.fuzz_file(str(tmp_fn), 1, str(out_path))
        out_files = list(out_path.iterdir())
        assert len(out_files) == 1
        out_data = out_files[0].read_bytes()
        assert len(out_data) == in_size
        if out_data != in_data:
            break
    else:
        raise AssertionError("failed to fuzz data")


def test_loki_01(tmp_path):
    """test Loki.fuzz_file() error cases"""
    fuzzer = Loki(aggression=0.1)
    # test missing file
    assert not fuzzer.fuzz_file("nofile.test", 1, str(tmp_path))
    assert not list(tmp_path.iterdir())
    # test empty file
    tmp_fn = tmp_path / "input"
    tmp_fn.touch()
    out_path = tmp_path / "out"
    out_path.mkdir()
    assert not fuzzer.fuzz_file(str(tmp_fn), 1, str(out_path))
    assert not list(out_path.iterdir())


def test_loki_02():
    """test Loki.fuzz_data()"""
    in_data = b"This is test DATA!"
    in_size = len(in_data)

    fuzzer = Loki(aggression=0.1)
    for _ in range(100):
        out_data = fuzzer.fuzz_data(in_data)
        assert len(out_data) == in_size
        if in_data not in out_data:
            break
    else:
        raise AssertionError("failed to fuzz data")


def test_loki_fuzz_01(mocker):
    """test Loki._fuzz()"""
    loki = Loki(aggression=1)
    # test empty input sample
    with SpooledTemporaryFile(max_size=10, mode="r+b") as tmp_fp:
        loki._fuzz(tmp_fp)
    # test multiple mutations
    with SpooledTemporaryFile(max_size=10, mode="r+b") as tmp_fp:
        tmp_fp.write(b"12345678")
        loki._fuzz(tmp_fp)
    # make remaining tests deterministic
    mocker.patch("loki.loki.getrandbits", autospec=True, return_value=1)
    mocker.patch("loki.loki.randint", autospec=True, side_effect=min)
    mocker.patch("loki.loki.sample", autospec=True, return_value=[0])
    # test multi-byte with > 3 bytes
    with SpooledTemporaryFile(max_size=10, mode="r+b") as tmp_fp:
        tmp_fp.write(b"1234")
        loki._fuzz(tmp_fp)
    # test multi-byte with > 1 byte
    with SpooledTemporaryFile(max_size=10, mode="r+b") as tmp_fp:
        tmp_fp.write(b"12")
        loki._fuzz(tmp_fp)
    # test multi-byte with 1 byte and byte order set
    loki.byte_order = ">"
    with SpooledTemporaryFile(max_size=10, mode="r+b") as tmp_fp:
        tmp_fp.write(b"1")
        loki._fuzz(tmp_fp)


def test_loki_fuzz_02(mocker):
    """test Loki._fuzz_data() paths"""
    fake_randint = mocker.patch("loki.loki.randint", autospec=True)
    # fuzz op 0
    fake_randint.side_effect = (0, 1, 1)
    Loki._fuzz_data(b"1", "<")
    # fuzz op 1
    fake_randint.side_effect = (1, 0)
    Loki._fuzz_data(b"1", "<")
    # fuzz op 2
    fake_randint.side_effect = (2,)
    Loki._fuzz_data(b"1", ">")
    # fuzz op 3
    fake_randint.side_effect = (3,)
    Loki._fuzz_data(b"1", ">")
    # fuzz op 4 & test data size 1
    fake_randint.side_effect = max
    Loki._fuzz_data(b"1", "<")
    # fuzz op 4 & test data size 2
    Loki._fuzz_data(b"12", "<")
    # fuzz op 4 & test data size 4
    fake_randint.side_effect = (4, 1)
    Loki._fuzz_data(b"1234", ">")
    # invalid data size
    with raises(AssertionError, match=r"Unsupported data size:"):
        Loki._fuzz_data(b"", ">")


def test_loki_stress_01():
    """test Loki._fuzz_data() with random input"""
    orders = ("<", ">")
    sizes = (1, 2, 4)
    for _ in range(3000):
        size = choice(sizes)
        if size == 1:
            in_data = pack("B", getrandbits(8))
        elif size == 2:
            in_data = pack("H", getrandbits(16))
        elif size == 4:
            in_data = pack("I", getrandbits(32))
        assert len(Loki._fuzz_data(in_data, choice(orders))) == size


def test_main_01(mocker, tmp_path):
    """test main()"""
    out_path = tmp_path / "out"
    out_path.mkdir()
    # no output path provided
    fake_mkdtemp = mocker.patch(
        "loki.loki.mkdtemp", autospec=True, return_value=str(out_path)
    )
    sample = tmp_path / "file.bin"
    sample.write_bytes(b"test!")
    args = mocker.Mock(
        aggression=0.1, byte_order=None, count=15, input=str(sample), output=None
    )
    assert Loki.main(args) == 0
    assert fake_mkdtemp.call_count == 1


def test_args_01(capsys):
    """test parse_args()"""
    assert parse_args(argv=["sample"])
    # invalid byte order
    with raises(SystemExit):
        parse_args(argv=["sample", "-b", "a"])
    assert "Invalid byte order" in capsys.readouterr()[1]
