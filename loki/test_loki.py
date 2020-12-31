# coding: utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from os import SEEK_END
from random import getrandbits
from struct import pack

from pytest import raises

from .args import parse_args
from .loki import Loki


def test_loki_01(tmp_path):
    """test a missing file"""
    fuzzer = Loki(aggression=0.1)
    fuzzer.fuzz_file("nofile.test", 1, out_dir=str(tmp_path))
    assert not list(tmp_path.iterdir())

def test_loki_02(tmp_path):
    """test an empty file"""
    tmp_fn = tmp_path / "input"
    tmp_fn.touch()

    out_path = tmp_path / "out"
    out_path.mkdir()

    fuzzer = Loki(aggression=0.1)
    fuzzer.fuzz_file(str(tmp_fn), 1, out_dir=str(out_path))
    assert not list(out_path.iterdir())

def test_loki_03(mocker, tmp_path):
    """test a single byte file"""
    out_path = tmp_path / "out"
    out_path.mkdir()
    # no output path provided
    fake_mkdtemp = mocker.patch(
        "loki.loki.mkdtemp",
        autospec=True,
        return_value=str(out_path)
    )

    in_data = b"A"
    tmp_fn = tmp_path / "input"
    tmp_fn.write_bytes(in_data)

    fuzzer = Loki(aggression=0.1)
    for _ in range(100):
        fuzzer.fuzz_file(str(tmp_fn), 1, out_dir=None)
        out_files = list(out_path.iterdir())
        assert len(out_files) == 1
        out_data = out_files[0].read_bytes()
        assert len(out_data) == 1
        if out_data != in_data:
            break
    assert out_data != in_data
    assert fake_mkdtemp.call_count == 1

def test_loki_04(tmp_path):
    """test a two byte file"""
    in_data = b"AB"
    tmp_fn = tmp_path / "input"
    tmp_fn.write_bytes(in_data)

    out_path = tmp_path / "out"
    out_path.mkdir()

    fuzzer = Loki(aggression=0.1)
    for _ in range(100):
        fuzzer.fuzz_file(str(tmp_fn), 1, out_dir=str(out_path))
        out_files = list(out_path.iterdir())
        assert len(out_files) == 1
        out_data = out_files[0].read_bytes()
        assert len(out_data) == 2
        if out_data != in_data:
            break
    assert out_data != in_data

def test_loki_05(tmp_path):
    """test a multi byte file"""
    in_size = 100
    in_byte = b"A"
    in_data = in_byte * in_size
    fuzz_found = False
    tmp_fn = tmp_path / "input"
    tmp_fn.write_bytes(in_data)

    out_path = tmp_path / "out"

    fuzzer = Loki(aggression=0.01)
    for _ in range(100):
        fuzzer.fuzz_file(str(tmp_fn), 1, out_dir=str(out_path))
        out_files = list(out_path.iterdir())
        assert len(out_files) == 1
        with out_files[0].open("rb") as out_fp:
            out_fp.seek(0, SEEK_END)
            assert out_fp.tell() == in_size
            out_fp.seek(0)
            for out_byte in out_fp:
                if out_byte != in_byte:
                    fuzz_found = True
                    break
        if fuzz_found:
            break
    assert fuzz_found
    assert out_path.is_dir()

def test_loki_06():
    """test fuzz_data()"""
    in_data = b"This is test DATA!"
    in_size = len(in_data)

    fuzz_found = False
    fuzzer = Loki(aggression=0.1)
    for _ in range(100):
        out_data = fuzzer.fuzz_data(in_data)
        assert len(out_data) == in_size
        if in_data not in out_data:
            fuzz_found = True
            break
    assert fuzz_found

def test_loki_07():
    """test invalid data sizes"""
    with raises(RuntimeError, match=r"Unsupported data size:"):
        Loki._fuzz_data(b"")

    with raises(RuntimeError, match=r"Unsupported data size:"):
        Loki._fuzz_data(b"123")

    with raises(RuntimeError, match=r"Unsupported data size:"):
        Loki._fuzz_data(b"12345")

def test_loki_08():
    """test endian support"""
    Loki._fuzz_data(b"1", ">")
    Loki._fuzz_data(b"1", "<")
    with raises(RuntimeError, match=r"Unsupported byte order"):
        Loki._fuzz_data(b"1", "BAD")

def test_loki_stress_01():
    """test with single byte"""
    for _ in range(1000):
        in_data = pack("B", getrandbits(8))
        assert len(Loki._fuzz_data(in_data)) == 1

def test_loki_stress_02():
    """test with two bytes"""
    in_data = b"\xff\xff"
    for _ in range(1000):
        assert len(Loki._fuzz_data(in_data)) == 2

def test_loki_stress_03():
    """test with four bytes"""
    in_data = b"TEST"
    for _ in range(1000):
        assert len(Loki._fuzz_data(in_data)) == 4

def test_main_01(mocker, tmp_path):
    """test main"""
    out_path = tmp_path / "out"
    out_path.mkdir()

    sample = tmp_path / "file.bin"
    sample.write_bytes(b"test!")

    args = mocker.Mock(
        aggression=0.1,
        count=15,
        input=str(sample),
        output=str(out_path)
    )
    Loki.main(args)

def test_args_01():
    """test parse_args()"""
    assert parse_args(argv=["sample"])
