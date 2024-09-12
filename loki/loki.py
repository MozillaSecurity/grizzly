# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Loki fuzzing library
"""
from __future__ import annotations

from logging import ERROR, INFO, basicConfig, getLogger
from os import SEEK_END
from pathlib import Path
from random import choice, getrandbits, randint, sample
from shutil import copy
from struct import pack, unpack
from tempfile import SpooledTemporaryFile, mkdtemp
from time import perf_counter, strftime
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from argparse import Namespace

__author__ = "Tyson Smith"

LOG = getLogger(__name__)


class Loki:
    BYTE_ORDERS = frozenset(("<", ">", "@", "!", "="))

    __slots__ = ("aggr", "byte_order")

    def __init__(self, aggression: float = 0.0, byte_order: str | None = None) -> None:
        """
        Arguments:
            aggression: Amount of fuzzing to perform. 0 for 0% up to 1.0 for 100%.
            byte_order: Used to indicate big or little endian when mutating multiple
                        bytes at once.
        """
        assert 0 <= aggression <= 1
        assert byte_order is None or byte_order in self.BYTE_ORDERS
        self.aggr = aggression
        self.byte_order = byte_order

    @staticmethod
    def _fuzz_data(in_data: bytes, byte_order: str) -> bytes:
        """Fuzz data.

        Args:
            in_data: Data to fuzz.
            byte_order: Byte order to use.

        Returns:
            Fuzzed data.
        """
        data_size = len(in_data)
        if data_size == 1:
            pack_unit = "B"
            mask = 0xFF
        elif data_size == 2:
            pack_unit = f"{byte_order}H"
            mask = 0xFFFF
        elif data_size == 4:
            pack_unit = f"{byte_order}I"
            mask = 0xFFFFFFFF
        else:
            raise RuntimeError(f"Unsupported data size: {data_size}")

        fuzz_op = randint(0, 4)
        if fuzz_op == 0:  # boundary
            out_data: int = (2 ** randint(2, data_size * 8)) + randint(-2, 2)
        elif fuzz_op == 1:  # arithmetic
            out_data = unpack(pack_unit, in_data)[0] + randint(-10, 10)
        elif fuzz_op == 2:  # interesting byte, short or int
            out_data = choice((0, 1, mask // 2, (mask // 2) + 1, mask))
        elif fuzz_op == 3:  # random byte, short or int
            out_data = getrandbits(32)
        elif fuzz_op == 4:
            if data_size == 1:  # toggle
                out_data = unpack(pack_unit, in_data)[0] ^ (2 ** getrandbits(3))
            elif data_size == 2:  # multiple of 8
                out_data = randint(1, 0x1FFF) * 8
            elif data_size == 4:  # multiple of 8
                out_data = randint(1, 0x1FFFFFFF) * 8
            else:  # pragma: no cover
                # this should be unreachable
                raise RuntimeError(f"Unsupported data size: {data_size}")
        else:  # pragma: no cover
            # this should be unreachable
            raise AssertionError(f"Invalid fuzz op: {fuzz_op}")

        return pack(pack_unit, out_data & mask)

    def _fuzz(self, tgt_fp: IO[bytes]) -> None:
        """Fuzz file data.

        Args:
            tgt_fp: Open file object.

        Returns:
            None
        """
        tgt_fp.seek(0, SEEK_END)
        length = tgt_fp.tell()
        if length < 1:
            LOG.debug("cannot fuzz empty file")
            return
        # minimum number of mutations should be 1
        max_mutations = max(round(length * self.aggr), 1)
        mutations = randint(1, max_mutations)
        LOG.debug(
            "%d of a possible %d mutations will be performed", mutations, max_mutations
        )
        if self.byte_order is not None:
            assert self.byte_order in self.BYTE_ORDERS
            byte_order = self.byte_order
        else:
            LOG.debug("using random byte order")
            byte_order = "<" if getrandbits(1) else ">"
        for count, idx in enumerate(sample(range(length), k=mutations)):
            # every few iterations randomly attempt multi-byte mutations
            if count % 10 == 0 and getrandbits(1):
                max_size = length - idx
                # target multiple bytes if possible
                if max_size > 3 and getrandbits(1):
                    size = 4
                elif max_size > 1:
                    size = 2
                else:
                    size = 1
            else:
                # target single byte
                size = 1
            # perform mutation
            tgt_fp.seek(idx)
            out_data = self._fuzz_data(tgt_fp.read(size), byte_order)
            tgt_fp.seek(idx)
            tgt_fp.write(out_data)

    def fuzz_data(self, data: bytes) -> bytes:
        """Create a fuzzed copy of the provided data.

        Args:
            data: Data to be fuzzed.

        Returns:
            Fuzzed data.
        """
        assert isinstance(data, bytes)
        # open a temp file in memory for fuzzing
        with SpooledTemporaryFile(max_size=0x800000, mode="r+b") as tmp_fp:
            tmp_fp.write(data)
            self._fuzz(tmp_fp)
            tmp_fp.seek(0)
            return tmp_fp.read()

    def fuzz_file(
        self, src: Path, count: int, dst: Path, ext: str | None = None
    ) -> bool:
        """Create fuzzed copies of the provided file.

        Args:
            src: Template file containing data to be fuzzed.
            count: Number of fuzzed copies to create.
            dst: Directory to store output.
            ext: File extension to use.

        Returns:
            True if successful otherwise False.
        """
        try:
            if src.stat().st_size < 1:
                LOG.error("Input must be at least 1 byte long")
                return False
        except FileNotFoundError:
            LOG.error("'%s' does not exist!", src)
            return False
        if ext is None:
            ext = src.suffix
        for i in range(count):
            out_file = dst / f"{i:06d}_fuzzed{ext}"
            copy(src, out_file)
            with out_file.open("r+b") as out_fp:
                self._fuzz(out_fp)
        return True

    @classmethod
    def main(cls, args: Namespace) -> int:
        basicConfig(format="", level=INFO if not args.quiet else ERROR)
        LOG.info("Starting Loki @ %s", strftime("%Y-%m-%d %H:%M:%S"))
        LOG.info("Target template is '%s'", args.input.resolve())
        out_dir = args.output
        if out_dir is None:
            out_dir = Path(mkdtemp(prefix=strftime("loki_%m-%d_%H-%M_"), dir="."))
        out_dir.mkdir(exist_ok=True)
        LOG.info("Output directory is '%s'", out_dir.resolve())
        count = max(args.count, 1)
        LOG.info("Generating %d fuzzed test cases...", count)
        loki = Loki(aggression=args.aggression, byte_order=args.byte_order)
        try:
            start_time = perf_counter()
            success = loki.fuzz_file(args.input, count, out_dir)
            finish_time = perf_counter() - start_time
            LOG.info("Done. Total run time %gs", finish_time)
            if success:
                LOG.info("About %gs per file", finish_time / count)
        except KeyboardInterrupt:  # pragma: no cover
            LOG.info("Ctrl+C detected.")
            success = False
        return 0 if success else 1
