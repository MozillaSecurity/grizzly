# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Loki fuzzing library
"""
from logging import ERROR, INFO, basicConfig, getLogger
from os import SEEK_END, makedirs
from os.path import abspath, getsize
from os.path import join as pathjoin
from os.path import splitext
from random import choice, getrandbits, randint, sample
from shutil import copy
from struct import pack, unpack
from tempfile import SpooledTemporaryFile, mkdtemp
from time import strftime, time

__author__ = "Tyson Smith"

LOG = getLogger(__name__)


class Loki:
    BYTE_ORDERS = ("<", ">", "@", "!", "=")

    __slots__ = ("aggr", "byte_order")

    def __init__(self, aggression=0.0, byte_order=None):
        self.aggr = min(max(aggression, 0.0), 1.0)
        self.byte_order = byte_order

    @staticmethod
    def _fuzz_data(in_data, byte_order):
        data_size = len(in_data)
        if data_size == 1:
            pack_unit = "B"
            mask = 0xFF
        elif data_size == 2:
            pack_unit = "%sH" % (byte_order,)
            mask = 0xFFFF
        elif data_size == 4:
            pack_unit = "%sI" % (byte_order,)
            mask = 0xFFFFFFFF
        else:
            raise AssertionError("Unsupported data size: %d" % data_size)

        fuzz_op = randint(0, 4)
        if fuzz_op == 0:  # boundary
            out_data = (2 ** randint(2, data_size * 8)) + randint(-2, 2)
        elif fuzz_op == 1:  # arithmetic
            out_data = unpack(pack_unit, in_data)[0] + randint(-10, 10)
        elif fuzz_op == 2:  # interesting byte, short or int
            out_data = choice((0, 1, int(mask / 2), int(mask / 2) + 1, mask))
        elif fuzz_op == 3:  # random byte, short or int
            out_data = getrandbits(32)
        elif fuzz_op == 4:
            if data_size == 1:  # toggle
                out_data = unpack(pack_unit, in_data)[0] ^ (2 ** getrandbits(3))
            elif data_size == 2:  # multiple of 8
                out_data = randint(1, 0x1FFF) * 8
            elif data_size == 4:  # multiple of 8
                out_data = randint(1, 0x1FFFFFFF) * 8

        return pack(pack_unit, out_data & mask)

    def _fuzz(self, tgt_fp):
        tgt_fp.seek(0, SEEK_END)
        length = tgt_fp.tell()
        if length < 1:
            LOG.debug("cannot fuzz empty file")
            return
        # minimum number of mutations should be 1
        max_mutations = max(int(round(length * self.aggr)), 1)
        mutations = randint(1, max_mutations)
        LOG.debug(
            "%d of a possible %d mutations will be performed", mutations, max_mutations
        )
        if self.byte_order is not None:
            assert self.byte_order in ("<", ">", "@", "!", "=")
            byte_order = self.byte_order
        else:
            LOG.debug("using random byte order")
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
            if self.byte_order is None:
                byte_order = "<" if getrandbits(1) else ">"
            # perform mutation
            tgt_fp.seek(idx)
            out_data = self._fuzz_data(tgt_fp.read(size), byte_order)
            tgt_fp.seek(idx)
            tgt_fp.write(out_data)

    def fuzz_data(self, data):
        assert data
        assert isinstance(data, bytes)
        # open a temp file in memory for fuzzing
        with SpooledTemporaryFile(max_size=0x800000, mode="r+b") as tmp_fp:
            tmp_fp.write(data)
            self._fuzz(tmp_fp)
            tmp_fp.seek(0)
            return tmp_fp.read()

    def fuzz_file(self, in_file, count, out_dir, ext=None):
        try:
            if getsize(in_file) < 1:
                LOG.error("Input must be at least 1 byte long")
                return False
        except OSError:
            LOG.error("%r does not exists!", in_file)
            return False
        if ext is None:
            ext = splitext(in_file)[1]
        for i in range(count):
            out_file = pathjoin(out_dir, "".join(("%06d_fuzzed" % i, ext)))
            copy(in_file, out_file)
            with open(out_file, "r+b") as out_fp:
                self._fuzz(out_fp)
        return True

    @classmethod
    def main(cls, args):
        basicConfig(format="", level=INFO if not args.quiet else ERROR)
        LOG.info("Starting Loki @ %s", strftime("%Y-%m-%d %H:%M:%S"))
        LOG.info("Target template is %r", abspath(args.input))
        out_dir = args.output
        if out_dir is None:
            out_dir = mkdtemp(prefix=strftime("loki_%m-%d_%H-%M_"), dir=".")
        makedirs(out_dir, exist_ok=True)
        LOG.info("Output directory is %r", abspath(out_dir))
        count = max(args.count, 1)
        LOG.info("Generating %d fuzzed test cases...", count)
        loki = Loki(aggression=args.aggression, byte_order=args.byte_order)
        try:
            start_time = time()
            success = loki.fuzz_file(args.input, count, out_dir)
            finish_time = time() - start_time
            LOG.info("Done. Total run time %gs", finish_time)
            if success:
                LOG.info("About %gs per file", finish_time / count)
        except KeyboardInterrupt:  # pragma: no cover
            LOG.info("Ctrl+C detected.")
            success = False
        return 0 if success else 1
