# coding: utf-8
"""
Loki fuzzing library
"""
from logging import basicConfig, getLogger, ERROR, INFO
from os import mkdir, SEEK_END
from os.path import abspath, getsize, isdir, splitext, join as pathjoin
from random import choice, getrandbits, randint
from struct import pack, unpack
import shutil
from tempfile import mkdtemp, SpooledTemporaryFile
from time import strftime, time


__author__ = "Tyson Smith"

LOG = getLogger(__name__)


class Loki(object):

    def __init__(self, aggression=0.0):
        self.aggr = min(max(aggression, 0.0), 1.0)

    @staticmethod
    def _fuzz_data(in_data, byte_order=None):
        data_size = len(in_data)
        if data_size == 1:
            pack_unit = "B"
            mask = 0xFF
        elif data_size == 2:
            pack_unit = "H"
            mask = 0xFFFF
        elif data_size == 4:
            pack_unit = "I"
            mask = 0xFFFFFFFF
        else:
            raise RuntimeError("Unsupported data size: %d" % data_size)

        if byte_order is None:
            # prefer little-endian
            byte_order = "<" if getrandbits(5) else ">"
        elif byte_order not in (">", "<"):
            raise RuntimeError("Unsupported byte order %r" % byte_order)
        pack_unit = "".join([byte_order, pack_unit])

        fuzz_op = randint(0, 4)
        if fuzz_op == 0:  # boundary
            out_data = (2 ** randint(2, (data_size * 8))) + randint(-2, 2)
        elif fuzz_op == 1:  # arithmetic
            out_data = unpack(pack_unit, in_data)[0] + randint(-10, 10)
        elif fuzz_op == 2:  # interesting byte, short or int
            out_data = choice((0, 1, int(mask / 2), int(mask / 2) + 1, mask))
        elif fuzz_op == 3:  # random byte, short or int
            out_data = getrandbits(32)
        elif fuzz_op == 4 and data_size == 1:  # toggle
            out_data = unpack(pack_unit, in_data)[0] ^ (2 ** getrandbits(3))
        elif fuzz_op == 4 and data_size == 2:  # multiple of a data size
            if getrandbits(1):
                out_data = randint(1, 0x1FFF) * 8
            else:
                out_data = randint(1, 0xFFF) * 16
        elif fuzz_op == 4 and data_size == 4:  # multiple of a data size
            fuzz_op = randint(0, 2)
            if fuzz_op == 0:
                out_data = randint(1, 0x1FFFFFFF) * 8
            elif fuzz_op == 1:
                out_data = randint(1, 0xFFFFFFF) * 16
            elif fuzz_op == 2:
                out_data = randint(1, 0x7FFFFFF) * 32

        return pack(pack_unit, out_data & mask)

    def _fuzz(self, tgt_fp):
        tgt_fp.seek(0, SEEK_END)
        length = tgt_fp.tell()
        if length < 1:
            raise RuntimeError("Zero length file cannot be fuzzed.")

        # minimum number of max passes should be 1
        max_passes = max(int(round(length * self.aggr)), 1)
        fuzz_passes = randint(1, max_passes)
        LOG.debug("%d of a possible %d fuzz passes will be performed", fuzz_passes, max_passes)

        max_bytes = min(length, 2) if length < 4 else 4
        for _ in range(fuzz_passes):
            if max_bytes > 1 and not getrandbits(4):  # 6.25%
                fuzz_size = max_bytes >> 1 if getrandbits(1) else max_bytes
            else:
                fuzz_size = 1
            target = randint(0, length - fuzz_size)

            tgt_fp.seek(target)
            out_data = self._fuzz_data(tgt_fp.read(fuzz_size))
            tgt_fp.seek(target)
            tgt_fp.write(out_data)

    def fuzz_data(self, data):
        assert isinstance(data, bytes)
        # open a temp file in memory for fuzzing
        with SpooledTemporaryFile(max_size=0x800000, mode="r+b") as tmp_fp:
            tmp_fp.write(data)
            self._fuzz(tmp_fp)
            tmp_fp.seek(0)
            return tmp_fp.read()

    def fuzz_file(self, in_file, count, ext=None, out_dir=None):
        start_time = time()
        LOG.info("Starting Loki @ %s", strftime("%Y-%m-%d %H:%M:%S"))

        # Analyze input test case
        LOG.info("Target template is %r", abspath(in_file))
        try:
            length = getsize(in_file)
        except OSError:
            LOG.error("%r does not exists!", in_file)
            return False

        if length < 1:
            LOG.error("Input must be at least 1 byte long")
            return False

        LOG.info("Template size in bytes is %d", length)
        if ext is None:
            ext = splitext(in_file)[1]

        # Checking output directory
        if out_dir is None:
            out_dir = mkdtemp(
                prefix=strftime("loki_%m%d%H%M_"),
                dir=".")
        elif not isdir(out_dir):
            mkdir(out_dir)
        LOG.info("Output directory is %s", abspath(out_dir))

        LOG.info("Generating %s fuzzed test cases...", count)
        for i in range(count):
            out_file = pathjoin(out_dir, "".join(("%06d_fuzzed" % i, ext)))
            shutil.copy(in_file, out_file)

            with open(out_file, "r+b") as out_fp:
                self._fuzz(out_fp)

        finish_time = time() - start_time
        LOG.info("Total run time %gs", finish_time)
        if count > 0:
            LOG.info("About %gs per file", finish_time / count)

        return True

    @staticmethod
    def splice_data(data_chunks):
        if len(data_chunks) not in (1, 2):
            return None  # one or two data blobs are required (one truncates)

        blob_pass = 1
        with SpooledTemporaryFile(max_size=0x800000, mode="r+b") as tmp_fp:
            for chunk in data_chunks:
                length = len(chunk)

                if length < 1:
                    return None  # not enough data chunks to work with

                target = randint(0, length - 1)

                if blob_pass == 1:
                    tmp_fp.write(chunk[:target])
                elif blob_pass == 2:
                    tmp_fp.write(chunk[target:])

                blob_pass += 1

            tmp_fp.seek(0)
            return tmp_fp.read()

    @classmethod
    def main(cls, args):
        basicConfig(format="", level=INFO if not args.quiet else ERROR)

        loki = Loki(aggression=args.aggression)
        try:
            loki.fuzz_file(args.input, args.count, out_dir=args.output)
        except KeyboardInterrupt:  # pragma: no cover
            LOG.info("Ctrl+C detected.")
