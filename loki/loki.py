"""
loki.py
"""
__author__ = "Tyson Smith"

import argparse
import logging
import logging.handlers
import os
import random
import struct
import shutil
import tempfile
import time

log = logging.getLogger("Loki")
log.propagate = False

class Loki(object):
    def __init__(self, aggression=0.0, verbose=False):
        self.aggr = min(max(aggression, 0.0), 1.0)

        # setup logging
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("[%(levelname).1s] %(message)s"))
        log.addHandler(ch)
        log.setLevel(logging.INFO if verbose else logging.ERROR)


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
            byte_order = "<" if random.getrandbits(5) else ">"  # prefer little-endian
        elif byte_order not in (">", "<"):
            raise RuntimeError("Unsupported byte order %r" % byte_order)
        pack_unit = "".join([byte_order, pack_unit])

        fuzz_op = random.randint(0, 4)
        if fuzz_op == 0:  # boundary
            out_data = (2**random.randint(2, (data_size * 8))) + random.randint(-2, 2)
        elif fuzz_op == 1:  # arithmetic
            out_data = struct.unpack(pack_unit, in_data)[0] + random.randint(-10, 10)
        elif fuzz_op == 2:  # interesting byte, short or int
            out_data = random.choice((0, 1, int(mask / 2), int(mask / 2) + 1, mask))
        elif fuzz_op == 3:  # random byte, short or int
            out_data = random.getrandbits(32)
        elif fuzz_op == 4 and data_size == 1:  # toggle
            out_data = struct.unpack(pack_unit, in_data)[0] ^ (2 ** random.getrandbits(3))
        elif fuzz_op == 4 and data_size == 2:  # multiple of a data size
            if random.getrandbits(1):
                out_data = random.randint(1, 0x1FFF) * 8
            else:
                out_data = random.randint(1, 0xFFF) * 16
        elif fuzz_op == 4 and data_size == 4:  # multiple of a data size
            fuzz_op = random.randint(0, 2)
            if fuzz_op == 0:
                out_data = random.randint(1, 0x1FFFFFFF) * 8
            elif fuzz_op == 1:
                out_data = random.randint(1, 0xFFFFFFF) * 16
            elif fuzz_op == 2:
                out_data = random.randint(1, 0x7FFFFFF) * 32

        return struct.pack(pack_unit, out_data & mask)


    def _fuzz(self, fp):
        fp.seek(0, os.SEEK_END)
        length = fp.tell()
        if length < 1:
            raise RuntimeError("Zero length file cannot be fuzzed.")

        # minimum number of max passes should be 1
        max_passes = max(int(round(length * self.aggr)), 1)
        fuzz_passes = random.randint(1, max_passes)
        log.debug("%d of a possible %d fuzz passes will be performed", fuzz_passes, max_passes)

        max_bytes = min(length, 2) if length < 4 else 4
        for _ in range(fuzz_passes):
            if max_bytes > 1 and not random.getrandbits(4):  # 6.25%
                fuzz_size = max_bytes >> 1 if random.getrandbits(1) else max_bytes
            else:
                fuzz_size = 1
            target = random.randint(0, length-fuzz_size)

            fp.seek(target)
            out_data = self._fuzz_data(fp.read(fuzz_size))
            fp.seek(target)
            fp.write(out_data)


    def fuzz_data(self, data):
        assert isinstance(data, bytes)
        # open a temp file in memory for fuzzing
        with tempfile.SpooledTemporaryFile(max_size=0x800000, mode="r+b") as fp:
            fp.write(data)
            self._fuzz(fp)
            fp.seek(0)
            return fp.read()


    def fuzz_file(self, in_file, count, ext=None, out_dir=None):
        start_time = time.time()
        log.info("Starting Loki @ %s", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

        # Analyze input test case
        log.info("Target template is %r", os.path.abspath(in_file))
        try:
            length = os.path.getsize(in_file)
        except OSError:
            log.error("%r does not exists!", in_file)
            return False

        if length < 1:
            log.error("Input must be at least 1 byte long")
            return False

        log.info("Template size in bytes is %d", length)
        if ext is None:
            ext = os.path.splitext(in_file)[1]

        # Checking output directory
        if out_dir is None:
            out_dir = tempfile.mkdtemp(
                prefix=time.strftime("loki_%m%d%H%M_", time.localtime()),
                dir=".")
        elif not os.path.isdir(out_dir):
            os.mkdir(out_dir)
        log.info("Output directory is %s", os.path.abspath(out_dir))

        log.info("Generating %s fuzzed test cases...", count)
        for i in range(count):
            out_file = os.path.join(out_dir, "".join(("%06d_fuzzed" % i, ext)))
            shutil.copy(in_file, out_file)

            with open(out_file, "r+b") as fp:
                self._fuzz(fp)

        finish_time = time.time()-start_time
        log.info("Total run time %gs", finish_time)
        if count > 0:
            log.info("About %gs per file", finish_time/count)

        return True


    @staticmethod
    def splice_data(data_chunks):
        if len(data_chunks) not in (1, 2):
            return None # one or two data blobs are required (one truncates)

        blob_pass = 1
        with tempfile.SpooledTemporaryFile(max_size=0x800000, mode="r+b") as fp:
            for chunk in data_chunks:
                length = len(chunk)

                if length < 1:
                    return None # not enough data chunks to work with

                target = random.randint(0, length-1)

                if blob_pass == 1:
                    fp.write(chunk[:target])
                elif blob_pass == 2:
                    fp.write(chunk[target:])

                blob_pass += 1

            fp.seek(0)
            return fp.read()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Loki fuzzing library")
    parser.add_argument(
        "input",
        help="Output will be generated based on this file")
    parser.add_argument(
        "-a", "--aggression", default=0.001, type=float,
        help="Controls how much fuzzing is done on the output file")
    parser.add_argument(
        "-c", "--count", default=100, type=int,
        help="Number test cases to generate")
    parser.add_argument(
        "-q", "--quiet", default=False, action="store_true",
        help="Display limited output")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory for fuzzed test cases")

    args = parser.parse_args()

    f = Loki(aggression=args.aggression, verbose=(not args.quiet))
    try:
        f.fuzz_file(args.input, args.count, out_dir=args.output)
    except KeyboardInterrupt:
        print("Ctrl+C detected.")
