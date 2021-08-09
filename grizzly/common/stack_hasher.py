#!/usr/bin/env python
# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
stack_hasher will take input text, parse out the stack trace and hash based on
the stack. When using to bucket crashes it is helpful to make two hashes, one
of the entire stack and the second that is less sensitive using the first few
entries on the top of the stack with the offsets removed. This returns a unique
crash id (1st hash) and a bug id (2nd hash). This is not perfect but works very
well in most cases.
"""
from enum import Enum, unique
from hashlib import sha1
from logging import DEBUG, INFO, basicConfig, getLogger
from os.path import basename
from re import compile as re_compile
from re import match as re_match

__all__ = ("Stack", "StackFrame")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)

MAJOR_DEPTH = 5
MAJOR_DEPTH_RUST = 10


@unique
class Mode(Enum):
    """Parse mode for detected stack type"""

    GDB = 0
    MINIDUMP = 1
    RR = 2
    RUST = 3
    SANITIZER = 4
    TSAN = 5
    VALGRIND = 6


class StackFrame:
    _re_func_name = re_compile(r"(?P<func>.+?)[\(|\s|\<]{1}")
    # regexs for supported stack trace lines
    _re_gdb = re_compile(r"^#(?P<num>\d+)\s+(?P<off>0x[0-9a-f]+\sin\s)*(?P<line>.+)")
    _re_rr = re_compile(r"rr\((?P<loc>.+)\+(?P<off>0x[0-9a-f]+)\)\[0x[0-9a-f]+\]")
    _re_rust_frame = re_compile(r"^\s+(?P<num>\d+):\s+0x[0-9a-f]+\s+\-\s+(?P<line>.+)")
    _re_sanitizer = re_compile(
        r"^\s*#(?P<num>\d+)\s0x[0-9a-f]+(?P<in>\sin)?\s+(?P<line>.+)"
    )
    _re_tsan = re_compile(
        r"^\s*#(?P<num>\d+)\s(?P<line>.+)\s\(((?P<mod>.+)\+)?(?P<off>0x[0-9a-f]+)\)"
    )
    _re_valgrind = re_compile(
        r"^==\d+==\s+(at|by)\s+0x[0-9A-F]+\:\s+(?P<func>.+?)\s+\((?P<line>.+)\)"
    )
    # TODO: add additional debugger support?
    # _re_rust_file = re_compile(r"^\s+at\s+(?P<line>.+)")
    # _re_windbg = re_compile(
    #   r"^(\(Inline\)|[a-f0-9]+)\s([a-f0-9]+|-+)\s+(?P<line>.+)\+(?P<off>0x[a-f0-9]+)"
    # )

    __slots__ = ("function", "location", "mode", "offset", "stack_line")

    def __init__(
        self, function=None, location=None, mode=None, offset=None, stack_line=None
    ):
        self.function = function
        self.location = location
        self.mode = mode
        self.offset = offset
        self.stack_line = stack_line

    def __str__(self):
        out = []
        if self.stack_line is not None:
            out.append("%02d" % int(self.stack_line))
        if self.function is not None:
            out.append("function: %r" % self.function)
        if self.location is not None:
            out.append("location: %r" % self.location)
        if self.offset is not None:
            out.append("offset: %r" % self.offset)
        return " - ".join(out)

    @classmethod
    def from_line(cls, input_line, parse_mode=None):
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
        sframe = None
        if parse_mode is None or parse_mode == Mode.SANITIZER:
            sframe = cls._parse_sanitizer(input_line)
        if not sframe and parse_mode is None or parse_mode == Mode.GDB:
            sframe = cls._parse_gdb(input_line)
        if not sframe and parse_mode is None or parse_mode == Mode.MINIDUMP:
            sframe = cls._parse_minidump(input_line)
        if not sframe and parse_mode is None or parse_mode == Mode.RR:
            sframe = cls._parse_rr(input_line)
        if not sframe and parse_mode is None or parse_mode == Mode.RUST:
            sframe = cls._parse_rust(input_line)
        if not sframe and parse_mode is None or parse_mode == Mode.TSAN:
            sframe = cls._parse_tsan(input_line)
        if not sframe and parse_mode is None or parse_mode == Mode.VALGRIND:
            sframe = cls._parse_valgrind(input_line)
        return sframe

    @classmethod
    def _parse_gdb(cls, input_line):
        if "#" not in input_line:
            return None
        match = cls._re_gdb.match(input_line)
        if match is None:
            return None
        input_line = match.group("line").strip()
        if not input_line:
            return None
        sframe = cls(mode=Mode.GDB, stack_line=match.group("num"))
        # sframe.offset = m.group("off")  # ignore binary offset for now
        # find function/method name
        match = cls._re_func_name.match(input_line)
        if match is not None:
            sframe.function = match.group("func")
        # find file name and line number
        if ") at " in input_line:
            input_line = input_line.split(") at ")[-1]
            try:
                input_line, sframe.offset = input_line.split(":")
            except ValueError:
                pass
            sframe.location = basename(input_line).split()[0]
        return sframe

    @classmethod
    def _parse_minidump(cls, input_line):
        try:
            (
                tid,
                stack_line,
                lib_name,
                func_name,
                file_name,
                line_no,
                offset,
            ) = input_line.split("|")
            if int(tid) < 0 or int(stack_line) < 0:
                return None
        except ValueError:
            return None
        sframe = cls(mode=Mode.MINIDUMP, stack_line=stack_line)
        if func_name:
            sframe.function = func_name.strip()
        if file_name:
            if file_name.count(":") > 1:
                # contains hg repo info
                sframe.location = basename(file_name.split(":")[-2])
            else:
                sframe.location = file_name
        elif lib_name:
            sframe.location = lib_name.strip()
        if line_no:
            sframe.offset = line_no.strip()
        elif offset:
            sframe.offset = offset.strip()
        return sframe

    @classmethod
    def _parse_rr(cls, input_line):
        if "rr(" not in input_line:
            return None
        match = cls._re_rr.match(input_line)
        if match is None:
            return None
        return cls(location=match.group("loc"), mode=Mode.RR, offset=match.group("off"))

    @classmethod
    def _parse_rust(cls, input_line):
        match = cls._re_rust_frame.match(input_line)
        if match is None:
            return None
        sframe = cls(mode=Mode.RUST, stack_line=match.group("num"))
        sframe.function = match.group("line").strip().rsplit("::h", 1)[0]
        # Don't bother with the file offset stuff atm
        # match = cls._re_rust_file.match(input_line) if frame is None else None
        # if match is not None:
        #    frame = {
        #        "function": None,
        #        "mode": Mode.RUST,
        #        "offset": None,
        #        "stack_line": None,
        #    }
        #    input_line = match.group("line").strip()
        #    if ":" in input_line:
        #        frame["location"], frame["offset"] = input_line.rsplit(":", 1)
        #    else:
        #        frame["location"] = input_line
        return sframe

    @classmethod
    def _parse_sanitizer(cls, input_line):
        if "#" not in input_line:
            return None
        match = cls._re_sanitizer.match(input_line)
        if match is None:
            return None
        sframe = cls(mode=Mode.SANITIZER, stack_line=match.group("num"))
        input_line = match.group("line")
        # check if line is symbolized
        if match.group("in"):
            # find function/method name
            match = cls._re_func_name.match(input_line)
            if match is not None:
                sframe.function = match.group("func")
        if input_line.startswith("("):
            input_line = input_line.strip("()")
        # find location (file name or module) and offset (line # or offset)
        offset = re_match(r"(.+?)(\:([0-9a-f]+)|\+(0x[0-9a-f]+)).*", input_line)
        if offset:
            sframe.location = basename(offset.group(1))
            sframe.offset = offset.group(3) or offset.group(4)
        else:
            sframe.location = input_line
        return sframe

    @classmethod
    def _parse_tsan(cls, input_line):
        if "#" not in input_line:
            return None
        match = cls._re_tsan.match(input_line)
        if match is None:
            return None
        sframe = cls(mode=Mode.TSAN, stack_line=match.group("num"))
        input_line = match.group("line")
        location = basename(input_line)
        # try to parse file name and line number
        if location:
            location = location.split()[-1].split(":")
            if location and location[0] != "<null>":
                sframe.location = location.pop(0)
                if location and location[0] != "<null>":
                    sframe.offset = location.pop(0)
        # use module name if file name cannot be found
        if not sframe.location:
            sframe.location = match.group("mod")
        # use module offset if line number cannot be found
        if not sframe.offset:
            sframe.offset = match.group("off")
        match = cls._re_func_name.match(input_line)
        if match is not None:
            function = match.group("func")
            if function and function != "<null>":
                sframe.function = function
        return sframe

    @classmethod
    def _parse_valgrind(cls, input_line):
        if "== " not in input_line:
            return None
        match = cls._re_valgrind.match(input_line)
        if match is None:
            return None
        input_line = match.group("line")
        if input_line is None:  # pragma: no cover
            # this should not happen
            LOG.warning("failure in _parse_valgrind()")
            return None
        sframe = cls(function=match.group("func"), mode=Mode.VALGRIND)
        try:
            location, sframe.offset = input_line.split(":")
            sframe.location = location.strip()
        except ValueError:
            # trim anything from the beginning we might have missed
            location = input_line.rsplit("(")[-1]
            if location.startswith("in "):
                location = input_line[3:]
            sframe.location = basename(location)
        if not sframe.location:
            return None
        return sframe


class Stack:
    __slots__ = ("frames", "_height_limit", "_major", "_major_depth", "_minor")

    def __init__(self, frames=None, hight_limit=None, major_depth=MAJOR_DEPTH):
        assert frames is None or isinstance(frames, list)
        self.frames = list() if frames is None else frames
        self._height_limit = hight_limit
        self._major_depth = major_depth
        self._major = None
        self._minor = None

    def __str__(self):
        return "\n".join(str(frame) for frame in self.frames)

    def _calculate_hash(self, major=False):
        if not self.frames or (major and self._major_depth < 1):
            return None
        shash = sha1()
        if self._height_limit is None:
            offset = 0
        else:
            offset = max(len(self.frames) - self._height_limit, 0)
        for depth, frame in enumerate(self.frames[offset:], start=1):
            if major and depth > self._major_depth:
                break
            if frame.location is not None:
                shash.update(frame.location.encode("utf-8", errors="ignore"))
            if frame.function is not None:
                shash.update(frame.function.encode("utf-8", errors="ignore"))
            if major and depth > 1:
                # only add the offset from the top frame when calculating
                # the major hash and skip the rest
                continue
            if frame.offset is not None:
                shash.update(frame.offset.encode("utf-8", errors="ignore"))
        return shash.hexdigest()

    def from_file(self, file_name):  # pragma: no cover
        raise NotImplementedError()  # TODO

    @classmethod
    def from_text(cls, input_text, major_depth=MAJOR_DEPTH, parse_mode=None):
        """
        parse a stack trace from text.
        input_txt is the data to parse the trace from.
        """

        frames = list()
        prev_line = None
        for line in reversed(input_text.split("\n")):
            if not line:
                # skip empty lines
                continue
            try:
                frame = StackFrame.from_line(line, parse_mode=parse_mode)
            except Exception:  # pragma: no cover
                LOG.error("Error calling from_line() with: %r", line)
                raise
            if frame is None:
                continue

            # avoid issues with mixed stack types
            if parse_mode is None:
                parse_mode = frame.mode
                LOG.debug("parser mode: %s", parse_mode.name)
            elif parse_mode != frame.mode:
                # don't mix parse modes!
                continue

            if frame.stack_line is not None:
                stack_line = int(frame.stack_line)
                # check if we've found a different stack in the data
                if prev_line is not None and prev_line <= stack_line:
                    break
                frames.insert(0, frame)
                if stack_line < 1:
                    break
                prev_line = stack_line
            else:
                frames.insert(0, frame)

        # sanity check
        if frames and prev_line is not None:
            # assuming the first frame is 0
            if int(frames[0].stack_line) != 0:
                LOG.warning("First stack line %s not 0", frames[0].stack_line)
            if int(frames[-1].stack_line) != len(frames) - 1:
                LOG.warning(
                    "Last stack line %s not %d (frames-1)",
                    frames[0].stack_line,
                    len(frames) - 1,
                )

        if frames and frames[0].mode == Mode.RUST and major_depth < MAJOR_DEPTH_RUST:
            major_depth = MAJOR_DEPTH_RUST

        return cls(frames=frames, major_depth=major_depth)

    @property
    def height_limit(self):
        return self._height_limit

    @height_limit.setter
    def height_limit(self, value):
        if value is not None:
            assert isinstance(value, int)
            assert value > 0
        self._height_limit = value
        # force recalculation of hashes
        self._major = None
        self._minor = None

    @property
    def major(self):
        if self._major is None:
            self._major = self._calculate_hash(major=True)
        return self._major

    @property
    def minor(self):
        if self._minor is None:
            self._minor = self._calculate_hash()
        return self._minor


if __name__ == "__main__":
    from argparse import ArgumentParser
    from os import getenv  # pylint: disable=ungrouped-imports

    # set output verbosity
    if getenv("DEBUG"):
        basicConfig(
            format="[%(levelname).1s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=DEBUG,
        )
    else:
        basicConfig(format="%(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=INFO)

    def main(args):
        with open(args.input, "rb") as in_fp:
            stack = Stack.from_text(in_fp.read().decode("utf-8", errors="ignore"))
        for frame in stack.frames:
            LOG.info(frame)
        LOG.info("Minor: %s", stack.minor)
        LOG.info("Major: %s", stack.major)
        LOG.info("Frames: %d", len(stack.frames))

    parser = ArgumentParser()
    parser.add_argument("input", help="File to scan for stack trace")
    main(parser.parse_args())
