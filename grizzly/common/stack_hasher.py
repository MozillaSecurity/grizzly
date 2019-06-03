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

__all__ = ("Stack", "StackFrame")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

import argparse
import hashlib
import logging
import os
import re

log = logging.getLogger("stack_hasher")  # pylint: disable=invalid-name

MAJOR_DEPTH = 5
MAJOR_DEPTH_RUST = 10

class StackFrame(object):
    MODE_ASAN = 0
    MODE_GDB = 1
    MODE_MINIDUMP = 2
    MODE_RR = 3
    MODE_RUST = 4
    MODE_VALGRIND = 5

    _re_func_name = re.compile(r"(?P<func>.+?)[\(|\s|\<]{1}")
    # regexs for supported stack trace lines
    _re_asan_w_syms = re.compile(r"^\s*#(?P<num>\d+)\s0x[0-9a-f]+\sin\s(?P<line>.+)")
    _re_asan_wo_syms = re.compile(r"^\s*#(?P<num>\d+)\s0x[0-9a-f]+\s+\((?P<line>.+?)(\+(?P<off>0x[0-9a-f]+))?\)")
    _re_gdb = re.compile(r"^#(?P<num>\d+)\s+(?P<off>0x[0-9a-f]+\sin\s)*(?P<line>.+)")
    _re_rr = re.compile(r"rr\((?P<loc>.+)\+(?P<off>0x[0-9a-f]+)\)\[0x[0-9a-f]+\]")
    _re_rust_frame = re.compile(r"^\s+(?P<num>\d+):\s+0x[0-9a-f]+\s+\-\s+(?P<line>.+)")
    _re_valgrind = re.compile(r"^==\d+==\s+(at|by)\s+0x[0-9A-F]+\:\s+(?P<func>.+?)\s+\((?P<line>.+)\)")

    # TODO: winddbg?
    #_re_rust_file = re.compile(r"^\s+at\s+(?P<line>.+)")
    #_re_windbg = re.compile(r"^(\(Inline\)|[a-f0-9]+)\s([a-f0-9]+|-+)\s+(?P<line>.+)\+(?P<off>0x[a-f0-9]+)")

    def __init__(self, function=None, location=None, mode=None, offset=None, stack_line=None):
        self.function = function
        self.location = location
        self.offset = offset
        self.stack_line = stack_line
        self.mode = mode


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
        # try to match symbolized ASan output line
        if parse_mode is None or parse_mode == StackFrame.MODE_ASAN:
            frame_info = cls._parse_asan_with_syms(input_line)
            if frame_info is not None:
                return StackFrame(**frame_info)
            frame_info = cls._parse_asan_wo_syms(input_line)
            if frame_info is not None:
                return StackFrame(**frame_info)

        if parse_mode is None or parse_mode == StackFrame.MODE_GDB:
            frame_info = cls._parse_gdb(input_line)
            if frame_info is not None:
                return StackFrame(**frame_info)

        if parse_mode is None or parse_mode == StackFrame.MODE_MINIDUMP:
            frame_info = cls._parse_minidump(input_line)
            if frame_info is not None:
                return StackFrame(**frame_info)

        if parse_mode is None or parse_mode == StackFrame.MODE_RR:
            frame_info = cls._parse_rr(input_line)
            if frame_info is not None:
                return StackFrame(**frame_info)

        if parse_mode is None or parse_mode == StackFrame.MODE_RUST:
            frame_info = cls._parse_rust(input_line)
            if frame_info is not None:
                return StackFrame(**frame_info)

        if parse_mode is None or parse_mode == StackFrame.MODE_VALGRIND:
            frame_info = cls._parse_valgrind(input_line)
            if frame_info is not None:
                return StackFrame(**frame_info)

        return None


    @staticmethod
    def _parse_asan_with_syms(input_line):
        if "#" not in input_line:
            return None  # no match
        m = StackFrame._re_asan_w_syms.match(input_line)
        if m is None:
            return None  # no match

        frame = {"function":None, "location":None, "mode":StackFrame.MODE_ASAN, "offset":None}
        input_line = m.group("line")
        frame["stack_line"] = m.group("num")

        # find function/method name
        m = StackFrame._re_func_name.match(input_line)
        if m is not None:
            frame["function"] = m.group("func")

        # find location (file name) and offset (line #)
        input_line = input_line.strip(")").split()[-1].split(":")
        if len(input_line) == 1:  # no line number
            input_line = input_line[0].split("+")  # look for offset
        frame["location"] = os.path.basename(input_line[0])
        if len(input_line) > 1:  # with offset
            frame["offset"] = input_line[1]

        return frame


    @staticmethod
    def _parse_asan_wo_syms(input_line):
        if "#" not in input_line:
            return None  # no match
        m = StackFrame._re_asan_wo_syms.match(input_line)
        if m is None:
            return None  # no match

        frame = {"function":None, "mode":StackFrame.MODE_ASAN, "offset":None}
        frame["stack_line"] = m.group("num")
        input_line = m.group("line")
        if input_line:
            frame["location"] = os.path.basename(input_line)
        # find location (binary) and offset
        offset = m.group("off")
        if offset:
            frame["offset"] = offset

        return frame


    @staticmethod
    def _parse_gdb(input_line):
        if "#" not in input_line:
            return None  # no match
        m = StackFrame._re_gdb.match(input_line)
        if m is None:
            return None
        frame = {"function":None, "location":None, "mode":StackFrame.MODE_GDB, "offset":None}
        frame["stack_line"] = m.group("num")
        #frame["offset"] = m.group("off")  # ignore binary offset for now
        input_line = m.group("line").strip()
        print(input_line)
        if not input_line:
            return

        # find function/method name
        m = StackFrame._re_func_name.match(input_line)
        if m is not None:
            frame["function"] = m.group("func")

        # find file name and line number
        if ") at " in input_line:
            input_line = input_line.split(") at ")[-1]
            try:
                input_line, frame["offset"] = input_line.split(":")
            except ValueError:
                pass
            frame["location"] = os.path.basename(input_line).split()[0]

        return frame


    @staticmethod
    def _parse_minidump(input_line):
        try:
            frame = {"function":None, "location":None, "mode":StackFrame.MODE_MINIDUMP, "offset":None}
            tid, frame["stack_line"], lib_name, func_name, file_name, line_no, offset = input_line.split("|")
            if int(tid) < 0 or int(frame["stack_line"]) < 0:
                return None  # invalid match
        except ValueError:
            return None  # no match

        if func_name:
            frame["function"] = func_name.strip()

        if file_name:
            if file_name.count(":") > 1:  # contains hg repo info
                frame["location"] = os.path.basename(file_name.split(":")[-2])
            else:
                frame["location"] = file_name
        elif lib_name:
            frame["location"] = lib_name.strip()

        if line_no:
            frame["offset"] = line_no.strip()
        elif offset:
            frame["offset"] = offset.strip()

        return frame


    @staticmethod
    def _parse_rr(input_line):
        if "rr(" not in input_line:
            return None  # no match
        m = StackFrame._re_rr.match(input_line)
        if m is None:
            return None
        frame = {"function":None, "mode":StackFrame.MODE_RR, "stack_line":None}

        frame["location"] = m.group("loc")
        frame["offset"] = m.group("off")

        return frame


    @staticmethod
    def _parse_rust(input_line):
        frame = None
        m = StackFrame._re_rust_frame.match(input_line)
        if m is not None:
            frame = {"mode":StackFrame.MODE_RUST, "location":None, "offset":None}
            frame["stack_line"] = m.group("num")
            frame["function"] = m.group("line").strip().rsplit("::h", 1)[0]
        # Don't bother with the file offset stuff atm
        #m = StackFrame._re_rust_file.match(input_line) if frame is None else None
        #if m is not None:
        #    frame = {"function":None, "mode":StackFrame.MODE_RUST, "offset":None, "stack_line":None}
        #    input_line = m.group("line").strip()
        #    if ":" in input_line:
        #        frame["location"], frame["offset"] = input_line.rsplit(":", 1)
        #    else:
        #        frame["location"] = input_line
        return frame


    @staticmethod
    def _parse_valgrind(input_line):
        if "== " not in input_line:
            return None  # no match
        m = StackFrame._re_valgrind.match(input_line)
        if m is None:
            return None
        frame = {"location":None, "mode":StackFrame.MODE_VALGRIND, "offset":None, "stack_line":None}
        frame["function"] = m.group("func")
        input_line = m.group("line")
        if input_line is None:
            return None  # this should not happen
        try:
            frame["location"], frame["offset"] = input_line.split(":")
            frame["location"] = frame["location"].strip()
        except ValueError:
            # trim anything from the beginning we might have missed
            frame["location"] = input_line.rsplit("(")[-1]
            if frame["location"].startswith("in "):
                frame["location"] = input_line[3:]
            frame["location"] = os.path.basename(frame["location"]).strip()
        if not frame["location"]:
            return None
        return frame


class Stack(object):
    def __init__(self, frames=None, major_depth=MAJOR_DEPTH):
        assert frames is None or isinstance(frames, list)
        self.frames = list() if frames is None else frames
        self._major_depth = major_depth
        self._major = None
        self._minor = None


    def __str__(self):
        return "\n".join(["%s" % frame for frame in self.frames])


    def _calculate_hash(self, major=False):
        h = hashlib.sha1()

        if not self.frames or (major and self._major_depth < 1):
            return None

        current_depth = 0
        for frame in self.frames:
            current_depth += 1
            if major and current_depth > self._major_depth:
                break

            if frame.location is not None:
                h.update(frame.location.encode("utf-8", errors="ignore"))

            if frame.function is not None:
                h.update(frame.function.encode("utf-8", errors="ignore"))

            if major and current_depth > 1:
                # only add the offset from the top frame when calculating
                # the major hash and skip the rest
                continue

            if frame.offset is not None:
                h.update(frame.offset.encode("utf-8", errors="ignore"))

        return h.hexdigest()


    def from_file(self, file_name):
        raise NotImplementedError()  # TODO


    @classmethod
    def from_text(cls, input_text, major_depth=MAJOR_DEPTH, parse_mode=None):
        """
        parse a stack trace from text.
        input_txt is the data to parse the trace from.
        """

        frames = list()
        prev_line = None
        parse_mode = parse_mode

        for line in reversed(input_text.split("\n")):
            if not line:
                continue  # skip empty lines
            try:
                frame = StackFrame.from_line(line, parse_mode=parse_mode)
            except Exception:
                log.error("Error calling from_line() with: %r", line)
                raise

            if frame is None:
                continue

            # avoid issues with mixed stack types
            if parse_mode is None:
                parse_mode = frame.mode
            elif parse_mode != frame.mode:
                continue  # don't mix parse modes!

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

        if frames and prev_line is not None:  # sanity check
            # assuming the first frame is 0
            if int(frames[0].stack_line) != 0:
                log.warning("First stack line %s not 0", frames[0].stack_line)
            if int(frames[-1].stack_line) != len(frames) - 1:
                log.warning("Last stack line %s not %d (frames-1)", frames[0].stack_line, len(frames) - 1)

        if frames and frames[0].mode == StackFrame.MODE_RUST and major_depth < MAJOR_DEPTH_RUST:
            major_depth = MAJOR_DEPTH_RUST

        return cls(frames=frames, major_depth=major_depth)


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
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="")

    args = parser.parse_args()

    # set output verbosity
    if os.getenv("DEBUG"):
        log_level = logging.DEBUG
        log_fmt = "[%(levelname).1s] %(message)s"
    else:
        log_level = logging.INFO
        log_fmt = "%(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    with open(args.input, "rb") as fp:
        stack = Stack.from_text(fp.read().decode("utf-8", errors="ignore"))

    for frame in stack.frames:
        log.info(frame)
    log.info("Minor: %s", stack.minor)
    log.info("Major: %s", stack.major)
    log.info("Frames: %d", len(stack.frames))
