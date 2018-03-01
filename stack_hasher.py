#!/usr/bin/env python
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

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

import argparse
import hashlib
import os
import re

# location/function/offset

# regexs for supported stack trace lines
_re_asan_w_syms = re.compile(r"^\s*#(?P<num>\d+)\s0x[0-9a-f]+\sin\s(?P<line>.+)")
_re_asan_wo_syms = re.compile(r"^\s*#(?P<num>\d+)\s0x[0-9a-f]+\s+\((?P<line>.+\+0x[0-9a-f]+)\)")
_re_gdb = re.compile(r"^#(?P<num>\d+)\s+(?P<off>0x[0-9a-f]+\sin\s)*(?P<line>.+)")
#_re_windbg = re.compile(r"^(\(Inline\)|[a-f0-9]+)\s([a-f0-9]+|-+)\s+(?P<line>.+)\+(?P<off>0x[a-f0-9]+)")

# 006fd6f4 7149b958 xul!nsLayoutUtils::AppUnitWidthOfStringBidi+0x6c

#0  __memmove_ssse3_back () at ../sysdeps/x86_64/multiarch/memcpy-ssse3-back.S:1654
#1  0x000000000041e276 in WelsDec::WelsReorderRefList (pCtx=0x7ffff7f44020)\n    at codec/decoder/core/src/manage_dec_ref.cpp:252
#2  0x0000000000400545 in main ()
#3  0x0000000000400545 in main () at test.c:5
_re_func_name = re.compile(r"(?P<func>.+?)[\(|\s]{1}")


def parse_line(line):
    # try to match symbolized ASan output line
    m = _re_asan_w_syms.match(line)
    if m is not None:
        line = m.group("line")
        line_no = m.group("num")

        # find function/method name
        m = _re_func_name.match(line)
        if m is not None:
            func = m.group("func")
        else:
            func = None

        # find location (file name) and offset (line #)
        line = line.strip(')').split()[-1].split(":")
        if len(line) == 1: # no line number
            line = line[0].split("+") # look for offset
        location = os.path.basename(line[0])
        if len(line) > 1: # with offset
            offset = line[-1]
        else:
            offset = None

        return (location, func, offset, line_no)

    # try to match unsymbolized ASan output line
    m = _re_asan_wo_syms.match(line)
    if m is not None:
        func = None
        line = m.group("line")
        line_no = m.group("num")

        # find location (binary) and offset
        line = line.split()[-1].split("+")
        location = os.path.basename(line[0])
        if len(line) > 1:
            offset = line[-1]
        else:
            offset = None

        return (location, func, offset, line_no)

    # try to match gdb output line
    m = _re_gdb.match(line)
    if m is not None:
        line = m.group("line")
        line_no = m.group("num")
        location = None
        offset = None
        bin_offset = m.group("off")

        # find function/method name
        m = _re_func_name.match(line)
        if m is not None:
            func = m.group("func")
        else:
            func = None

        # find file name and line number
        if line.find(") at ") != -1:
            line = line.split(") at ")[-1]
            try:
                line, offset = line.split(":")
            except ValueError:
                offset = None
            location = os.path.basename(line)

        if offset is None and bin_offset is not None:
            offset = bin_offset.split(" ")[0]

        return (location, func, offset, line_no)

    return None


def stack_from_text(input_txt):
    """
    parse a stack trace from text.

    input_txt is the data to parse the trace from.
    """

    prev_line = None
    stack = list()

    for line in reversed(input_txt.splitlines()):
        try:
            location, func, offset, stack_line = parse_line(line)
        except TypeError:
            continue

        stack_line = int(stack_line)
        # check if we've found a different stack in the data
        if prev_line is not None and prev_line <= stack_line:
            break
        stack.insert(0, (location, func, offset))
        if stack_line < 1:
            break
        prev_line = stack_line

    return stack


def stack_to_hash(stack, major=False, major_depth=5):
    h = hashlib.sha1()

    if not stack or (major and major_depth <= 0):
        return None

    current_depth = -1
    for location, func, offset in stack:
        current_depth += 1
        if major and current_depth >= major_depth:
            break

        if location is not None:
            h.update(location)

        if func is not None:
            h.update(func)

        if major and current_depth > 0:
            # only add the offset from the top frame
            # when calculating the major hash
            continue

        if offset is not None:
            h.update(offset)


    return h.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="")

    args = parser.parse_args()

    # asan support tests
    #print parse_line("    #1 0x7f00dad60565 in Abort(char const*) /blah/base/nsDebugImpl.cpp:472")
    #print parse_line("    #36 0x48a6e4 in main /app/nsBrowserApp.cpp:399")
    #print parse_line("    #1 0x7f00ecc1b33f (/lib/x86_64-linux-gnu/libpthread.so.0+0x1033f)")
    #print parse_line("    #25 0x7f0155526181 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x8181)")

    # gdb support tests
    #print parse_line("#0  __memmove_ssse3_back () at ../sysdeps/x86_64/multiarch/memcpy-ssse3-back.S:1654")
    #print parse_line("#1  0x000000000041e276 in WelsDec::WelsReorderRefList (pCtx=0x7ffff7f44020)\n    at codec/decoder/core/src/manage_dec_ref.cpp:252")
    #print parse_line("#2  0x0000000000400545 in main ()")
    #print parse_line("#3  0x0000000000400545 in main () at test.c:5")

    # windbg support tests
    #print parse_line("006fd6f4 7149b958 xul!nsLayoutUtils::AppUnitWidthOfStringBidi+0x6c")
    #print parse_line("006fd6f4 7149b958 xul!nsLayoutUtils::AppUnitWidthOfStringBidi+0x6c")
    #print parse_line("(Inline) -------- xul!SkTDArray<SkAAClip::Builder::Row>::append+0xc")

    with open(args.input, "r") as fp:
        stack = stack_from_text(fp.read())

    for line in stack:
        print(line)
        #if None in line:
        #    print line
    print(stack_to_hash(stack))
    print(stack_to_hash(stack, major=True))
