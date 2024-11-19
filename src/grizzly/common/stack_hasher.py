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
from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import suppress
from hashlib import sha1
from logging import DEBUG, INFO, basicConfig, getLogger
from os.path import basename
from re import compile as re_compile
from re import match as re_match

__all__ = ("Stack",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

# These entries pad out the stack and make bucketing more difficult
IGNORED_FRAMES = (
    "AnnotateMozCrashReason",
    "core::panicking::",
    "mozglue_static::panic_hook",
    "rust_begin_unwind",
    "RustMozCrash",
    "std::panicking::",
    "std::sys_common::backtrace::",
)
LOG = getLogger(__name__)
MAJOR_DEPTH = 5
_RE_FUNC_NAME = re_compile(r"(?P<func>.+?)[\(|\s|\<]{1}")


class StackFrame(ABC):
    __slots__ = ("function", "location", "offset", "stack_line")

    def __init__(
        self,
        function: str | None = None,
        location: str | None = None,
        offset: str | None = None,
        stack_line: str | None = None,
    ) -> None:
        self.function = function
        self.location = location
        self.offset = offset
        self.stack_line = stack_line

    def __str__(self) -> str:
        out = []
        if self.stack_line is not None:
            out.append(f"{int(self.stack_line):02d}")
        if self.function is not None:
            out.append(f"function: {self.function!r}")
        if self.location is not None:
            out.append(f"location: {self.location!r}")
        if self.offset is not None:
            out.append(f"offset: {self.offset!r}")
        return " - ".join(out)

    @classmethod
    @abstractmethod
    def from_line(cls, input_line: str) -> StackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            StackFrame
        """


class MinidumpStackFrame(StackFrame):
    @classmethod
    def from_line(cls, input_line: str) -> MinidumpStackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            MinidumpStackFrame
        """
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
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
            # check tid and stack_line are valid
            _ = int(tid)
            _ = int(stack_line)
        except ValueError:
            return None
        sframe = cls(stack_line=stack_line)
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


class GdbStackFrame(StackFrame):
    _re_gdb = re_compile(r"^#(?P<num>\d+)\s+(?P<off>0x[0-9a-f]+\sin\s)*(?P<line>.+)")

    @classmethod
    def from_line(cls, input_line: str) -> GdbStackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            GdbStackFrame
        """
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
        if "#" not in input_line:
            return None
        match = cls._re_gdb.match(input_line)
        if match is None:
            return None
        input_line = match.group("line").strip()
        if not input_line:
            return None
        sframe = cls(stack_line=match.group("num"))
        # sframe.offset = m.group("off")  # ignore binary offset for now
        # find function/method name
        match = _RE_FUNC_NAME.match(input_line)
        if match is not None:
            sframe.function = match.group("func")
        # find file name and line number
        if ") at " in input_line:
            input_line = input_line.split(") at ")[-1]
            with suppress(ValueError):
                input_line, sframe.offset = input_line.split(":")
            sframe.location = basename(input_line).split()[0]
        return sframe


class RrStackFrame(StackFrame):
    _re_rr = re_compile(r"rr\((?P<loc>.+)\+(?P<off>0x[0-9a-f]+)\)\[0x[0-9a-f]+\]")

    @classmethod
    def from_line(cls, input_line: str) -> RrStackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            RrStackFrame
        """
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
        if "rr(" not in input_line:
            return None
        match = cls._re_rr.match(input_line)
        if match is None:
            return None
        return cls(location=match.group("loc"), offset=match.group("off"))


class RustStackFrame(StackFrame):
    _re_rust_frame = re_compile(r"^\s+(?P<num>\d+):\s+0x[0-9a-f]+\s+\-\s+(?P<line>.+)")

    @classmethod
    def from_line(cls, input_line: str) -> RustStackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            RustStackFrame
        """
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
        match = cls._re_rust_frame.match(input_line)
        if match is None:
            return None
        sframe = cls(stack_line=match.group("num"))
        sframe.function = match.group("line").strip().rsplit("::h", 1)[0]
        return sframe


class SanitizerStackFrame(StackFrame):
    _re_sanitizer = re_compile(
        r"^\s*#(?P<num>\d+)\s0x[0-9a-f]+(?P<in>\sin)?\s+(?P<line>.+)"
    )

    @classmethod
    def from_line(cls, input_line: str) -> SanitizerStackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            SanitizerStackFrame
        """
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
        if "#" not in input_line:
            return None
        match = cls._re_sanitizer.match(input_line)
        if match is None:
            return None
        sframe = cls(stack_line=match.group("num"))
        input_line = match.group("line")
        # check if line is symbolized
        if match.group("in"):
            # find function/method name
            match = _RE_FUNC_NAME.match(input_line)
            if match:
                sframe.function = match.group("func")
                # remove function name
                input_line = input_line.split(" ", 1)[-1]
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


class ThreadSanitizerStackFrame(StackFrame):
    _re_tsan = re_compile(
        r"^\s*#(?P<num>\d+)\s(?P<line>.+)\s\(((?P<mod>.+)\+)?(?P<off>0x[0-9a-f]+)\)"
    )

    @classmethod
    def from_line(cls, input_line: str) -> ThreadSanitizerStackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            ThreadSanitizerStackFrame
        """
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
        if "#" not in input_line:
            return None
        match = cls._re_tsan.match(input_line)
        if match is None:
            return None
        sframe = cls(stack_line=match.group("num"))
        input_line = match.group("line")
        location_raw = basename(input_line)
        # try to parse file name and line number
        if location_raw:
            location_parts = location_raw.split()[-1].split(":")
            if location_parts and location_parts[0] != "<null>":
                sframe.location = location_parts.pop(0)
                if location_parts and location_parts[0] != "<null>":
                    sframe.offset = location_parts.pop(0)
        # use module name if file name cannot be found
        if not sframe.location:
            sframe.location = match.group("mod")
        # use module offset if line number cannot be found
        if not sframe.offset:
            sframe.offset = match.group("off")
        match = _RE_FUNC_NAME.match(input_line)
        if match is not None:
            function = match.group("func")
            if function and function != "<null>":
                sframe.function = function
        return sframe


class ValgrindStackFrame(StackFrame):
    _re_valgrind = re_compile(
        r"^==\d+==\s+(at|by)\s+0x[0-9A-F]+\:\s+(?P<func>.+?)\s+\((?P<line>.+)\)"
    )

    @classmethod
    def from_line(cls, input_line: str) -> ValgrindStackFrame | None:
        """Parse stack frame details.

        Args:
            input_line: A single line of text.

        Returns:
            ValgrindStackFrame
        """
        assert "\n" not in input_line, "Input contains unexpected new line(s)"
        if "== " not in input_line:
            return None
        match = cls._re_valgrind.match(input_line)
        if match is None:
            return None
        input_line = match.group("line")
        if input_line is None:  # pragma: no cover
            # this should not happen
            LOG.warning("failure in ValgrindStackFrame.from_line()")
            return None
        sframe = cls(function=match.group("func"))
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

    def __init__(
        self,
        frames: list[StackFrame],
        height_limit: int = 0,
        major_depth: int = MAJOR_DEPTH,
    ) -> None:
        assert height_limit >= 0
        assert major_depth >= 0
        self.frames = frames
        # use 0 for no limit
        self._height_limit = height_limit
        # use 0 for no limit for no limit
        self._major_depth = major_depth
        self._major: str | None = None
        self._minor: str | None = None

    def __str__(self) -> str:
        return "\n".join(str(frame) for frame in self.frames)

    def _calculate_hash(self, major: bool = False) -> str | None:
        """Calculate hash value from frames.

        Args:
            major: Perform major has calculation.

        Returns:
            Hash string.
        """
        if not self.frames or (major and self._major_depth < 1):
            return None

        if self._height_limit == 0:
            offset = 0
        else:
            offset = max(len(self.frames) - self._height_limit, 0)

        bucket_hash = sha1()
        major_depth = 0
        for frame in self.frames[offset:]:
            # only track depth when needed
            # and don't count ignored frames towards major hash depth
            if (major and self._major_depth > 0) and (
                not frame.function
                or not any(frame.function.startswith(x) for x in IGNORED_FRAMES)
            ):
                major_depth += 1
                if major_depth > self._major_depth:
                    break

            if frame.location is not None:
                bucket_hash.update(frame.location.encode(errors="replace"))
            if frame.function is not None:
                bucket_hash.update(frame.function.encode(errors="replace"))
            if major_depth > 1:
                # only add the offset from the top frame when calculating
                # the major hash and skip the rest
                continue
            if frame.offset is not None:
                bucket_hash.update(frame.offset.encode(errors="replace"))
        return bucket_hash.hexdigest()

    @classmethod
    def from_text(cls, input_text: str, major_depth: int = MAJOR_DEPTH) -> Stack:
        """Parse a stack trace from text. This is intended to parse the output
        from a single result. Some debuggers such as ASan and TSan can include
        multiple stacks per result.

        Args:
            input_text: Data to parse.
            major_depth: Number of frames to use to calculate the major hash. Use 0
                for no limit.

        Returns:
            Stack
        """

        frames: list[StackFrame] = []
        parser_class: type[StackFrame] | None = None
        for line in input_text.split("\n"):
            line = line.rstrip()
            if not line:
                # skip empty lines
                continue
            frame: StackFrame | None = None
            try:
                # only use a single StackFrame type
                if parser_class is None:
                    # order most to least common
                    for frame_parser in (
                        SanitizerStackFrame,
                        MinidumpStackFrame,
                        ThreadSanitizerStackFrame,
                        ValgrindStackFrame,
                        RrStackFrame,
                        RustStackFrame,
                        GdbStackFrame,
                    ):
                        frame = frame_parser.from_line(line)
                        if frame is not None:
                            LOG.debug("frame parser: %s", frame_parser.__name__)
                            parser_class = frame_parser
                            break
                else:
                    frame = parser_class.from_line(line)
            except Exception:  # pragma: no cover
                LOG.error("Error calling from_line() with: %r", line)
                raise
            if frame is None:
                continue

            if frame.stack_line is not None and frames:
                num = int(frame.stack_line)
                # check for new stack
                if num == 0:
                    # select stack to use
                    if parser_class in (SanitizerStackFrame, ThreadSanitizerStackFrame):
                        break
                    frames.clear()
                # check for out of order or missing frames
                elif frames[-1].stack_line and num - 1 != int(frames[-1].stack_line):
                    LOG.debug("scrambled logs?")
                    break
            frames.append(frame)

        return cls(frames, major_depth=major_depth)

    @property
    def height_limit(self) -> int:
        """Height limit used to calculate hash. The stack height is calculated from
        the entry point.

        Args:
            None

        Returns:
            Height limit.
        """
        return self._height_limit

    @height_limit.setter
    def height_limit(self, value: int) -> None:
        assert isinstance(value, int)
        assert value >= 0
        self._height_limit = value
        # force recalculation of hashes
        self._major = None
        self._minor = None

    @property
    def major(self) -> str | None:
        if self._major is None:
            self._major = self._calculate_hash(major=True)
        return self._major

    @property
    def minor(self) -> str | None:
        if self._minor is None:
            self._minor = self._calculate_hash()
        return self._minor


if __name__ == "__main__":
    from argparse import ArgumentParser, Namespace
    from pathlib import Path

    def main(args: Namespace) -> None:
        # set output verbosity
        if args.debug:
            basicConfig(format="[%(levelname).1s] %(message)s", level=DEBUG)
        else:
            basicConfig(format="%(message)s", level=INFO)

        with args.input.open("rb") as in_fp:
            stack = Stack.from_text(in_fp.read().decode(errors="replace"))
        for frame in stack.frames:
            LOG.info(frame)
        LOG.info("Minor: %s", stack.minor)
        LOG.info("Major: %s", stack.major)
        LOG.info("Frames: %d", len(stack.frames))

    parser = ArgumentParser()
    parser.add_argument("input", type=Path, help="File to scan for stack trace")
    parser.add_argument("-d", "--debug", action="store_true", help="Output debug info")
    main(parser.parse_args())
