# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer beautify strategy definitions.

Constants:
    HAVE_CSSBEAUTIFIER (bool): True if `cssbeautifier` module is available.
    HAVE_JSBEAUTIFIER (bool): True if `jsbeautifier` module is available.
"""
import os
import re
from abc import ABC, abstractmethod
from logging import getLogger

from lithium.testcases import TestcaseLine

try:
    import cssbeautifier

    HAVE_CSSBEAUTIFIER = True
except ImportError:  # pragma: no cover
    HAVE_CSSBEAUTIFIER = False
try:
    import jsbeautifier

    HAVE_JSBEAUTIFIER = True
except ImportError:  # pragma: no cover
    HAVE_JSBEAUTIFIER = False

from ...common.storage import TestCase
from . import Strategy, _contains_dd

LOG = getLogger(__name__)


class _BeautifyStrategy(Strategy, ABC):
    """A strategy that beautifies code in the testcase to make it more reducible.

    Implementors must define these class attributes:

    Class attributes:
        all_extensions (set(str)): Set of all file extensions to beautify.
        import_available (bool): Whether or not the beautify module was imported.
        import_name (str): The name of the beautify module imported (for error
                           reporting).
        name (str): The strategy name.
        native_extension (str): The native file extension for this type.
        tag_name (str): Tag name to search for in other (non-native) extensions.
    """

    all_extensions = None
    ignore_files = {"test_info.json", "prefs.js"}
    import_available = None
    import_name = None
    native_extension = None
    tag_name = None

    def __init__(self, testcases):
        """Initialize beautification strategy instance.

        Arguments:
            testcases (list(grizzly.common.storage.TestCase)):
                List of testcases to reduce. The object does not take ownership of the
                testcases.
        """
        super().__init__(testcases)
        self._files_to_beautify = []
        for path in self._testcase_root.glob("**/*"):
            if (
                path.is_file()
                and path.suffix in self.all_extensions
                and path.name not in self.ignore_files
            ):
                if _contains_dd(path):
                    self._files_to_beautify.append(path)
        self._current_feedback = None
        tag_bytes = self.tag_name.encode("ascii")
        self._re_tag_start = re.compile(
            br"<\s*" + tag_bytes + br".*?>", flags=re.DOTALL | re.IGNORECASE
        )
        self._re_tag_end = re.compile(
            br"</\s*" + tag_bytes + br"\s*>", flags=re.IGNORECASE
        )

    @classmethod
    def sanity_check_cls_attrs(cls):
        """Sanity check the strategy class implementation.

        Raises:
            AssertionError: Required class attributes are missing or wrong type.

        Returns:
            None
        """
        super().sanity_check_cls_attrs()
        assert isinstance(cls.all_extensions, set)
        assert all(isinstance(ext, str) for ext in cls.all_extensions)
        assert isinstance(cls.import_available, bool)
        assert isinstance(cls.import_name, str)
        assert isinstance(cls.native_extension, str)
        assert isinstance(cls.tag_name, str)

    def update(self, success, served=None):
        """Inform the strategy whether or not the last beautification yielded was good.

        Arguments:
            success (bool): Whether or not the last beautification was acceptable.
            served (list(list(str))): The list of served files for each testcase in the
                                      last beautification.

        Returns:
            None
        """
        # beautify does nothing with served. it's unlikely a beautify operation alone
        # would render a file unserved.
        assert self._current_feedback is None
        self._current_feedback = success

    @classmethod
    @abstractmethod
    def beautify_bytes(cls, data, linesep=b"\n"):
        """Perform beautification on a code buffer.

        Arguments:
            data (bytes): The code data to be beautified.
            linesep (bytes): Newline sequence used in this testcase.

        Returns:
            bytes: The beautified result.
        """

    def _chunks_to_beautify(self, before, to_beautify, file):
        """Iterate over `to_beautify` and find chunks of style/script to beautify.

        Arguments:
            before (bytes): The data preceding `to_beautify`. Used to check whether
                            `to_beautify` is already in an open <script> or <style> tag.
            to_beautify (bytes): The data to beautify.
            file (Path): The input file (used only to check if this is a .css/.js file)

        Yields:
            tuple (int,int): Slices of `to_beautify` that should be beautified.
        """
        # native extension, there's no need to search for tags
        if file.suffix == self.native_extension:
            yield (0, len(to_beautify))
            return

        # find the last <tag> preceding DDBEGIN
        last_tag_start = None
        for match in self._re_tag_start.finditer(before):
            last_tag_start = match
        in_tag_already = (
            # there was an open <tag>
            last_tag_start is not None
            # and it isn't followed by a closing </tag>
            and self._re_tag_end.search(before[last_tag_start.end(0) :]) is None
        )
        if in_tag_already:
            tag_end = self._re_tag_end.search(to_beautify)
            if tag_end is None:
                # similar to native case. DDBEGIN/END occurred inside the tag, so
                # no need to look further
                yield (0, len(to_beautify))
                return
            yield (0, tag_end.start(0))
            search_start = tag_end.end(0)
        else:
            search_start = 0

        # scan for <tag></tag> (with </tag> being optional for the last match)
        while True:
            tag_start = self._re_tag_start.search(to_beautify[search_start:])
            if tag_start is None:
                break
            chunk_start = search_start + tag_start.end(0)
            tag_end = self._re_tag_end.search(to_beautify[chunk_start:])
            if tag_end is None:
                # last </tag> was missing, stop looking
                yield (chunk_start, len(to_beautify))
                break
            yield (chunk_start, chunk_start + tag_end.start(0))
            search_start = chunk_start + tag_end.end(0)

    def __iter__(self):
        """Iterate over potential beautifications of testcases according to this
        strategy.

        The caller should evaluate each testcase set yielded, and call `update` with the
        result. The caller owns the testcases yielded, and should call `cleanup` for
        each.

        Yields:
            list(grizzly.common.storage.TestCase): list of testcases with beautification
                                                   applied
        """
        if not self.import_available:
            LOG.warning("%s not available, skipping strategy.", self.import_name)
            return

        LOG.info("Beautifying %d files", len(self._files_to_beautify))
        for file_no, file in enumerate(self._files_to_beautify):
            LOG.info(
                "Beautifying %s (file %d/%d)",
                file.relative_to(self._testcase_root),
                file_no + 1,
                len(self._files_to_beautify),
            )

            # Use Lithium just to split the file at DDBEGIN/END.
            # Lithium already has the right logic for DDBEGIN/END and line endings.
            lith_tc = TestcaseLine()
            lith_tc.load(file)
            raw = b"".join(lith_tc.parts)

            # try to determine line-endings from testcase before resorting to os.linesep
            if b"\r\n" in lith_tc.before or b"\r\n" in lith_tc.after or b"\r\n" in raw:
                linesep = b"\r\n"
            elif b"\n" in lith_tc.before or b"\n" in lith_tc.after or b"\n" in raw:
                linesep = b"\n"
            else:
                linesep = os.linesep.encode("utf-8")

            with file.open("wb") as testcase_fp:
                last = 0
                any_beautified = False
                testcase_fp.write(lith_tc.before)
                for start, end in self._chunks_to_beautify(lith_tc.before, raw, file):
                    before = raw[last:start]
                    testcase_fp.write(before)
                    to_beautify = raw[start:end]
                    LOG.debug("before: %r", to_beautify)
                    beautified = self.beautify_bytes(to_beautify, linesep)
                    LOG.debug("after: %r", beautified)
                    if beautified:
                        if before and not before.endswith(linesep):
                            beautified = linesep + beautified
                        if not beautified.endswith(linesep):
                            beautified = beautified + linesep

                        testcase_fp.write(beautified)
                        if beautified == to_beautify:
                            LOG.warning("Beautify had no effect!")
                        else:
                            any_beautified = True
                    elif to_beautify.strip():  # pragma: no cover
                        # this should never happen, but just in case...
                        # pragma: no cover
                        LOG.warning(
                            "No output from beautify! Writing %s unmodified.",
                            self.tag_name,
                        )
                        testcase_fp.write(to_beautify)  # pragma: no cover
                    last = end
                testcase_fp.write(raw[last:])
                testcase_fp.write(lith_tc.after)

                if last == 0:
                    LOG.warning("<%s> tags not found, skipping", self.tag_name)
                    continue

                if not any_beautified:
                    LOG.warning("Beautify had no effect on the file, skipping")
                    continue

            tc_hash = self._calculate_testcase_hash()
            if tc_hash in self._tried:
                LOG.info("cache hit, reverting")
                lith_tc.dump(file)
                continue

            yield TestCase.load(str(self._testcase_root), True)

            assert self._current_feedback is not None, "No feedback for last iteration"
            if self._current_feedback:
                LOG.info("%s was successful", self.name)
            else:
                LOG.warning("%s failed (reverting)", self.name)
                lith_tc.dump(file)
                self._tried.add(tc_hash)
            self._current_feedback = None


class CSSBeautify(_BeautifyStrategy):
    """Run CSS beautification on all CSS files and `<style>` tags.

    This should make the CSS more reducible if there are long lines with compound
    definitions.
    """

    all_extensions = {".css", ".htm", ".html", ".xhtml"}
    import_available = HAVE_CSSBEAUTIFIER
    import_name = "cssbeautifier"
    name = "cssbeautify"
    native_extension = ".css"
    opts = (
        ("end_with_newline", False),
        ("indent_size", 2),
        ("newline_between_rules", False),
        ("preserve_newlines", False),
    )
    tag_name = "style"

    @classmethod
    def beautify_bytes(cls, data, linesep=b"\n"):
        """Perform CSS beautification on a code buffer.

        Arguments:
            data (bytes): The code data to be beautified.
            linesep (bytes): Newline sequence used in this testcase.

        Returns:
            bytes: The beautified result.
        """
        assert cls.import_available
        linesep_u = linesep.decode("utf-8")
        data = data.decode("utf-8", errors="surrogateescape")
        beautified = cssbeautifier.beautify(data, cls.opts)
        return linesep_u.join(beautified.splitlines()).encode(
            "utf-8", errors="surrogateescape"
        )


class JSBeautify(_BeautifyStrategy):
    """Run JS beautification on all JS files and `<script>` tags.

    This should make the javascript more reducible if there are long lines with
    compound statements.
    """

    all_extensions = {".js", ".htm", ".html", ".xhtml"}
    import_available = HAVE_JSBEAUTIFIER
    import_name = "jsbeautifier"
    name = "jsbeautify"
    native_extension = ".js"
    opts = None
    tag_name = "script"
    try_catch_re = re.compile(r"(\s*try {)\r?\n\s*(.*)\r?\n\s*(}\s*catch.*)")

    @classmethod
    def beautify_bytes(cls, data, linesep=b"\n"):
        """Perform JS beautification on a code buffer.

        Arguments:
            data (bytes): The code data to be beautified.
            linesep (bytes): Newline sequence used in this testcase.

        Returns:
            bytes: The beautified result.
        """
        assert HAVE_JSBEAUTIFIER
        linesep_u = linesep.decode("utf-8")
        data = data.decode("utf-8", errors="surrogateescape")
        beautified = jsbeautifier.beautify(data, cls.opts)
        # All try/catch pairs will be expanded on their own lines
        # Collapse these pairs when only a single instruction is contained within
        beautified = cls.try_catch_re.sub(r"\1 \2 \3", beautified)
        return linesep_u.join(beautified.splitlines()).encode(
            "utf-8", errors="surrogateescape"
        )
