# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Grizzly Reducer strategy definitions
"""
from abc import ABC, abstractmethod
import json
from logging import getLogger
from pathlib import Path
import re
from shutil import rmtree
from tempfile import mkdtemp
from types import MappingProxyType

from lithium.strategies import CheckOnly, CollapseEmptyBraces as LithCollapseEmptyBraces, Minimize, \
    Strategy as LithStrategy
from lithium.testcases import TestcaseChar, TestcaseJsStr, TestcaseLine, Testcase as LithTestcase
from pkg_resources import iter_entry_points

from ..common.utils import grz_tmp
from ..common.storage import TestCase

try:
    import cssbeautifier
    HAVE_CSSBEAUTIFIER = True
except ImportError:
    HAVE_CSSBEAUTIFIER = False
try:
    import jsbeautifier
    HAVE_JSBEAUTIFIER = True
except ImportError:
    HAVE_JSBEAUTIFIER = False


LOG = getLogger(__name__)


DEFAULT_STRATEGIES = (
    "list",
    "lines",
    "cssbeautify",
    "jsbeautify",
    "collapsebraces",
)


def _load_strategies():
    """STRATEGIES is created at the end of this file.
    """
    strategies = {}
    for entry_point in iter_entry_points("grizzly_reduce_strategies"):
        try:
            strategy_cls = entry_point.load()
            strategy_cls.sanity_check_impl()
            assert (
                strategy_cls.name == entry_point.name
            ), "entry_point name mismatch, check setup.py and %s.name" % (
                strategy_cls.__name__,
            )
        except Exception as exc:  # pylint: disable=broad-except
            LOG.debug("error loading strategy type %s: %s", entry_point.name, exc)
            continue
        strategies[entry_point.name] = strategy_cls
    for strategy in DEFAULT_STRATEGIES:
        assert (
            strategy in strategies
        ), "Unknown entry in DEFAULT_STRATEGIES: %s (STRATEGIES: [%s])" % (
            strategy, ",".join(strategies)
        )
    return MappingProxyType(strategies)


class Strategy(ABC):
    """Implementors must define these class attributes:

    Attributes:
        name (str): The strategy name.
    """
    name = None

    def __init__(self, testcases):
        self._testcase_root = Path(mkdtemp(prefix="tc_", dir=grz_tmp("reduce")))
        for idx, testcase in enumerate(testcases):
            LOG.debug("Extracting testcase %d/%d", idx + 1, len(testcases))
            testpath = self._testcase_root / ("%03d" % (idx,))
            testcase.dump(str(testpath), include_details=True)

    @classmethod
    def sanity_check_impl(cls):
        assert isinstance(cls.name, str)

    @abstractmethod
    def __iter__(self):
        pass

    @abstractmethod
    def update(self, success):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwds):
        self.cleanup()

    def cleanup(self):
        rmtree(str(self._testcase_root))


class _BeautifyStrategy(Strategy, ABC):
    """Implementors must define these class attributes:

    Attributes:
        all_extensions (set(str)): Set of all file extensions to beautify.
        import_available (bool): Whether or not the beautify module was imported.
        import_name (str): The name of the beautify module imported (for error reporting).
        name (str): The strategy name.
        native_extension (str): The native file extension for this type.
        tag_name (str): Tag name to search for in other (non-native) extensions.
    """
    all_extensions = None
    blacklist_files = {"test_info.json", "prefs.js"}
    import_available = None
    import_name = None
    native_extension = None
    tag_name = None

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self._files_to_reduce = []
        for path in self._testcase_root.glob("**/*"):
            if (path.is_file() and path.suffix in self.all_extensions
                    and path.name not in self.blacklist_files):
                self._files_to_reduce.append(path)
        self._current_feedback = None
        tag_bytes = self.tag_name.encode("ascii")
        self._re_tag = re.compile(br"(<" + tag_bytes + br".*?>)(.*?)(</\s*" + tag_bytes + br"\s*>)",
                                  flags=re.DOTALL | re.IGNORECASE)
        self._re_tag_start = re.compile(br"<" + tag_bytes + br".*?>\s*$", flags=re.DOTALL | re.IGNORECASE)
        self._re_tag_end = re.compile(br"^\s*</\s*" + tag_bytes + br"\s*>", flags=re.IGNORECASE)

    @classmethod
    def sanity_check_impl(cls):
        super().sanity_check_impl()
        assert isinstance(cls.all_extensions, set)
        assert all(isinstance(ext, str) for ext in cls.all_extensions)
        assert isinstance(cls.import_available, bool)
        assert isinstance(cls.import_name, str)
        assert isinstance(cls.native_extension, str)
        assert isinstance(cls.tag_name, str)

    def update(self, success):
        assert self._current_feedback is None
        self._current_feedback = success

    @classmethod
    @abstractmethod
    def beautify_bytes(cls, data):
        pass

    def __iter__(self):
        if not self.import_available:
            LOG.warning("%s not available, skipping strategy.", self.import_name)
            return

        LOG.info("Beautifying %d files", len(self._files_to_reduce))
        for file_no, file in enumerate(self._files_to_reduce):
            LOG.info("Beautifying %s (file %d/%d)", file.relative_to(self._testcase_root), file_no + 1,
                     len(self._files_to_reduce))

            # Use Lithium just to split the file at DDBEGIN/END.
            # Lithium already has the right logic for DDBEGIN/END and line endings.
            lith_tc = TestcaseLine()
            lith_tc.load(file)
            to_reduce = b"".join(lith_tc.parts)
            # check if the DDBEGIN/END were right inside a <script> or <style> tag
            in_tag_already = (self._re_tag_start.match(lith_tc.before) is not None
                              and self._re_tag_end.match(lith_tc.after) is not None)

            if file.suffix == self.native_extension or in_tag_already:
                with file.open("wb") as testcase_fp:
                    testcase_fp.write(lith_tc.before)
                    testcase_fp.write(self.beautify_bytes(to_reduce))
                    testcase_fp.write(lith_tc.after)
            else:
                # handle html files
                pos = 0
                with file.open("wb") as testcase_fp:
                    testcase_fp.write(lith_tc.before)
                    for match in self._re_tag.finditer(to_reduce):
                        testcase_fp.write(to_reduce[pos:match.start(2)])
                        beautified = self.beautify_bytes(match.group(2))
                        if beautified:
                            if not to_reduce[pos:match.start(2)].endswith(b"\n"):
                                testcase_fp.write(b"\n")
                            testcase_fp.write(beautified)
                            if not beautified.endswith(b"\n"):
                                testcase_fp.write(b"\n")
                        pos = match.end(2)
                    testcase_fp.write(to_reduce[pos:])
                    testcase_fp.write(lith_tc.after)
                if pos == 0:
                    LOG.warning("<%s> tags not found, skipping", self.tag_name)
                    continue

            yield TestCase.load(str(self._testcase_root), False)

            assert self._current_feedback is not None, "No feedback for last iteration"
            if self._current_feedback:
                LOG.info("%s was successful", self.name)
            else:
                LOG.warning("%s failed (reverting)", self.name)
                lith_tc.dump(file)
            self._current_feedback = None


class _LithiumStrategy(Strategy, ABC):
    """Implementors must define these class attributes:

    Attributes:
        name (str): The strategy name.
        strategy_cls (lithium.strategies.Strategy): Lithium strategy type.
        testcase_cls (lithium.testcases.Testcase): Lithium testcase type.
    """
    strategy_cls = None
    testcase_cls = None

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self._current_reducer = None
        self._files_to_reduce = []
        for path in self._testcase_root.glob("**/*"):
            if path.is_file() and path.name not in {"test_info.json", "prefs.js"}:
                self._files_to_reduce.append(path)

    @classmethod
    def sanity_check_impl(cls):
        super().sanity_check_impl()
        assert issubclass(cls.strategy_cls, LithStrategy)
        assert issubclass(cls.testcase_cls, LithTestcase)

    def update(self, success):
        assert self._current_reducer is not None
        self._current_reducer.feedback(success)

    def __iter__(self):
        LOG.info("Reducing %d files", len(self._files_to_reduce))
        for file_no, file in enumerate(self._files_to_reduce):
            LOG.info("Reducing %s (file %d/%d)", file, file_no + 1, len(self._files_to_reduce))
            lithium_testcase = self.testcase_cls()  # pylint: disable=not-callable
            lithium_testcase.load(file)
            # pylint: disable=not-callable
            self._current_reducer = self.strategy_cls().reduce(lithium_testcase)
            for reduction in self._current_reducer:
                reduction.dump()
                yield TestCase.load(str(self._testcase_root), False)
            # write out the best found testcase
            self._current_reducer.testcase.dump()
            self._current_reducer = None


class Check(_LithiumStrategy):
    name = "check"
    strategy_cls = CheckOnly
    testcase_cls = TestcaseLine

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        # trim files_to_reduce, for check we don't need to run on every file
        # just once per Grizzly TestCase set is enough.
        self._files_to_reduce = self._files_to_reduce[:1]


class CollapseEmptyBraces(_LithiumStrategy):
    name = "collapsebraces"
    strategy_cls = LithCollapseEmptyBraces
    testcase_cls = TestcaseLine


class CSSBeautify(_BeautifyStrategy):
    all_extensions = {".css", ".htm", ".html", ".xhtml"}
    import_available = HAVE_CSSBEAUTIFIER
    import_name = "cssbeautifier"
    name = "cssbeautify"
    native_extension = ".css"
    opts = (
        ('end_with_newline', False),
        ('indent_size', 2),
        ('newline_between_rules', False),
        ('preserve_newlines', False),
    )
    tag_name = "style"

    @classmethod
    def beautify_bytes(cls, data):
        assert cls.import_available
        data = data.decode("utf-8", errors="surrogateescape")
        return cssbeautifier.beautify(data, cls.opts).encode("utf-8", errors="surrogateescape")


class JSBeautify(_BeautifyStrategy):
    all_extensions = {".js", ".htm", ".html", ".xhtml"}
    import_available = HAVE_JSBEAUTIFIER
    import_name = "jsbeautifier"
    name = "jsbeautify"
    native_extension = ".js"
    opts = None
    tag_name = "script"
    try_catch_re = re.compile(r"(\s*try {)\n\s*(.*)\n\s*(}\s*catch.*)")

    @classmethod
    def beautify_bytes(cls, data):
        assert HAVE_JSBEAUTIFIER
        data = data.decode("utf-8", errors="surrogateescape")

        beautified = jsbeautifier.beautify(data, cls.opts)
        # All try/catch pairs will be expanded on their own lines
        # Collapse these pairs when only a single instruction is contained within
        beautified = cls.try_catch_re.sub(r"\1 \2 \3", beautified)
        return beautified.encode("utf-8", errors="surrogateescape")


class MinimizeChars(_LithiumStrategy):
    name = "chars"
    strategy_cls = Minimize
    testcase_cls = TestcaseChar


class MinimizeJSChars(_LithiumStrategy):
    name = "jschars"
    strategy_cls = Minimize
    testcase_cls = TestcaseJsStr


class MinimizeLines(_LithiumStrategy):
    name = "lines"
    strategy_cls = Minimize
    testcase_cls = TestcaseLine


class MinimizeTestcaseList(Strategy):
    """Try removing testcases from a list of sequential testcases (eg. Grizzly result
    cache). The strategy favours testcases at the tail of the list, so for a list of
    five testcases:
                        testcases
                0       1 2 3 4 5
    iteration   1         2 3 4 5
                2       1   3 4 5
                3       1 2   4 5
                4       1 2 3   5
                5       1 2 3 4
    """
    name = "list"

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self._current_feedback = None

    def update(self, success):
        assert self._current_feedback is None
        self._current_feedback = success

    def __iter__(self):
        assert self._current_feedback is None
        idx = 0
        testcases = None
        try:
            testcases = TestCase.load(str(self._testcase_root), False)
            n_testcases = len(testcases)
            while True:
                if n_testcases <= 1:
                    LOG.info("Testcase list has length %d, not enough to reduce!", n_testcases)
                    break
                if idx >= n_testcases:
                    LOG.info("Attempted to remove every single testcase")
                    break
                # try removing the testcase at idx
                if testcases is None:
                    testcases = TestCase.load(str(self._testcase_root), False)
                    assert n_testcases == len(testcases)
                removed_ts = testcases[idx].timestamp
                testcases.pop(idx).cleanup()
                yield testcases
                testcases = None  # caller owns testcases now
                assert self._current_feedback is not None, "no feedback received!"
                if self._current_feedback:
                    # removal was success! find the testcase that matches timestamp,
                    # and remove it
                    LOG.info("Removing testcase %d/%d was successful!", idx + 1, n_testcases)
                    removed_path = None
                    for test_info in self._testcase_root.glob("*/test_info.json"):
                        info = json.loads(test_info.read_text())
                        if removed_ts == info["timestamp"]:
                            assert (
                                removed_path is None
                            ), "Duplicate testcases found with timestamp %s" % (
                                removed_ts,
                            )
                            removed_path = test_info
                    assert (
                        removed_path is not None
                    ), "No testcase found with timestamp %s" % (removed_ts,)
                    rmtree(str(removed_path.parent))
                    n_testcases -= 1
                else:
                    LOG.info("No result without testcase %d/%d", idx + 1, n_testcases)
                    idx += 1
                # reset
                self._current_feedback = None
        finally:
            if testcases is not None:
                for testcase in testcases:
                    testcase.cleanup()


STRATEGIES = _load_strategies()
