# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.strategies.proxy`."""

from logging import getLogger

from ..common.storage import TestCase
from .strategies.proxy import (
    DeProxy,
    _common_ancestor_body,
    _find_matching_brace,
    parse_map,
    rewrite_test_file,
)

LOG = getLogger(__name__)


# A minimal but valid map file. `trees` marks type "B" as compatible with "A"
# (a read of an unassigned "B" slot may fall back to an assigned "A" slot).
MAP_JS = """\
class Objects {
  constructor(nodes) { this.nodes = nodes; }
}
const trees = {"A": ["A"], "B": ["B", "A"]};
const nodes = [
  { index: 0, tree: trees["A"] },
  { index: 1, tree: trees["B"] }
];
const o = new Proxy(new Objects(nodes), {});
"""


def _run_deproxy(best_tests, feedback):
    """Drive a DeProxy strategy over `best_tests`, replying `feedback` to each
    yielded attempt. Returns the resulting best testcase list."""
    with DeProxy(best_tests) as sgy:
        for tests in sgy:
            sgy.update(feedback)
            for test in best_tests:
                test.cleanup()
            best_tests = [x.clone() for x in tests]
    return best_tests


def test_deproxy_html(tmp_path):
    """test DeProxy() rewrites o[N] and strips the map <script> in an HTML scope"""
    html = '<script src="map.js"></script>\n<script src="test.js"></script>\n'
    test_js = "o[0] = makeA();\no[1] = makeB();\nuse(o[0]);\n"

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(html.encode("utf-8"), test.entry_point)
        test.add_from_bytes(MAP_JS.encode("utf-8"), "map.js")
        test.add_from_bytes(test_js.encode("utf-8"), "test.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        best_tests = _run_deproxy(best_tests, True)
        assert len(best_tests) == 1
        assert best_tests[0]["test.js"].read_bytes().decode("utf-8") == (
            "var o_A_0, o_B_1;\no_A_0 = makeA();\no_B_1 = makeB();\nuse(o_A_0);\n"
        )
        # the map reference is stripped from the HTML (map file left on disk)
        assert best_tests[0]["test.html"].read_bytes().decode("utf-8") == (
            '<script src="test.js"></script>\n'
        )
        assert "map.js" in best_tests[0]
    finally:
        for test in best_tests:
            test.cleanup()


def test_deproxy_importscripts(tmp_path):
    """test DeProxy() handles a service-worker importScripts() scope"""
    html = "<script>navigator.serviceWorker.register('sw.js')</script>\n"
    sw_js = 'importScripts("map.js");\no[0] = makeA();\nuse(o[0]);\n'

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(html.encode("utf-8"), test.entry_point)
        test.add_from_bytes(MAP_JS.encode("utf-8"), "map.js")
        test.add_from_bytes(sw_js.encode("utf-8"), "sw.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        best_tests = _run_deproxy(best_tests, True)
        assert best_tests[0]["sw.js"].read_bytes().decode("utf-8") == (
            "var o_A_0;\no_A_0 = makeA();\nuse(o_A_0);\n"
        )
    finally:
        for test in best_tests:
            test.cleanup()


def test_deproxy_module(tmp_path):
    """test DeProxy() handles an ES-module import scope"""
    html = '<script type="module" src="mod.js"></script>\n'
    mod_js = 'import { o } from "./map.js";\no[0] = makeA();\nuse(o[0]);\n'

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(html.encode("utf-8"), test.entry_point)
        test.add_from_bytes(MAP_JS.encode("utf-8"), "map.js")
        test.add_from_bytes(mod_js.encode("utf-8"), "mod.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        best_tests = _run_deproxy(best_tests, True)
        assert best_tests[0]["mod.js"].read_bytes().decode("utf-8") == (
            "var o_A_0;\no_A_0 = makeA();\nuse(o_A_0);\n"
        )
    finally:
        for test in best_tests:
            test.cleanup()


def test_deproxy_fallback(tmp_path):
    """test read of an unassigned slot falls back to a compatible assigned slot"""
    # index 0 -> "B" (unassigned, read only), index 1 -> "A" (assigned).
    # trees["B"] == ["B", "A"], so the o[0] read resolves to the o[1] "A" slot.
    map_js = """\
class Objects {
  constructor(nodes) { this.nodes = nodes; }
}
const trees = {"A": ["A"], "B": ["B", "A"]};
const nodes = [
  { index: 0, tree: trees["B"] },
  { index: 1, tree: trees["A"] }
];
const o = new Proxy(new Objects(nodes), {});
"""
    html = '<script src="map.js"></script>\n<script src="test.js"></script>\n'
    test_js = "o[1] = makeA();\nuse(o[0]);\n"

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(html.encode("utf-8"), test.entry_point)
        test.add_from_bytes(map_js.encode("utf-8"), "map.js")
        test.add_from_bytes(test_js.encode("utf-8"), "test.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        best_tests = _run_deproxy(best_tests, True)
        assert best_tests[0]["test.js"].read_bytes().decode("utf-8") == (
            "var o_A_1;\no_A_1 = makeA();\nuse(o_A_1);\n"
        )
    finally:
        for test in best_tests:
            test.cleanup()


def test_deproxy_no_map(tmp_path):
    """test DeProxy() is a no-op when no map file is present"""
    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b'<script src="test.js"></script>\n', test.entry_point)
        test.add_from_bytes(b"o[0] = 1;\n", "test.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        with DeProxy(best_tests) as sgy:
            assert not any(sgy)
    finally:
        for test in best_tests:
            test.cleanup()


def test_deproxy_non_utf8_sibling(tmp_path):
    """test a sibling .js with non-UTF-8 bytes does not abort the strategy"""
    html = '<script src="map.js"></script>\n<script src="test.js"></script>\n'
    test_js = "o[0] = makeA();\nuse(o[0]);\n"
    blob = b'var x = "\xff\xfe";\n'  # not valid UTF-8

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(html.encode("utf-8"), test.entry_point)
        test.add_from_bytes(MAP_JS.encode("utf-8"), "map.js")
        test.add_from_bytes(test_js.encode("utf-8"), "test.js")
        test.add_from_bytes(blob, "blob.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        best_tests = _run_deproxy(best_tests, True)
        assert best_tests[0]["test.js"].read_bytes().decode("utf-8") == (
            "var o_A_0;\no_A_0 = makeA();\nuse(o_A_0);\n"
        )
        # the non-UTF-8 file is left byte-for-byte untouched
        assert best_tests[0]["blob.js"].read_bytes() == blob
    finally:
        for test in best_tests:
            test.cleanup()


def test_deproxy_malformed_map(tmp_path):
    """test a file matching the map signatures but unparsable is skipped"""
    # matches all MAP_FILE_SIGNATURES, but `trees` is never closed so
    # _extract_balanced_braces raises ValueError
    broken_map = (
        "class Objects {}\n"
        'const trees = {"A": ["A"]\n'
        "const nodes = [\n"
        '  { index: 0, tree: trees["A"] }\n'
        "];\n"
        "const o = new Proxy(new Objects(nodes), {});\n"
    )
    html = '<script src="map.js"></script>\n<script src="test.js"></script>\n'
    test_js = "o[0] = makeA();\n"

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(html.encode("utf-8"), test.entry_point)
        test.add_from_bytes(broken_map.encode("utf-8"), "map.js")
        test.add_from_bytes(test_js.encode("utf-8"), "test.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        # the malformed map is skipped, so there is nothing to rewrite
        with DeProxy(best_tests) as sgy:
            assert not any(sgy)
        # the referenced test file is left untouched
        assert best_tests[0]["test.js"].read_bytes().decode("utf-8") == test_js
    finally:
        for test in best_tests:
            test.cleanup()


def test_deproxy_reverts(tmp_path):
    """test DeProxy() restores original file contents on failed feedback"""
    html = '<script src="map.js"></script>\n<script src="test.js"></script>\n'
    test_js = "o[0] = makeA();\nuse(o[0]);\n"

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(html.encode("utf-8"), test.entry_point)
        test.add_from_bytes(MAP_JS.encode("utf-8"), "map.js")
        test.add_from_bytes(test_js.encode("utf-8"), "test.js")
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src", catalog=True)]

    try:
        attempts = 0
        with DeProxy(best_tests) as sgy:
            for _ in sgy:
                attempts += 1
                sgy.update(False)
            # the generator reverts on failure once it resumes past the yield,
            # so by the time it is exhausted the files match the originals
            assert (sgy._testcase_root / "000" / "test.js").read_text() == test_js
            assert (sgy._testcase_root / "000" / "test.html").read_text() == html
        assert attempts == 1
    finally:
        for test in best_tests:
            test.cleanup()


def test_parse_map():
    """test parse_map() extracts node index->type and the trees table"""
    info = parse_map(MAP_JS)
    assert info["index_to_type"] == {0: "A", 1: "B"}
    assert info["trees"] == {"A": ["A"], "B": ["B", "A"]}


def test_rewrite_test_file_scoping():
    """test var declarations are placed in the smallest enclosing function body"""
    info = {"index_to_type": {0: "A"}, "trees": {"A": ["A"]}}
    text = "function f() {\no[0] = 1;\nuse(o[0]);\n}\n"
    result = rewrite_test_file(text, info)
    assert result == ("function f() {\nvar o_A_0;\no_A_0 = 1;\nuse(o_A_0);\n}\n")


def test_rewrite_test_file_no_refs():
    """test rewrite_test_file() leaves text without o[N] refs untouched"""
    info = {"index_to_type": {0: "A"}, "trees": {"A": ["A"]}}
    text = "const x = foo.o[0];\n"
    # `.o[0]` is a member access, not a proxy ref, so nothing changes
    assert rewrite_test_file(text, info) == text


def test_find_matching_brace():
    """test _find_matching_brace() ignores braces in strings and comments"""
    text = 'f() {\n  var s = "}";\n  // }\n  /* } */\n}'
    assert _find_matching_brace(text, text.index("{")) == len(text)
    assert _find_matching_brace("{ unbalanced", 0) == -1


def test_common_ancestor_body():
    """test _common_ancestor_body() selects the smallest enclosing body"""
    bodies = [(0, 100), (10, 50)]
    assert _common_ancestor_body({(10, 50)}, bodies) == (10, 50)
    # a use at module scope (None) forces module-scope placement
    assert _common_ancestor_body({(10, 50), None}, bodies) is None
    # two disjoint inner bodies share only the outer body
    assert _common_ancestor_body(
        {(10, 50), (60, 90)}, [(0, 100), (10, 50), (60, 90)]
    ) == (
        0,
        100,
    )
