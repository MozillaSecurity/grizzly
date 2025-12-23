# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.strategies.beautifulsoup`."""

from logging import getLogger

from pytest import mark, param

from ..common.storage import TestCase
from .strategies.beautifulsoup import BeautifulSoupCSSMerge, BeautifulSoupPrettify

LOG = getLogger(__name__)


@mark.parametrize(
    "test_data, reduced",
    [
        param("", "", id="no data"),
        param(
            "<br/>",
            "<br/>\n",
            id="add final new line",
        ),
        param(
            "<br><br>\n",
            "<br/>\n<br/>\n",
            id="add line breaks between tags",
        ),
        param(
            "<p>test</p>\n",
            "<p>\ntest\n</p>\n",
            id="add line breaks between tags and text",
        ),
        param(
            "<div>a</div>\n<!-- DDBEGIN -->\n<p>b</p>\n<!-- DDEND-->\n<div>c</div>",
            "<div>a</div>\n<!-- DDBEGIN -->\n<p>\nb\n</p>\n<!-- DDEND-->\n<div>c</div>",
            id="DDBEGIN and DDEND",
        ),
        param(
            "<br/>\n",
            "<br/>\n",
            id="no changes needed",
        ),
        param(
            "<br/>\r\n",
            "<br/>\n",
            id="normalize windows line endings",
        ),
        param(
            "<br/>\r",
            "<br/>\n",
            id="normalize mac line endings",
        ),
        param(
            "<div>",
            "<div></div>\n",
            id="add missing close tag",
        ),
        param(
            "<div></div>\n",
            "<div></div>\n",
            id="keep empty tags closed",
        ),
        param(
            "<div>\n</div>\n",
            "<div></div>\n",
            id="collapse empty tags closed",
        ),
        param(
            "<div>test<div>nested</div><div></div></div>\n",
            "<div>\ntest\n<div>\nnested\n</div>\n<div></div>\n</div>\n",
            id="split text and tags",
        ),
        param(
            "<div><br/></div>\n",
            "<div>\n<br/>\n</div>\n",
            id="split tags with nested tags that do not contain text",
        ),
        param(
            "<script>let a='<a>'</script>\n",
            "<script>\nlet a='<a>'\n</script>\n",
            id="script tags",
        ),
    ],
)
def test_beautifulsoup_prettify(test_data, reduced, mocker, tmp_path):
    """test BeautifulSoupPrettify() successful attempts"""
    mocker.patch(
        "grizzly.reduce.strategies.beautifulsoup._contains_dd", return_value=True
    )

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(test_data.encode("utf-8"), test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupPrettify(best_tests) as sgy:
            for tests in sgy:
                sgy.update(True)
                for test in best_tests:
                    test.cleanup()
                best_tests = [x.clone() for x in tests]
        assert len(best_tests) == 1
        assert best_tests[0]["test.html"].read_bytes().decode("utf-8") == reduced
    finally:
        for test in best_tests:
            test.cleanup()


def test_beautifulsoup_no_effect(mocker, tmp_path):
    """test BeautifulSoupPrettify() had no effect"""
    mocker.patch(
        "grizzly.reduce.strategies.beautifulsoup._contains_dd", return_value=True
    )

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"<br/>\n", test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupPrettify(best_tests) as sgy:
            assert not any(sgy)
    finally:
        for test in best_tests:
            test.cleanup()


def test_beautifulsoup_prettify_failed(mocker, tmp_path):
    """test BeautifulSoupPrettify() failed attempt"""
    mocker.patch(
        "grizzly.reduce.strategies.beautifulsoup._contains_dd", return_value=True
    )

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"<br>", test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupPrettify(best_tests) as sgy:
            count = 0
            for _ in sgy:
                sgy.update(False)
                count += 1
            assert count > 0
    finally:
        for test in best_tests:
            test.cleanup()


def test_beautifulsoup_prettify_not_available(tmp_path):
    """test BeautifulSoupPrettify() beautifulsoup4 not available"""

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"foo", test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupPrettify(best_tests) as sgy:
            sgy.import_available = False
            assert not any(sgy)
    finally:
        for test in best_tests:
            test.cleanup()


def test_beautifulsoup_prettify_ignore_unsupported_files(mocker, tmp_path):
    """test BeautifulSoupPrettify() skip unsupported files"""
    mocker.patch(
        "grizzly.reduce.strategies.beautifulsoup._contains_dd", return_value=True
    )

    with TestCase("test.js", "test-adapter") as test:
        test.add_from_bytes(b"foo", test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupPrettify(best_tests) as sgy:
            assert not any(sgy)
    finally:
        for test in best_tests:
            test.cleanup()


@mark.parametrize(
    "test_data, reduced",
    [
        param("", "", id="no data"),
        param(
            "<div></div>",
            "<div></div>",
            id="no style attr",
        ),
        param(
            "<div style=''></div>",
            "<div style=''></div>",
            id="empty style attr",
        ),
        param(
            "<div style='foo: 1'></div>",
            "<div style='foo: 1'></div>",
            id="tag with style missing id",
        ),
        param(
            "<div id='a' style='foo: 1'></div>",
            '<div id="a"></div>\n<style>\n#a { foo: 1 }\n</style>\n',
            id="add style tag",
        ),
        param(
            "<div id='a' style='foo: 1'></div>\n<div id='b' style='bar: 2'></div>",
            (
                '<div id="a"></div>\n'
                '<div id="b"></div>\n'
                "<style>\n#a { foo: 1 }\n#b { bar: 2 }\n</style>\n"
            ),
            id="multiple tags with style attr",
        ),
        param(
            "<style>\n#a {}\n</style>\n<div id='b' style='foo: 1'></div>",
            '<style>\n#a {}\n#b { foo: 1 }\n</style>\n<div id="b"></div>',
            id="existing style tag",
        ),
        param(
            "<style></style>\n<div id='a' style='foo: 1; bar: 2'></div>",
            '<style>\n#a { foo: 1; bar: 2 }\n</style>\n<div id="a"></div>',
            id="multiple style attr entries",
        ),
        param(
            "<style></style>\n<style></style>\n<div id='a' style='foo: 1'></div>",
            '<style>\n#a { foo: 1 }\n</style>\n<style></style>\n<div id="a"></div>',
            id="multiple style tags",
        ),
        param(
            "<style></style>\n<div id='a' style='foo: 1' style='bar: 2'></div>",
            '<style>\n#a { bar: 2 }\n</style>\n<div id="a"></div>',
            id="multiple style attrs on one tag",
        ),
    ],
)
def test_beautifulsoup_css_merge(test_data, reduced, mocker, tmp_path):
    """test BeautifulSoupCSSMerge() successful attempts"""
    mocker.patch(
        "grizzly.reduce.strategies.beautifulsoup._contains_dd", return_value=True
    )

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(test_data.encode("utf-8"), test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupCSSMerge(best_tests) as sgy:
            for tests in sgy:
                sgy.update(True)
                for test in best_tests:
                    test.cleanup()
                best_tests = [x.clone() for x in tests]
        assert len(best_tests) == 1
        assert best_tests[0]["test.html"].read_bytes().decode("utf-8") == reduced
    finally:
        for test in best_tests:
            test.cleanup()


def test_beautifulsoup_css_merge_failed(mocker, tmp_path):
    """test BeautifulSoupCSSMerge() failed attempt"""
    mocker.patch(
        "grizzly.reduce.strategies.beautifulsoup._contains_dd", return_value=True
    )

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"<div id='a' style='a: 1'></div>", test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupCSSMerge(best_tests) as sgy:
            count = 0
            for _ in sgy:
                sgy.update(False)
                count += 1
            assert count > 0
    finally:
        for test in best_tests:
            test.cleanup()


def test_beautifulsoup_css_merge_not_available(tmp_path):
    """test BeautifulSoupCSSMerge() beautifulsoup4 not available"""

    with TestCase("test.html", "test-adapter") as test:
        test.add_from_bytes(b"foo", test.entry_point)
        test.dump(tmp_path / "src", include_details=True)
    best_tests = [TestCase.load(tmp_path / "src")]

    try:
        with BeautifulSoupCSSMerge(best_tests) as sgy:
            sgy.import_available = False
            assert not any(sgy)
    finally:
        for test in best_tests:
            test.cleanup()
