# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.strategies.beautifulsoup`."""

from logging import getLogger

from pytest import mark, param

from ..common.storage import TestCase
from .strategies.beautifulsoup import BeautifulSoupPrettify

LOG = getLogger(__name__)


@mark.parametrize(
    "test_data, reduced",
    [
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
            "<br/>\n",
            "<br/>\n",
            id="no changes needed",
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
            for _ in sgy:
                sgy.update(False)
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
