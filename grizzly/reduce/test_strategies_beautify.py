# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""Unit tests for `grizzly.reduce.strategies.beautify`."""
from logging import getLogger

import pytest

from ..common.storage import TestCase
from .strategies.beautify import CSSBeautify, JSBeautify

LOG = getLogger(__name__)


def _test_beautify(cls, interesting, test_name, test_data, reduced, mocker):
    mocker.patch("grizzly.reduce.strategies.beautify._contains_dd", return_value=True)

    best_test = TestCase(test_name, None, "test-adapter")
    best_test.add_from_bytes(test_data.encode("ascii"), test_name)
    best_tests = [best_test]

    def _interesting(testcases):
        for test in testcases:
            contents = test.get_file(test_name).data_file.read_bytes().decode("ascii")
            if interesting(contents):
                return True
        return False

    try:
        with cls(best_tests) as sgy:
            for tests in sgy:
                try:
                    result = _interesting(tests)
                    sgy.update(result)
                    if result:
                        for test in best_tests:
                            test.cleanup()
                        best_tests = tests
                        tests = []
                finally:
                    for test in tests:
                        test.cleanup()
        assert len(best_tests) == 1
        contents = (
            best_tests[0].get_file(test_name).data_file.read_bytes().decode("ascii")
        )
        assert contents == reduced
    finally:
        for test in best_tests:
            test.cleanup()


@pytest.mark.parametrize(
    "test_data, reduced",
    [
        pytest.param(
            "try{'a';'R'}catch(e){}\n",
            "try {\n    'a';\n    'R'\n} catch (e) {}\n",
            id="#0: test beautify a .js file",
        ),
        pytest.param(
            "try{\n//DDBEGIN\n'a';'R'\n//DDEND\n}catch(e){}\n",
            "try{\n//DDBEGIN\n'a';\n'R'\n//DDEND\n}catch(e){}\n",
            id="#1: test DDBEGIN/END respected in .js file",
        ),
        pytest.param(
            "try{\r\n'a';'R'}catch(e){}\n",
            "try {\n    'a';\n    'R'\n} catch (e) {}\n",
            id="#2: test that mixed crlf/lf gets converted to lf",
        ),
        pytest.param(
            "try{\r'a';'R'}catch(e){}\n",
            "try {\n    'a';\n    'R'\n} catch (e) {}\n",
            id="#3: test that mixed cr/lf gets converted to lf",
        ),
        pytest.param(
            "try{'a\v';'R'}catch(e){}\n",
            "try {\n    'a\v';\n    'R'\n} catch (e) {}\n",
            id="#4: test beautify with a string containing a \v",
        ),
        pytest.param(
            "try{'a';'R'}\n\ncatch(e){}\n",
            "try {\n    'a';\n    'R'\n} catch (e) {}\n",
            id="#5: test that existing newlines are not preserved",
        ),
    ],
)
def test_beautify_js_1(test_data, reduced, mocker):
    _test_beautify(
        JSBeautify, lambda x: "R" in x, "test.js", test_data, reduced, mocker
    )


@pytest.mark.parametrize(
    "test_data, reduced",
    [
        pytest.param(
            "try{'a';'R'+'R'}catch(e){}\n",
            "try{'a';'R'+'R'}catch(e){}\n",
            id="#6: test beautify js where beautification breaks",
        ),
    ],
)
def test_beautify_js_2(test_data, reduced, mocker):
    _test_beautify(
        JSBeautify, lambda x: "'R'+'R'" in x, "test.js", test_data, reduced, mocker
    )


@pytest.mark.parametrize(
    "test_data, reduced",
    [
        pytest.param(
            "<script>try{'a';'R'}catch(e){}</script>\n",
            "<script>\ntry {\n    'a';\n    'R'\n} catch (e) {}\n</script>\n",
            id="#7: test beautify js embedded in html",
        ),
        pytest.param(
            "<script>try{'a';'R'}catch(e){}\n",
            "<script>\ntry {\n    'a';\n    'R'\n} catch (e) {}\n",
            id="#8: test beautify js embedded in html with no end",
        ),
        pytest.param(
            "<!--DDBEGIN-->\n<script>\ntry{'a';'R'}catch(e){}\n</script><!--DDEND-->\n",
            "<!--DDBEGIN-->\n<script>\ntry {\n    'a';\n    'R'\n"
            "} catch (e) {}\n</script><!--DDEND-->\n",
            id="#9: test DDBEGIN/END respected for js embedded in html, "
            "DD outside <script>",
        ),
        pytest.param(
            "<script>try{\n//DDBEGIN\n'a';'R'\n//DDEND\n}catch(e){}</script>\n",
            "<script>try{\n//DDBEGIN\n'a';\n'R'\n//DDEND\n}catch(e){}</script>\n",
            id="#10: test DDBEGIN/END respected for js embedded in html, "
            "DD inside <script>",
        ),
        pytest.param(
            "<!--DDBEGIN-->\n<script>\ntry{'a';'R'}catch(e){}\n//DDEND\n",
            "<!--DDBEGIN-->\n<script>\ntry {\n    'a';\n    'R'\n"
            "} catch (e) {}\n//DDEND\n",
            id="#11: test DDBEGIN/END respected for js embedded in html, "
            "DD straddle before <script>",
        ),
        pytest.param(
            "<script>\n//DDBEGIN\ntry{'a';'R'}catch(e){}\n//DDEND\n",
            "<script>\n//DDBEGIN\ntry {\n    'a';\n    'R'\n} catch (e) {}\n//DDEND\n",
            id="#12: test DDBEGIN/END respected for js embedded in html, "
            "DD straddle after <script>",
        ),
        pytest.param(
            "<script>\n//DDBEGIN\ntry{'a';'R'}catch(e){}\n</script>\n<!--DDEND-->\n",
            "<script>\n//DDBEGIN\ntry {\n    'a';\n    'R'\n"
            "} catch (e) {}\n</script>\n<!--DDEND-->\n",
            id="#13: test DDBEGIN/END respected for js embedded in html, "
            "DD straddle after </script>",
        ),
        pytest.param(
            "try{'a';'R'}catch(e){}\n",
            "try{'a';'R'}catch(e){}\n",
            id="#14: test beautify js embedded in html (no <script>)",
        ),
    ],
)
def test_beautify_js_3(test_data, reduced, mocker):
    _test_beautify(
        JSBeautify, lambda x: "R" in x, "test.html", test_data, reduced, mocker
    )


@pytest.mark.parametrize(
    "test_data, reduced",
    [
        pytest.param(
            "<script>try{'a';'R'}catch(e){}</script><script>'a';'Q'</script>\n",
            "<script>\ntry {\n    'a';\n    'R'\n} catch (e) {}\n</script>"
            "<script>\n'a';\n'Q'\n</script>\n",
            id="#15: test beautify multiple js embedded in html",
        ),
    ],
)
def test_beautify_js_4(test_data, reduced, mocker):
    _test_beautify(
        JSBeautify,
        lambda x: "Q" in x and "R" in x,
        "test.html",
        test_data,
        reduced,
        mocker,
    )


@pytest.mark.parametrize(
    "test_data, reduced",
    [
        pytest.param(
            "*,#a{a:0;R:1}\n",
            "*,\n#a {\n  a: 0;\n  R: 1\n}\n",
            id="#0: test beautify a .css file",
        ),
        pytest.param(
            "*,\r\n#a{a:0;R:1}\n",
            "*,\n#a {\n  a: 0;\n  R: 1\n}\n",
            id="#1: test that mixed crlf/lf gets converted to lf",
        ),
        pytest.param(
            "*,\r#a{a:0;R:1}\n",
            "*,\n#a {\n  a: 0;\n  R: 1\n}\n",
            id="#2: test that mixed cr/lf gets converted to lf",
        ),
        pytest.param(
            "*,#a{a:0;\n\nR:1}\n",
            "*,\n#a {\n  a: 0;\n  R: 1\n}\n",
            id="#3: test that existing newlines are not preserved",
        ),
    ],
)
def test_beautify_css_1(test_data, reduced, mocker):
    _test_beautify(
        CSSBeautify, lambda x: "R" in x, "test.css", test_data, reduced, mocker
    )


@pytest.mark.parametrize(
    "test_data, reduced",
    [
        pytest.param(
            "<style>*,#a{a:0;R:1}</style>\n",
            "<style>\n*,\n#a {\n  a: 0;\n  R: 1\n}\n</style>\n",
            id="#4: test beautify css embedded in html",
        ),
        pytest.param(
            "<style>*,#a{a:0;R:1}\n",
            "<style>\n*,\n#a {\n  a: 0;\n  R: 1\n}\n",
            id="#5: test beautify css embedded in html with no end",
        ),
        pytest.param(
            "<style>\n*,\n#a {\n  a: 0;\n  R: 1\n}\n</style>\n",
            "<style>\n*,\n#a {\n  a: 0;\n  R: 1\n}\n</style>\n",
            id="#6: test already beautified css (beautify does nothing)",
        ),
        pytest.param(
            "*,#a{a:0;R:1}\n",
            "*,#a{a:0;R:1}\n",
            id="#7: test beautify css embedded in html (no <style>)",
        ),
    ],
)
def test_beautify_css_2(test_data, reduced, mocker):
    _test_beautify(
        CSSBeautify, lambda x: "R" in x, "test.html", test_data, reduced, mocker
    )


@pytest.mark.parametrize(
    "beautify, test_data",
    [
        (JSBeautify, "<script>try{'a';'R'}catch(e){}\n"),
        (CSSBeautify, "<style>*,#a{a:0;R:1}\n"),
    ],
)
def test_no_beautify(beautify, test_data, mocker):
    """test that when beautifiers are not available, the strategies have no effect"""
    mocker.patch.object(beautify, "import_available", False)
    _test_beautify(
        beautify, lambda x: "R" in x, "test.html", test_data, test_data, mocker
    )
