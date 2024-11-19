# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from ...common.storage import TestCase
from . import NoOpAdapter


def test_no_op_01():
    """test a simple Adapter"""
    with NoOpAdapter("no-op") as adapter:
        adapter.setup(None, None)
        with TestCase("a.html", adapter.name) as test:
            assert not test.data_size
            assert "a.html" not in test
            adapter.generate(test, None)
            assert "a.html" in test
