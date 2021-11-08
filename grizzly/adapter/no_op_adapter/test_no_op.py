# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from grizzly.common.storage import TestCase

from . import NoOpAdapter


def test_no_op_01():
    """test a simple Adapter"""
    adapter = NoOpAdapter("no-op")
    adapter.setup(None, None)
    test = TestCase("a", "b", adapter.name)
    assert not test.data_size
    assert "a" not in test.contents
    adapter.generate(test, None)
    assert "a" in test.contents
