# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Reducer unit test fixtures
"""
import pytest
from grizzly.reduce import reduce, ReductionJob
from .test_common import FakeReduceStatus, FakeTarget
from .test_reduce import FakeInteresting


@pytest.fixture
def job(monkeypatch, request):
    """Pytest fixture to provide a ReductionJob object with dependencies stubbed and default values"""
    interesting_cls = getattr(request, "param", FakeInteresting)
    use_testcase_cache = getattr(interesting_cls, "USE_TESTCASE_CACHE", False)
    use_analysis = getattr(interesting_cls, "USE_ANALYZE", False)
    monkeypatch.setattr(reduce, "Interesting", interesting_cls)
    result = ReductionJob([], FakeTarget(), 60, False, False, 0, 1, 1, 3, 25, 60,
                          FakeReduceStatus(), None, use_testcase_cache, not use_analysis)
    yield result
    result.close()
