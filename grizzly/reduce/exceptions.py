# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly Reduction exceptions."""
from ..session import Session


class GrizzlyReduceBaseException(Exception):
    """Base for other Grizzly Reducer specific exceptions."""
    def __init__(self, msg, code=Session.EXIT_ERROR):
        super().__init__()
        self.msg = msg
        self.code = code


class NotReproducible(GrizzlyReduceBaseException):
    """Crash was not observed when expected during reduction."""
    def __init__(self, msg):
        super().__init__(msg, code=Session.EXIT_FAILURE)
