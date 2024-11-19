# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly Reduction exceptions."""
from ..common.utils import Exit


class GrizzlyReduceBaseException(Exception):
    """Base for other Grizzly Reducer specific exceptions."""

    def __init__(self, msg: str, code: Exit = Exit.ERROR) -> None:
        super().__init__()
        self.msg = msg
        self.code = code


class NotReproducible(GrizzlyReduceBaseException):
    """Crash was not observed when expected during reduction."""

    def __init__(self, msg: str) -> None:
        super().__init__(msg, code=Exit.FAILURE)
