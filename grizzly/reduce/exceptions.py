# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

__author__ = "Jesse Schwartzentruber"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


class ReducerError(Exception):
    pass


class TestcaseError(ReducerError):
    pass


class NoTestcaseError(TestcaseError):
    pass


class CorruptTestcaseError(TestcaseError):
    pass
