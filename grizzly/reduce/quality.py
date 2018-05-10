# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Quality value codes
"""

# testcase quality values
QUALITIES = {
    0: "REDUCED_RESULT",  # the final reduced testcase
    1: "REDUCED_ORIGINAL",  # the original used for successful reduction
    4: "REPRODUCIBLE",  # the testcase was reproducible
    5: "UNREDUCED",  # haven't attempted reduction yet
    8: "REDUCER_BROKE",  # the testcase was reproducible, but broke during reduction
    9: "REDUCER_ERROR",  # reducer error
    10: "NOT_REPRODUCIBLE",  # could not reproduce the testcase
}

for value, name in QUALITIES.items():
    globals()[name] = value
