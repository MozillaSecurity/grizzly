# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os
import re

__all__ = ("ReductionJob",)


def testcase_contents(path="."):
    for dir_name, _, dir_files in os.walk(path):
        arc_path = os.path.relpath(dir_name, path)
        # skip tmp folders
        if re.match(r"^tmp.+$", arc_path.split(os.sep, 1)[0]) is not None:
            continue
        for file_name in dir_files:
            # skip core files
            if re.match(r"^core.\d+$", file_name) is not None:
                continue
            if arc_path == ".":
                yield file_name
            else:
                yield os.path.join(arc_path, file_name)


from .reduce import ReductionJob  # noqa pylint: disable=wrong-import-position
