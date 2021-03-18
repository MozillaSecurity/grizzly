# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from os import makedirs
from os.path import join as pathjoin
from tempfile import gettempdir

__all__ = ("ConfigError", "grz_tmp", "TIMEOUT_DELAY")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


# TIMEOUT_DELAY is added to the test time limit to create the default timeout
TIMEOUT_DELAY = 15


class ConfigError(Exception):
    """Raised to indicate invalid configuration a state"""

    def __init__(self, message, exit_code):
        super().__init__(message)
        self.exit_code = exit_code


def grz_tmp(*subdir):
    path = pathjoin(gettempdir(), "grizzly", *subdir)
    makedirs(path, exist_ok=True)
    return path
