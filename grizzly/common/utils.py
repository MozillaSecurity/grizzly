# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import DEBUG, basicConfig
from os import getenv, makedirs
from os.path import join as pathjoin
from re import split as resplit
from tempfile import gettempdir

__all__ = (
    "ConfigError",
    "configure_logging",
    "grz_tmp",
    "sanitizer_opts",
    "TIMEOUT_DELAY",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


# TIMEOUT_DELAY is added to the test time limit to create the default timeout
TIMEOUT_DELAY = 15


class ConfigError(Exception):
    """Raised to indicate invalid configuration a state"""

    def __init__(self, message, exit_code):
        super().__init__(message)
        self.exit_code = exit_code


def configure_logging(log_level):
    """Configure log output level and formatting.

    Args:
        log_level (int): Set log level.

    Returns:
        None
    """
    # allow force enabling log_level via environment
    if getenv("DEBUG", "0").lower() in ("1", "true"):
        log_level = DEBUG
    if log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)


def grz_tmp(*subdir):
    path = pathjoin(gettempdir(), "grizzly", *subdir)
    makedirs(path, exist_ok=True)
    return path


def sanitizer_opts(env_data):
    """Parse the values defined in given *SAN_OPTIONS environment variable.
    For example "ASAN_OPTIONS=debug=false:log_path='/test/file.log'"
    would return {"debug": "false", "log_path": "'/test/file.log'"}

    Args:
        env_var (str): *SAN_OPTIONS environment variable to parse.

    Returns:
        dict: Sanitized values from environment.
    """
    opts = dict()
    for opt in resplit(r":(?![\\|/])", env_data):
        if not opt:
            continue
        key, val = opt.split("=")
        opts[key] = val
    return opts
