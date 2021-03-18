# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from argparse import ArgumentParser
from logging import DEBUG, INFO, basicConfig
from os.path import isdir

from .core import Sapphire


def configure_logging(log_level):
    if log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)


def parse_args(argv=None):
    # log levels for console logging
    level_map = {"DEBUG": DEBUG, "INFO": INFO}
    parser = ArgumentParser()
    parser.add_argument("path", help="Specify a directory to act as wwwroot")
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Configure console logging. Options: %s (default: %%(default)s)"
        % ", ".join(k for k, v in sorted(level_map.items(), key=lambda x: x[1])),
    )
    parser.add_argument(
        "--port", type=int, help="Specify a port to bind to (default: random)"
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Allow connections from addresses other than 127.0.0.1",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Duration in seconds to serve before exiting. Default run forever.",
    )
    args = parser.parse_args(argv)
    # sanity check
    if not isdir(args.path):
        parser.error("Path does not exist %r" % (args.path,))
    if args.timeout is not None and args.timeout <= 0:
        parser.error("Specified timeout must be greater than 0")
    log_level = level_map.get(args.log_level.upper(), None)
    if log_level is None:
        parser.error("Invalid log-level %r" % (args.log_level,))
    args.log_level = log_level
    return args


ARGS = parse_args()
configure_logging(ARGS.log_level)
Sapphire.main(ARGS)
