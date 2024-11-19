# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from argparse import ArgumentParser, Namespace
from logging import DEBUG, INFO, basicConfig
from pathlib import Path

from .core import Sapphire


def configure_logging(log_level: int) -> None:
    if log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)


def parse_args(argv: list[str] | None = None) -> Namespace:
    # log levels for console logging
    level_map = {"DEBUG": DEBUG, "INFO": INFO}
    parser = ArgumentParser()
    parser.add_argument("path", type=Path, help="Specify a directory to act as wwwroot")
    parser.add_argument(
        "--log-level",
        choices=sorted(level_map),
        default="INFO",
        help="Configure console logging (default: %(default)s)",
    )
    parser.add_argument(
        "--port", default=0, type=int, help="Specify port (default: automatic)"
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Allow connections from addresses other than 127.0.0.1",
    )
    parser.add_argument(
        "--timeout",
        default=0,
        type=int,
        help="Duration in seconds to serve before exiting (default: 0 - no timeout)",
    )
    args = parser.parse_args(argv)
    # sanity check
    if not args.path.is_dir():
        parser.error(f"Directory does not exist '{args.path}'")
    if args.port < 0 or args.port > 65535:
        parser.error("--port must be >= 0 and <= 65535")
    if args.timeout < 0:
        parser.error("--timeout must be >= 0")
    args.log_level = level_map[args.log_level]
    return args


ARGS = parse_args()
configure_logging(ARGS.log_level)
Sapphire.main(ARGS)
