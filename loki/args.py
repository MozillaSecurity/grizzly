# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from argparse import ArgumentParser, Namespace
from pathlib import Path

from loki import Loki

__author__ = "Tyson Smith"


def parse_args(argv: list[str] | None = None) -> Namespace:
    parser = ArgumentParser(description="Loki fuzzing library")
    parser.add_argument(
        "input", type=Path, help="Output will be generated based on this file"
    )
    parser.add_argument(
        "-a",
        "--aggression",
        default=0.001,
        type=float,
        help="Maximum fuzz rate. 1.0 == 100%% (default: %(default)s)",
    )
    parser.add_argument(
        "-b",
        "--byte-order",
        choices=sorted(Loki.BYTE_ORDERS),
        default=None,
        help="Byte order to use when mutating multiple bytes at once. "
        "Use '>' for big-endian or '<' for little-endian (default: random)",
    )
    parser.add_argument(
        "-c",
        "--count",
        default=1,
        type=int,
        help="Number of test cases to generate, minimum 1 (default: %(default)s)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output directory for fuzzed test cases (default: '.')",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        default=False,
        action="store_true",
        help="Display limited output (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        parser.error(f"'{args.input}' is not a file")

    return args
