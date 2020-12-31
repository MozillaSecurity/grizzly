# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from argparse import ArgumentParser


__author__ = "Tyson Smith"


def parse_args(argv=None):
    parser = ArgumentParser(description="Loki fuzzing library")
    parser.add_argument(
        "input",
        help="Output will be generated based on this file")
    parser.add_argument(
        "-a", "--aggression", default=0.001, type=float,
        help="Controls how much fuzzing is done on the output file")
    parser.add_argument(
        "-c", "--count", default=100, type=int,
        help="Number test cases to generate")
    parser.add_argument(
        "-q", "--quiet", default=False, action="store_true",
        help="Display limited output")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory for fuzzed test cases")
    return parser.parse_args(argv)
