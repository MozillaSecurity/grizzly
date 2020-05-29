# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import basicConfig, DEBUG
from os import getenv
from sys import exit as sysexit

from .adapters import load
from .args import GrizzlyArgs
from .main import main

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


# TODO: This can go away once Adapters are loaded using
# setuptools entrypoints. It is only needed to get log output from
# load() because it is called before parse arguments (which
# is where basicConfig should be called).
if getenv("DEBUG"):
    basicConfig(
        format="%(levelname).1s %(name)s [%(asctime)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=DEBUG)
# load Adapters
load()
sysexit(main(GrizzlyArgs().parse_args()))
