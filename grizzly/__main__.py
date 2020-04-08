# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import sys

from .adapters import load
from .args import GrizzlyArgs
from .main import console_init_logging, main

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


console_init_logging()
load()
sys.exit(main(GrizzlyArgs().parse_args()))
