# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import sys

from .reduce import main
from .args import ReducerArgs
from ..main import console_init_logging


console_init_logging()
sys.exit(main(ReducerArgs().parse_args()))
