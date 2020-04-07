# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import sys

from .args import ReplayArgs
from .replay import ReplayManager
from ..main import console_init_logging


console_init_logging()
sys.exit(ReplayManager.main(ReplayArgs().parse_args()))
