# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import logging
import os

from .reduce import main
from .args import ReducerArgs


log_level = logging.INFO
log_fmt = "[%(asctime)s] %(message)s"
if bool(os.getenv("DEBUG")):
    log_level = logging.DEBUG
    log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

main(ReducerArgs().parse_args())
