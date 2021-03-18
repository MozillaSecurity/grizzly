# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Grizzly reducer CLI.
"""
from . import ReduceManager
from .args import ReduceArgs

raise SystemExit(ReduceManager.main(ReduceArgs().parse_args()))
