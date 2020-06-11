# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from sys import exc_info
from traceback import extract_tb
from pkg_resources import iter_entry_points

from .target import sanitizer_opts, Target, TargetError, TargetLaunchError, TargetLaunchTimeout

__all__ = ("Target", "TargetError", "TargetLaunchError", "TargetLaunchTimeout",
           "available", "load", "sanitizer_opts")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

TARGETS = None
LOG = getLogger("grizzly")


def _load_targets():
    global TARGETS  # pylint: disable=global-statement
    TARGETS = {}
    for entry_point in iter_entry_points('grizzly_targets'):
        LOG.debug("scanning target %r", entry_point.name)
        try:
            target = entry_point.load()
        except Exception:  # pylint: disable=broad-except
            exc_type, exc_obj, exc_tb = exc_info()
            tbinfo = extract_tb(exc_tb)[-1]
            LOG.warning("Target %r raised an exception %s: %s (%s:%d)", entry_point.name, exc_type.__name__,
                        exc_obj, tbinfo[0], tbinfo[1])
            continue
        if not issubclass(target, Target):
            LOG.warning("Target %r doesn't inherit from grizzly.target.Target, skipping.", entry_point.name)
        elif entry_point.name in TARGETS:
            raise RuntimeError("Target %r already exists as %r. (duplicate: %r)" %
                               (entry_point.name, TARGETS[entry_point.name], target))
        else:
            TARGETS[entry_point.name] = target


def available():
    if TARGETS is None:
        _load_targets()
    return TARGETS.keys()


def load(name):
    if TARGETS is None:
        _load_targets()
    return TARGETS[name]
