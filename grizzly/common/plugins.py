# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger

from pkg_resources import iter_entry_points

__all__ = ("load", "scan", "PluginLoadError")


LOG = getLogger(__name__)


class PluginLoadError(Exception):
    """Raised if loading a plug-in fails"""


def load(name, group, base_type):
    """Load a plug-in.

    Args:
        name (str): Name of entry point to load.
        group (str): Group containing entry point.
        base_type (type): Used to validate loaded objects.

    Returns:
        *: Python object.
    """
    assert isinstance(base_type, type)
    for entry in iter_entry_points(group):
        if entry.name == name:
            LOG.debug("loading %r (%s)", name, base_type.__name__)
            plugin = entry.load()
            break
    else:
        raise PluginLoadError("%r not found in %r" % (name, group))
    if not issubclass(plugin, base_type):
        raise PluginLoadError("%r doesn't inherit from %s" % (name, base_type.__name__))
    return plugin


def scan(group):
    """Scan for installed plug-ins.

    Args:
        group (str): Entry point group to scan.

    Returns:
        list: Names of installed entry points.
    """
    found = list()
    LOG.debug("scanning %r", group)
    for entry in iter_entry_points(group):
        if entry.name in found:
            # not sure if this can even happen
            raise PluginLoadError("Duplicate entry %r in %r" % (entry.name, group))
        found.append(entry.name)
    return found


def scan_target_assets():
    """Scan targets and load list of supported assets (minimal sanity checking).

    Args:
        None

    Returns:
        dict: Name of target and list of supported assets.
    """
    assets = dict()
    for entry in iter_entry_points("grizzly_targets"):
        assets[entry.name] = entry.load().SUPPORTED_ASSETS
    return assets
