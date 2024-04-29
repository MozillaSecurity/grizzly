# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from typing import Any, Dict, List, Tuple

from pkg_resources import iter_entry_points

__all__ = ("load", "scan", "PluginLoadError")


LOG = getLogger(__name__)


class PluginLoadError(Exception):
    """Raised if loading a plug-in fails"""


def load(name: str, group: str, base_type: type) -> Any:
    """Load a plug-in.

    Args:
        name: Name of entry point to load.
        group: Group containing entry point.
        base_type: Used to validate loaded objects.

    Returns:
        Loaded plug-in object.
    """
    assert isinstance(base_type, type)
    for entry in iter_entry_points(group):
        if entry.name == name:
            LOG.debug("loading %r (%s)", name, base_type.__name__)
            plugin = entry.load()
            break
    else:
        raise PluginLoadError(f"{name!r} not found in {group!r}")
    if not issubclass(plugin, base_type):
        raise PluginLoadError(f"{name!r} doesn't inherit from {base_type.__name__}")
    return plugin


def scan(group: str) -> List[str]:
    """Scan for installed plug-ins.

    Args:
        group: Entry point group to scan.

    Returns:
        Names of installed entry points.
    """
    found = []
    LOG.debug("scanning %r", group)
    for entry in iter_entry_points(group):
        if entry.name in found:
            # not sure if this can even happen
            raise PluginLoadError(f"Duplicate entry {entry.name!r} in {group!r}")
        found.append(entry.name)
    return found


def scan_target_assets() -> Dict[str, Tuple[str, ...]]:
    """Scan targets and load collection of supported assets (minimal sanity checking).

    Args:
        None

    Returns:
        Name of target and list of supported assets.
    """
    assets = {}
    for entry in iter_entry_points("grizzly_targets"):
        assets[entry.name] = entry.load().SUPPORTED_ASSETS
    return assets
