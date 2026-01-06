# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from importlib.metadata import entry_points
from logging import getLogger
from typing import Any

__all__ = ("PluginLoadError", "load_plugin", "scan_plugins")


LOG = getLogger(__name__)


class PluginLoadError(Exception):
    """Raised if loading a plug-in fails"""


def load_plugin(name: str, group: str, base_type: type) -> Any:
    """Load a plug-in.

    Args:
        name: Name of entry point to load.
        group: Group containing entry point.
        base_type: Used to validate loaded objects.

    Returns:
        Loaded plug-in object.
    """

    for entry in entry_points().select(group=group):
        if entry.name == name:
            plugin = entry.load()
            LOG.debug("loading '%s' (%s)", name, base_type.__name__)
            break
    else:
        raise PluginLoadError(f"'{name}' not found in '{group}'")
    if not issubclass(plugin, base_type):
        raise PluginLoadError(f"'{name}' doesn't inherit from {base_type.__name__}")
    return plugin


def scan_plugins(group: str) -> list[str]:
    """Scan for installed plug-ins.

    Args:
        group: Entry point group to scan.

    Returns:
        Names of installed entry points.
    """
    found: list[str] = []
    LOG.debug("scanning '%s'", group)
    for entry in entry_points().select(group=group):
        if entry.name in found:
            # not sure if this can even happen
            raise PluginLoadError(f"Duplicate entry '{entry.name}' in '{group}'")
        found.append(entry.name)
    return found


def scan_target_assets() -> dict[str, tuple[str, ...]]:
    """Scan targets and load collection of supported assets (minimal sanity checking).

    Args:
        None

    Returns:
        Name of target and list of supported assets.
    """
    assets: dict[str, tuple[str, ...]] = {}
    for entry in entry_points().select(group="grizzly_targets"):
        assets[entry.name] = entry.load().SUPPORTED_ASSETS
    return assets
