# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from pathlib import Path
from shutil import copyfile, copytree, move, rmtree
from tempfile import mkdtemp

__all__ = ("AssetError", "AssetManager")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class AssetError(Exception):
    """Raised by AssetManager"""


class AssetManager:
    __slots__ = ("assets", "path")

    def __init__(self, base_path=None):
        self.assets = {}
        self.path = Path(mkdtemp(prefix="assets_", dir=base_path))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add(self, asset, path, copy=True):
        """Add asset to the AssetManager.

        Args:
            asset (str): Name of asset.
            path (Path): Location on disk.
            copy (bool): Copy or move the content.

        Returns:
            str: Path to the asset on the filesystem.
        """
        assert isinstance(asset, str)
        assert isinstance(path, Path)
        assert self.path, "cleanup() was called"
        if not path.exists():
            raise OSError(f"'{path}' does not exist")
        dst = self.path / path.name
        # remove existing asset with the same name
        if asset in self.assets:
            LOG.debug("asset %r exists, removing existing", asset)
            self.remove(asset)
        # avoid overwriting data that is part of an existing asset
        if dst.exists():
            raise AssetError(f"{asset}: '{path.name}' already exists")
        if copy:
            if path.is_file():
                copyfile(path, dst)
            else:
                copytree(path, dst)
        else:
            # TODO: move() only accepts str in Python 3.8
            move(str(path), str(self.path))
        self.assets[asset] = path.name
        LOG.debug("%s asset %r to '%s'", "copied" if copy else "moved", asset, dst)
        return dst

    def add_batch(self, assets):
        """Add collection of assets to the AssetManager.

        Args:
            assets (list(list(str, str))): List of list that contain asset, path pairs.

        Returns:
            None
        """
        for asset, path in assets:
            self.add(asset, Path(path))

    def cleanup(self):
        """Remove asset files from filesystem.

        Args:
            None

        Returns:
            None
        """
        if self.path:
            rmtree(self.path, ignore_errors=True)
            self.assets.clear()
            self.path = None

    def get(self, asset):
        """Get path to content on filesystem for given asset.

        Args:
            asset (str): Asset to lookup.

        Returns:
            Path: Path to asset content or None if asset does not exist.
        """
        item = self.assets.get(asset, None)
        return self.path / item if item else None

    def is_empty(self):
        """Check if AssetManager contains entries.

        Args:
            None

        Returns:
            bool: True if AssetManager contains entries else False.
        """
        return not self.assets

    @classmethod
    def load(cls, assets, src_path, base_path=None):
        """Load assets from filesystem.

        Args:
            asset (dict): Asset paths on filesystem relative to src_path, keyed on
                          asset name.
            src_path (Path): Path to scan for assets.
            base_path (str): Base path to use to create local storage.

        Returns:
            AssetManager: Populated with contents provided by assets argument.
        """
        obj = cls(base_path=base_path)
        for asset, src_name in assets.items():
            obj.add(asset, src_path / src_name)
        return obj

    def remove(self, asset):
        """Remove asset from AssetManager if asset exists.

        Args:
            asset (str): Asset to remove.

        Returns:
            None
        """
        local_path = self.assets.pop(asset, None)
        if local_path:
            path = self.path / local_path
            if path.is_file():
                path.unlink()
            else:
                rmtree(path, ignore_errors=True)
