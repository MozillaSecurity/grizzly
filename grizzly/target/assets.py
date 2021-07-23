# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from os import makedirs, unlink
from os.path import abspath, basename, exists, isdir, isfile
from os.path import join as pathjoin
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
        self.assets = dict()
        self.path = mkdtemp(prefix="assets_", dir=base_path)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add(self, asset, path, copy=True):
        """Add asset to the AssetManager.

        Args:
            asset (str): Name of asset.
            path (str): Path of content to use as asset.
            copy (bool): Copy or move the content.

        Returns:
            str: Path to the asset on the filesystem.
        """
        assert isinstance(asset, str)
        assert isinstance(path, str)
        assert self.path, "cleanup() was called"
        if not exists(path):
            raise OSError("%r does not exist" % (path,))
        path = abspath(path)
        # only copy files from outside working path
        if path.startswith(self.path):
            raise AssetError("Cannot add existing asset content %r" % (path,))
        # remove existing asset with the same name
        if asset in self.assets:
            LOG.debug("asset %r exists, removing existing", asset)
            self.remove(asset)
        dst_path = pathjoin(self.path, basename(path))
        # avoid overwriting data that is part of an existing asset
        if exists(dst_path):
            raise AssetError("%r is an existing asset" % (basename(path),))
        if copy:
            if isfile(path):
                copyfile(path, dst_path)
            else:
                copytree(path, dst_path)
        else:
            move(path, self.path)
        self.assets[asset] = dst_path
        LOG.debug(
            "added asset %r %s to %r", asset, "copied" if copy else "moved", dst_path
        )
        return dst_path

    def add_batch(self, assets):
        """Add collection of assets to the AssetManager.

        Args:
            assets (list(list(str, str))): List of list that contain asset, path pairs.

        Returns:
            None
        """
        for asset, path in assets:
            self.add(asset, path)

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

    def dump(self, dst_path, subdir="_assets_"):
        """Copy assets content to a given path.

        Args:
            dst_path (str): Path to copy assets content to.
            subdir (str): Create and use as destination if given.

        Returns:
            dict: Collection asset paths keyed by asset name.
        """
        dumped = dict()
        if self.assets:
            if subdir:
                dst_path = pathjoin(dst_path, subdir)
            makedirs(dst_path, exist_ok=not subdir)
            for asset, src in self.assets.items():
                dst_name = basename(src)
                dumped[asset] = dst_name
                if isfile(src):
                    copyfile(src, pathjoin(dst_path, dst_name))
                elif isdir(src):
                    copytree(src, pathjoin(dst_path, dst_name))
                else:
                    dumped.pop(asset)
                    LOG.warning("Failed to dump asset %r from %r", asset, src)
        return dumped

    def get(self, asset):
        """Get path to content on filesystem for given asset.

        Args:
            asset (str): Asset to lookup.

        Returns:
            str: Path to asset content or None if asset does not exist.
        """
        return self.assets.get(asset, None)

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
            src_path (str): Path to scan for assets.
            base_path (str): Base path to use to create local storage.

        Returns:
            AssetManager: Populated with contents provided by assets argument.
        """
        obj = cls(base_path=base_path)
        for asset, src_name in assets.items():
            obj.add(asset, pathjoin(src_path, src_name))
        return obj

    def remove(self, asset):
        """Remove asset from AssetManager if asset exists.

        Args:
            asset (str): Asset to remove.

        Returns:
            None
        """
        path = self.assets.pop(asset, None)
        if path:
            if isfile(path):
                unlink(path)
            else:
                rmtree(path, ignore_errors=True)
