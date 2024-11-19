# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

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

    def __init__(self, base_path: Path | None = None) -> None:
        self.assets: dict[str, str] = {}
        self.path = Path(mkdtemp(prefix="assets_", dir=base_path))

    def __enter__(self) -> AssetManager:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def add(self, asset: str, path: Path, copy: bool = True) -> Path:
        """Add asset to the AssetManager.

        Args:
            asset: Name of asset.
            path: Location on disk.
            copy: Copy or move the content.

        Returns:
            Path to the asset on the filesystem.
        """
        assert asset
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
            # Python 3.9+: move() accepts a path-like object for both src and dst
            move(str(path.resolve()), str(self.path.resolve()))
        self.assets[asset] = path.name
        LOG.debug("%s asset %r to '%s'", "copied" if copy else "moved", asset, dst)
        return dst

    def add_batch(self, assets: list[list[str]]) -> None:
        """Add collection of assets to the AssetManager.

        Args:
            assets: List of list that contain asset, path pairs.

        Returns:
            None
        """
        for asset, path in assets:
            self.add(asset, Path(path))

    def cleanup(self) -> None:
        """Remove asset files from filesystem.

        Args:
            None

        Returns:
            None
        """
        if self.path:
            rmtree(self.path, ignore_errors=True)
            self.assets.clear()

    def get(self, asset: str) -> Path | None:
        """Get path to content on filesystem for given asset.

        Args:
            asset: Asset to lookup.

        Returns:
            Path to asset content or None if asset does not exist.
        """
        item = self.assets.get(asset, None)
        return self.path / item if item else None

    def is_empty(self) -> bool:
        """Check if AssetManager contains entries.

        Args:
            None

        Returns:
            True if AssetManager contains entries else False.
        """
        return not self.assets

    @classmethod
    def load(
        cls, assets: dict[str, str], src_path: Path, base_path: Path | None = None
    ) -> AssetManager:
        """Load assets from filesystem.

        Args:
            asset: Asset paths on filesystem relative to src_path, keyed on asset name.
            src_path: Path to scan for assets.
            base_path: Base path to use to create local storage.

        Returns:
            AssetManager populated with contents provided by assets argument.
        """
        obj = cls(base_path=base_path)
        for asset, src_name in assets.items():
            obj.add(asset, src_path / src_name)
        return obj

    def remove(self, asset: str) -> None:
        """Remove asset from AssetManager if asset exists.

        Args:
            asset: Asset to remove.

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
