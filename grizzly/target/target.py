# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod, abstractproperty
from logging import getLogger
from os import makedirs, unlink
from os.path import basename, dirname, exists, isdir, isfile
from os.path import join as pathjoin
from shutil import copyfile, copytree, rmtree
from tempfile import mkdtemp
from threading import Lock

from ..common.utils import grz_tmp

__all__ = ("Target", "TargetError", "TargetLaunchError")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


class AssetManager:
    __slots__ = ("assets", "path")

    def __init__(self, base_path=None):
        self.assets = dict()
        self.path = mkdtemp(prefix="assets_", dir=base_path)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add(self, asset, path):
        assert isinstance(asset, str)
        assert self.path, "cleanup() was called"
        if not path or not exists(path):
            raise OSError("Asset %r not found %r" % (asset, path))
        assert asset not in self.assets
        # only copy files from outside working path
        if dirname(path) != self.path:
            # check file name collision
            dst_path = pathjoin(self.path, basename(path))
            if exists(dst_path):
                raise OSError("Name collision in asset path %r" % (basename(path),))
            if isfile(path):
                copyfile(path, dst_path)
            else:
                copytree(path, dst_path)
            self.assets[asset] = dst_path
        else:
            self.assets[asset] = path
        LOG.debug("added asset %r from %r", asset, path)

    def add_batch(self, assets):
        for asset, path in assets:
            self.add(asset, path)

    def cleanup(self):
        if self.path:
            rmtree(self.path, ignore_errors=True)
            self.assets.clear()
            self.path = None

    def dump(self, dst_path, subdir="_assets_"):
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
        return self.assets.get(asset, None)

    def is_empty(self):
        return not self.assets

    @classmethod
    def load(cls, assets, src_path):
        obj = cls()
        for asset, src_name in assets.items():
            obj.add(asset, pathjoin(src_path, src_name))
        return obj

    def remove(self, asset):
        path = self.assets.pop(asset, None)
        if path:
            if isfile(path):
                unlink(path)
            else:
                rmtree(path, ignore_errors=True)


class TargetError(Exception):
    """Raised by Target"""


class TargetLaunchError(TargetError):
    """Raised if a failure during launch occurs"""

    def __init__(self, message, report):
        super().__init__(message)
        self.report = report


class TargetLaunchTimeout(TargetError):
    """Raised if the target does not launch within the defined amount of time"""


class Target(metaclass=ABCMeta):
    RESULT_NONE = 0
    RESULT_FAILURE = 1
    RESULT_IGNORED = 2
    SUPPORTED_ASSETS = None

    __slots__ = (
        "_assets",
        "_lock",
        "_monitor",
        "binary",
        "launch_timeout",
        "log_limit",
        "memory_limit",
    )

    def __init__(self, binary, launch_timeout, log_limit, memory_limit, assets=None):
        assert log_limit >= 0
        assert memory_limit >= 0
        assert binary is not None and isfile(binary)
        assert assets is None or isinstance(assets, AssetManager)
        self._assets = assets if assets else AssetManager(base_path=grz_tmp("target"))
        self._lock = Lock()
        self._monitor = None
        self.binary = binary
        self.launch_timeout = max(launch_timeout, 300)
        self.log_limit = log_limit
        self.memory_limit = memory_limit

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def add_abort_token(self, _token):  # pylint: disable=no-self-use
        # TODO: change this to asset file containing tokens
        LOG.warning("add_abort_token() not implemented!")

    @property
    def assets(self):
        return self._assets

    @assets.setter
    def assets(self, assets):
        self._assets.cleanup()
        assert isinstance(assets, AssetManager)
        self._assets = assets

    @abstractmethod
    def _cleanup(self):
        pass

    def cleanup(self):
        # call target specific _cleanup first
        self._cleanup()
        self._assets.cleanup()

    @abstractmethod
    def close(self, force_close=False):
        pass

    @abstractproperty
    def closed(self):
        pass

    @abstractmethod
    def create_report(self, is_hang=False):
        pass

    @abstractmethod
    def detect_failure(self, ignored):
        pass

    def dump_coverage(self, _timeout=0):  # pylint: disable=no-self-use
        LOG.warning("dump_coverage() is not supported!")

    @abstractmethod
    def handle_hang(self, ignore_idle=True):
        pass

    # TODO: move to monitor?
    def is_idle(self, _threshold):  # pylint: disable=no-self-use
        LOG.debug("Target.is_idle() not implemented! returning False")
        return False

    @abstractmethod
    def launch(self, _location, _env_mod=None):
        pass

    def log_size(self):  # pylint: disable=no-self-use
        LOG.debug("log_size() not implemented! returning 0")
        return 0

    @abstractproperty
    def monitor(self):
        pass

    @abstractmethod
    def process_assets(self):
        pass

    def reverse(self, remote, local):
        # remote->device, local->desktop
        pass

    @abstractmethod
    def save_logs(self, *args, **kwargs):
        pass
