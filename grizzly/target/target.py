# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod
from enum import Enum, unique
from logging import getLogger
from os import environ
from os.path import isfile
from threading import Lock

from ..common.utils import grz_tmp
from .assets import AssetManager

__all__ = ("Result", "Target", "TargetError", "TargetLaunchError")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

LOG = getLogger(__name__)


@unique
class Result(Enum):
    """Target results codes"""

    NONE = 0
    FOUND = 1
    IGNORED = 2


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
    SUPPORTED_ASSETS = None
    TRACKED_ENVVARS = ()

    __slots__ = (
        "_assets",
        "_lock",
        "_monitor",
        "binary",
        "environ",
        "launch_timeout",
        "log_limit",
        "memory_limit",
    )

    def __init__(self, binary, launch_timeout, log_limit, memory_limit, assets=None):
        assert launch_timeout > 0
        assert log_limit >= 0
        assert memory_limit >= 0
        assert binary is not None and isfile(binary)
        assert assets is None or isinstance(assets, AssetManager)
        self._assets = assets if assets else AssetManager(base_path=grz_tmp("target"))
        self._lock = Lock()
        self._monitor = None
        self.binary = binary
        self.environ = self.scan_environment(dict(environ), self.TRACKED_ENVVARS)
        self.launch_timeout = launch_timeout
        self.log_limit = log_limit
        self.memory_limit = memory_limit

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

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

    @abstractmethod
    def check_result(self, ignored):
        pass

    def cleanup(self):
        # call target specific _cleanup first
        self._cleanup()
        self._assets.cleanup()

    @abstractmethod
    def close(self, force_close=False):
        pass

    @property
    @abstractmethod
    def closed(self):
        pass

    @abstractmethod
    def create_report(self, is_hang=False):
        pass

    def dump_coverage(self, _timeout=0):  # pylint: disable=no-self-use
        LOG.warning("dump_coverage() is not supported!")

    def filtered_environ(self):
        """Used to collect the environment to add to a testcase"""
        return dict(self.environ)

    @abstractmethod
    def handle_hang(self, ignore_idle=True):
        pass

    # TODO: move to monitor?
    def is_idle(self, _threshold):  # pylint: disable=no-self-use
        LOG.debug("Target.is_idle() not implemented! returning False")
        return False

    @abstractmethod
    def launch(self, location):
        pass

    def log_size(self):  # pylint: disable=no-self-use
        LOG.debug("log_size() not implemented! returning 0")
        return 0

    @property
    @abstractmethod
    def monitor(self):
        pass

    @abstractmethod
    def process_assets(self):
        pass

    def reverse(self, remote, local):
        # remote->device, local->desktop
        pass

    @staticmethod
    def scan_environment(to_scan, tracked):
        # scan environment for tracked environment variables
        env = dict()
        if tracked:
            for var in tracked:
                if var in to_scan:
                    env[var] = to_scan[var]
        return env

    @abstractmethod
    def save_logs(self, *args, **kwargs):
        pass
