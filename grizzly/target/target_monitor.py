# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from abc import ABCMeta, abstractmethod
from os import remove

__all__ = ("TargetMonitor",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


class TargetMonitor(metaclass=ABCMeta):
    @abstractmethod
    def clone_log(self, log_id, offset=0):
        pass

    @abstractmethod
    def is_healthy(self):
        pass

    @abstractmethod
    def is_running(self):
        pass

    @property
    @abstractmethod
    def launches(self):
        pass

    def log_data(self, log_id, offset=0):
        data = None
        log_file = self.clone_log(log_id, offset=offset)
        if log_file:
            try:
                with open(log_file, "rb") as log_fp:
                    data = log_fp.read()
            finally:
                remove(log_file)
        return data

    @abstractmethod
    def log_length(self, log_id):
        pass
