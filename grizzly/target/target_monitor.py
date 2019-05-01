# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import abc
import os

import six

__all__ = ("TargetMonitor",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


@six.add_metaclass(abc.ABCMeta)
class TargetMonitor(object):
    @abc.abstractmethod
    def clone_log(self, log_id, offset=0):
        pass

    @abc.abstractmethod
    def is_healthy(self):
        pass

    @abc.abstractmethod
    def is_running(self):
        pass

    @abc.abstractproperty
    def launches(self):
        pass

    def log_data(self, log_id, offset=0):
        log_file = self.clone_log(log_id, offset=offset)
        if log_file is None:
            return None
        try:
            with open(log_file, "rb") as log_fp:
                return log_fp.read()
        finally:
            os.remove(log_file)

    @abc.abstractmethod
    def log_length(self, log_id):
        pass
