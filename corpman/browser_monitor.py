# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class BrowserMonitor(object):
    def __init__(self):
        self._fn_clone_log = None
        self._fn_is_running = None
        self._fn_launch_count = None
        self._fn_log_length = None


    def clone_log(self, log_id, offset=0):
        if self._fn_clone_log is None:
            return None
        return self._fn_clone_log(log_id, offset=offset)


    def launch_count(self):
        if self._fn_launch_count is None:
            return 0
        return self._fn_launch_count()


    def is_running(self):
        if self._fn_is_running is None:
            return False
        return self._fn_is_running()


    def log_data(self, log_id, offset=0):
        if self._fn_clone_log is None:
            return None
        log_file = self._fn_clone_log(log_id, offset=offset)
        if log_file is None:
            return None
        try:
            with open(log_file, "rb") as log_fp:
                return log_fp.read()
        finally:
            os.remove(log_file)


    def log_length(self, log_id):
        if self._fn_log_length is None:
            return 0
        return self._fn_log_length(log_id)


    def monitor_instance(self, puppet):
        self._fn_clone_log = puppet.clone_log
        self._fn_is_running = puppet.is_running
        self._fn_launch_count = puppet.get_launch_count
        self._fn_log_length = puppet.log_length
