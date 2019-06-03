#!/usr/bin/env python
# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""

import sqlite3

from .status import Status

__all__ = ("ReduceStatus",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class ReduceStatus(object):
    """ReduceStatus holds status information for the Grizzly reduce session.
    """
    REPORT_FREQ = 60

    def __init__(self, status):
        assert isinstance(status, Status)
        # track overall reduce status with these properties
        self.reduce_fail = 0  # Q6, Q10
        self.reduce_pass = 0  # Q0
        self.reduce_error = 0  # Q7, Q8 or Q9
        # track specific (per testcase) status in self._status
        self._status = status

    def cleanup(self):
        """Remove entries that are no longer needed.

        Args:
            None

        Returns:
            None
        """
        if self._status is None:
            return
        conn = sqlite3.connect(self._status.DB_FILE)
        try:
            conn.execute("""DELETE FROM reduce_status WHERE id = ?;""", (self._status.uid,))
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
            self._status.cleanup()
        self._status = None

    @classmethod
    def load(cls, uid):
        """Read Grizzly reduce status report.

        Args:
            uid (int): Unique ID of Grizzly ReduceStatus to load.

        Returns:
            ReduceStatus: Grizzly ReduceStatus object or None if uid is unused.
        """
        status = Status.load(uid)
        if status is None:
            return None
        conn = sqlite3.connect(status.DB_FILE)
        try:
            cur = conn.cursor()
            cur.execute("""SELECT error, fail, pass
                           FROM reduce_status WHERE id = ?;""", (status.uid,))
            row = cur.fetchone()
        except sqlite3.OperationalError:
            return None
        finally:
            conn.close()
        assert row is not None, "Status exists but ReduceStatus does not"
        report = cls(status)
        report.reduce_error = int(row[0])
        report.reduce_fail = int(row[1])
        report.reduce_pass = int(row[2])
        return report

    def report(self, force=False, report_freq=REPORT_FREQ, reset_status=False):
        """Write Grizzly reduce status report. Reports are only written when the duration
        of time since the previous report was created exceeds `report_freq` seconds

        Args:
            force (bool): Ignore report frequently limiting.
            report_freq (int): Minimum number of seconds between writes.
            reset_status: Reset Status (implies force=True)

        Returns:
            None
        """
        assert self._status is not None
        if reset_status:
            self._status.reset()
        elif not self._status.report(force=force, report_freq=report_freq):
            return
        conn = sqlite3.connect(self._status.DB_FILE)
        try:
            conn.execute("""UPDATE reduce_status
                            SET error = ?,
                                fail = ?,
                                pass = ?
                            WHERE id = ?;""",
                         (self.reduce_error, self.reduce_fail, self.reduce_pass, self._status.uid))
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()

    @classmethod
    def start(cls, uid=None):
        """Create a unique ReduceStatus object.

        Args:
            None

        Returns:
            ReduceStatus: Ready to be used to report Grizzly status
        """
        status = Status.start(uid=uid)
        assert status is not None
        conn = sqlite3.connect(status.DB_FILE)
        try:
            cur = conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS reduce_status
                           (id    INTEGER PRIMARY KEY,
                            error INTEGER DEFAULT 0,
                            fail  INTEGER DEFAULT 0,
                            pass  INTEGER DEFAULT 0);""")
            conn.commit()
            # remove old reports
            cur.execute("""DELETE FROM reduce_status
                           WHERE id NOT IN (SELECT id FROM status)
                           OR id = ?;""", (status.uid,))
            # create new reduce_status entry that maps to a status entry
            cur.execute("""INSERT INTO reduce_status (id)
                           VALUES (?);""", (status.uid,))
            conn.commit()
        finally:
            conn.close()
        return cls(status)

    ### Map properties from Status object
    @property
    def duration(self):
        return 0 if self._status is None else self._status.duration

    @property
    def ignored(self):
        return 0 if self._status is None else self._status.ignored

    @ignored.setter
    def ignored(self, value):
        if self._status is not None:
            self._status.ignored = value

    @property
    def iteration(self):
        return 0 if self._status is None else self._status.iteration

    @iteration.setter
    def iteration(self, value):
        if self._status is not None:
            self._status.iteration = value

    @property
    def rate(self):
        return 0 if self._status is None else self._status.rate

    @property
    def results(self):
        return 0 if self._status is None else self._status.results

    @results.setter
    def results(self, value):
        if self._status is not None:
            self._status.results = value

    @property
    def start_time(self):
        return 0 if self._status is None else self._status.start_time

    @property
    def timestamp(self):
        return 0 if self._status is None else self._status.timestamp

    @property
    def uid(self):
        return 0 if self._status is None else self._status.uid
