# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""

import sqlite3
import time

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class Status(object):
    """Status holds status information for the Grizzly session.
    """
    AGE_LIMIT = 3600  # 1 hour
    DB_FILE = "grz-status.db"
    REPORT_FREQ = 60

    def __init__(self, uid, start_time):
        assert isinstance(start_time, int)
        assert isinstance(uid, int)
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.results = 0
        self.start_time = start_time
        self.test_name = None
        self.timestamp = start_time
        self.uid = uid

    def cleanup(self):
        """Remove entries that are no longer needed.

        Args:
            None

        Returns:
            None
        """
        conn = sqlite3.connect(self.DB_FILE)
        try:
            conn.execute("""DELETE FROM status WHERE id = ?;""", (self.uid,))
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()

    @property
    def duration(self):
        """Calculate the number of second since start() was called

        Args:
            None

        Returns:
            int: Total runtime in seconds since start() was called
        """
        return max(self.timestamp - self.start_time, 0)

    @classmethod
    def load(cls, uid):
        """Read Grizzly status report.

        Args:
            uid (int): Unique ID of Grizzly status to load.

        Returns:
            Status: Grizzly Status object or None if uid is unused.
        """
        assert isinstance(uid, int)
        conn = sqlite3.connect(cls.DB_FILE)
        try:
            cur = conn.cursor()
            cur.execute("""SELECT ignored, iteration, log_size,
                                  results, start_time, time_stamp
                           FROM status WHERE id = ?;""", (uid,))
            row = cur.fetchone()
        except sqlite3.OperationalError:
            return None
        finally:
            conn.close()
        if row is None:
            return None
        report = cls(uid, int(row[4]))
        report.ignored = int(row[0])
        report.iteration = int(row[1])
        report.log_size = int(row[2])
        report.results = int(row[3])
        report.timestamp = int(row[5])
        return report

    @property
    def rate(self):
        """Calculate the number of iterations performed per second since start() was called

        Args:
            None

        Returns:
            float: Number of iterations performed per second
        """
        duration = self.duration
        return self.iteration / float(duration) if duration > 0 else 0

    def report(self, force=False, report_freq=REPORT_FREQ):
        """Write Grizzly status report. Reports are only written when the duration
        of time since the previous report was created exceeds `report_freq` seconds

        Args:
            force (bool): Ignore report frequently limiting.
            report_freq (int): Minimum number of seconds between writes.

        Returns:
            bool: Returns true if the report was successful otherwise false
        """
        now = int(time.time())
        if not force and now < (self.timestamp + report_freq):
            return False
        self.timestamp = now
        conn = sqlite3.connect(self.DB_FILE)
        try:
            conn.execute("""UPDATE status
                            SET ignored = ?,
                                iteration = ?,
                                log_size = ?,
                                results = ?,
                                time_stamp = ?
                            WHERE id = ?;""",
                         (self.ignored, self.iteration, self.log_size,
                          self.results, self.timestamp, self.uid))
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
        return True

    def reset(self):
        """Reset Grizzly status to initial state.

        Args:
            None

        Returns:
            bool: Returns true if the reset was successful otherwise false
        """
        now = int(time.time())
        conn = sqlite3.connect(self.DB_FILE)
        try:
            conn.execute("""UPDATE status
                            SET ignored = 0,
                                iteration = 0,
                                log_size = 0,
                                results = 0,
                                start_time = ?,
                                time_stamp = ?
                            WHERE id = ?;""", (now, now, self.uid))
            conn.commit()
            self.ignored = 0
            self.iteration = 0
            self.log_size = 0
            self.results = 0
            self.start_time = self.timestamp = now
        except sqlite3.OperationalError:
            return False
        finally:
            conn.close()
        return True

    @classmethod
    def start(cls, uid=None):
        """Create a unique Status object.

        Args:
            None

        Returns:
            Status: Ready to be used to report Grizzly status
        """
        conn = sqlite3.connect(cls.DB_FILE)
        try:
            cur = conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS status
                           (id         INTEGER PRIMARY KEY,
                            ignored    INTEGER DEFAULT 0,
                            iteration  INTEGER DEFAULT 0,
                            log_size   INTEGER DEFAULT 0,
                            results    INTEGER DEFAULT 0,
                            start_time INTEGER DEFAULT 0,
                            time_stamp INTEGER DEFAULT 0);""")
            conn.commit()
            now = int(time.time())
            # remove old reports
            cur.execute("""DELETE FROM status
                           WHERE time_stamp < ?;""", (now - cls.AGE_LIMIT,))
            # create new status entry
            if uid is None:
                cur = conn.execute("""INSERT INTO status (start_time, time_stamp)
                                      VALUES (?, ?);""", (now, now))
            else:
                assert isinstance(uid, int)
                cur = conn.execute("""INSERT INTO status (id, start_time, time_stamp)
                                      VALUES (?, ?, ?);""", (uid, now, now))
            conn.commit()
            return cls(cur.lastrowid, now)
        finally:
            conn.close()
