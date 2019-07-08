# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Manage Grizzly status reports."""
import logging
import os
import sqlite3
import tempfile
import time

__all__ = ("Status",)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = logging.getLogger("status")


class Status(object):
    """Status holds status information for the Grizzly session.
    """
    AGE_LIMIT = 3600  # 1 hour
    DB_FILE = os.path.join(tempfile.gettempdir(), "grz-status.db")
    REPORT_FREQ = 60

    def __init__(self, uid, start_time, conn=None):
        assert isinstance(start_time, int)
        assert isinstance(uid, int)
        self.conn = conn
        self.ignored = 0
        self.iteration = 0
        self.log_size = 0
        self.results = 0
        self.start_time = start_time
        self.test_name = None
        self.timestamp = start_time
        self.uid = uid

    def cleanup(self):
        """Close db connection and remove entries that are no longer needed.

        Args:
            None

        Returns:
            None
        """
        if self.conn is None:
            LOG.debug("cleanup: self.conn is None")
            return
        try:
            self.conn.execute("""DELETE FROM status WHERE id = ?;""", (self.uid,))
            self.conn.commit()
        except (sqlite3.OperationalError, sqlite3.ProgrammingError) as exc:
            LOG.warning("cleanup failed: %r", str(exc))
        self.close()

    def close(self):
        """Close db connection.

        Args:
            None

        Returns:
            None
        """
        if self.conn is not None:
            LOG.debug("closing db connection")
            self.conn.close()
            self.conn = None

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
    def load(cls, conn=None, timeout=10, uid=None):
        """Read Grizzly status reports.

        Args:
            conn (sqlite3.Connection): An open (shared) sqlite db connection.
            timeout (int): Timeout for sqlite db connection.
            uid (int): Unique ID of Grizzly status to load.

        Returns:
            Generator: Status objects stored in cls.DB_FILE
        """
        LOG.debug("load uid %r", uid)
        if uid is None:
            assert conn is not None, "shared conn required when loading all entries"
            query = """SELECT id, ignored, iteration, log_size,
                              results, start_time, time_stamp
                       FROM status
                       WHERE time_stamp >= ?;"""
            args = (int(time.time()) - cls.AGE_LIMIT,)
        else:
            assert isinstance(uid, int)
            if conn is None:
                conn = cls.open_connection(timeout=timeout)
            query = """SELECT id, ignored, iteration, log_size,
                              results, start_time, time_stamp
                       FROM status
                       WHERE time_stamp >= ? AND id = ?;"""
            args = (int(time.time()) - cls.AGE_LIMIT, uid)
        try:
            for row in conn.execute(query, args):
                # if uid is None a shared connection is implied and
                # not passed to the status object
                status = cls(int(row[0]), int(row[5]), conn=None if uid is None else conn)
                status.ignored = int(row[1])
                status.iteration = int(row[2])
                status.log_size = int(row[3])
                status.results = int(row[4])
                status.timestamp = int(row[6])
                yield status
        except sqlite3.OperationalError as exc:
            LOG.warning("load failed: %r", str(exc))
            conn.close()

    @classmethod
    def open_connection(cls, timeout=10):
        """Open a database connection.

        Args:
            timeout (int): Timeout for sqlite db connection.

        Returns:
            sqlite3.Connection: An open sqlite db connection.
        """
        LOG.debug("opening db %r (timeout %d)", cls.DB_FILE, timeout)
        return sqlite3.connect(cls.DB_FILE, timeout)

    @property
    def rate(self):
        """Calculate the number of iterations performed per second since start() was called

        Args:
            None

        Returns:
            float: Number of iterations performed per second
        """
        return self.iteration / float(self.duration) if self.duration > 0 else 0

    def report(self, force=False, report_freq=REPORT_FREQ):
        """Write Grizzly status report. Reports are only written when the duration
        of time since the previous report was created exceeds `report_freq` seconds

        Args:
            force (bool): Ignore report frequently limiting.
            report_freq (int): Minimum number of seconds between writes.

        Returns:
            bool: Returns true if the report was successful otherwise false
        """
        assert self.conn is not None
        now = int(time.time())
        if not force and now < (self.timestamp + report_freq):
            return False
        self.timestamp = now
        try:
            self.conn.execute("""UPDATE status
                                 SET ignored = ?,
                                     iteration = ?,
                                     log_size = ?,
                                     results = ?,
                                     time_stamp = ?
                                 WHERE id = ?;""",
                              (self.ignored, self.iteration, self.log_size,
                               self.results, self.timestamp, self.uid))
            self.conn.commit()
        except sqlite3.OperationalError as exc:
            LOG.warning("report failed: %r", str(exc))
            return False
        return True

    def reset(self):
        """Reset Grizzly status to initial state.

        Args:
            None

        Returns:
            bool: Returns true if the reset was successful otherwise false
        """
        assert self.conn is not None
        now = int(time.time())
        try:
            self.conn.execute("""UPDATE status
                                 SET ignored = 0,
                                     iteration = 0,
                                     log_size = 0,
                                     results = 0,
                                     start_time = ?,
                                     time_stamp = ?
                                 WHERE id = ?;""", (now, now, self.uid))
            self.conn.commit()
            self.ignored = 0
            self.iteration = 0
            self.log_size = 0
            self.results = 0
            self.start_time = self.timestamp = now
        except sqlite3.OperationalError as exc:
            LOG.warning("reset failed: %r", str(exc))
            return False
        return True

    @classmethod
    def start(cls, uid=None):
        """Create a unique Status object.

        Args:
            uid (int): Unique ID of Grizzly status to use.

        Returns:
            Status: Ready to be used to report Grizzly status
        """
        conn = cls.open_connection()
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
            now = int(time.time())
            # remove old reports
            cur.execute("""DELETE FROM status
                           WHERE time_stamp < ?;""", (now - cls.AGE_LIMIT,))
            # create new status entry
            if uid is None:
                cur = conn.execute("""INSERT INTO status (start_time, time_stamp)
                                      VALUES (?, ?);""", (now, now))
            else:
                LOG.warning("uid %r specified", uid)
                assert isinstance(uid, int)
                cur = conn.execute("""INSERT INTO status (id, start_time, time_stamp)
                                      VALUES (?, ?, ?);""", (uid, now, now))
            conn.commit()
            return cls(cur.lastrowid, now, conn=conn)
        except sqlite3.OperationalError:
            conn.close()
            raise
