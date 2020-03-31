# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import socket
import threading

import sapphire

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = logging.getLogger("sapphire_worker")  # pylint: disable=invalid-name


class SapphireWorker(object):
    __slots__ = ("_conn", "_thread")

    def __init__(self, conn, thread):
        self._conn = conn
        self._thread = thread

    def close(self):
        if not self.done:
            LOG.warning("Closing socket while thread is running!")
        self._conn.close()
        self.join()

    @property
    def done(self):
        if self._thread is not None:
            if not self._thread.is_alive():
                self.join()
        return self._thread is None

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    @classmethod
    def launch(cls, listen_sock, job):
        assert job.accepting.is_set()
        conn = None
        try:
            conn, _ = listen_sock.accept()
            conn.settimeout(None)
            # create a worker thread to handle client request
            w_thread = threading.Thread(target=sapphire.Sapphire._handle_request, args=(conn, job))
            job.accepting.clear()
            w_thread.start()
            return cls(conn, w_thread)
        except (socket.error, socket.timeout):
            if conn is not None:  # pragma: no cover
                conn.close()
        except threading.ThreadError:
            conn.close()
            # reset accepting status
            job.accepting.set()
            raise
        return None
