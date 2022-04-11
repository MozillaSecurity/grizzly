# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from sys import exc_info
from threading import Thread, ThreadError, active_count
from time import sleep, time
from traceback import format_exception

from .worker import Worker

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class ConnectionManager:
    SHUTDOWN_DELAY = 0.5  # allow extra time before closing socket if needed

    __slots__ = ("_job", "_listener", "_socket", "_workers")

    def __init__(self, job, sock, max_workers=1):
        assert max_workers > 0
        self._job = job
        self._listener = None
        self._socket = sock
        self._workers = max_workers

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._job.finish()
        if self._listener is not None:
            self._listener.join()
            self._listener = None
        if not self._job.exceptions.empty():
            exc_type, exc_obj, exc_tb = self._job.exceptions.get()
            LOG.error(
                "Unexpected exception:\n%s",
                "".join(format_exception(exc_type, exc_obj, exc_tb)),
            )
            # re-raise exception from worker once all workers are closed
            raise exc_obj

    def start(self):
        assert self._job.pending
        # create the listener thread to handle incoming requests
        listener = Thread(
            target=self.listener,
            args=(self._socket, self._job, self._workers),
            kwargs={"shutdown_delay": self.SHUTDOWN_DELAY},
        )
        # launch listener thread and handle thread errors
        for retry in reversed(range(10)):
            try:
                listener.start()
            except ThreadError:
                # thread errors can be due to low system resources while fuzzing
                LOG.warning("ThreadError (listener), threads: %d", active_count())
                if retry < 1:
                    raise
                sleep(1)
                continue
            self._listener = listener
            break

    def wait(self, timeout, continue_cb=None, poll=0.5):
        assert self._listener is not None
        if timeout > 0:
            deadline = time() + timeout
        else:
            deadline = None
        if continue_cb is not None and not callable(continue_cb):
            raise TypeError("continue_cb must be callable")
        # it is important to keep this loop fast because it can limit
        # the total iteration rate of Grizzly
        while not self._job.is_complete(wait=poll):
            # check for a timeout
            if deadline and deadline <= time():
                return False
            # check if callback returns False
            if continue_cb is not None and not continue_cb():
                LOG.debug("continue_cb() returned False")
                break
        return True

    @staticmethod
    def listener(serv_sock, serv_job, max_workers, shutdown_delay=0):
        assert max_workers > 0
        assert shutdown_delay >= 0
        total_launches = 0
        worker_pool = list()
        pool_size = 0
        LOG.debug("starting listener")
        try:
            while not serv_job.is_complete():
                if not serv_job.accepting.wait(0.05):
                    continue
                worker = Worker.launch(serv_sock, serv_job)
                if worker is not None:
                    worker_pool.append(worker)
                    pool_size += 1
                    total_launches += 1
                # manage worker pool
                if pool_size >= max_workers:
                    LOG.debug(
                        "pool size: %d, waiting for worker to finish...", pool_size
                    )
                    serv_job.worker_complete.wait()
                    serv_job.worker_complete.clear()
                    LOG.debug("removing completed workers from worker pool")
                    # sometimes the thread that triggered the event doesn't quite
                    # cleanup in time, so retry (10x with 0.5 second sleep on failure)
                    for _ in range(10):
                        worker_pool = list(w for w in worker_pool if not w.done)
                        pool_size = len(worker_pool)
                        if pool_size < max_workers:
                            break
                        sleep(0.5)  # pragma: no cover
                    else:  # pragma: no cover
                        # this should never happen
                        raise RuntimeError("Failed to trim worker pool!")
                    LOG.debug("trimmed worker pool (size: %d)", pool_size)
        except Exception:  # pylint: disable=broad-except
            if serv_job.exceptions.empty():
                serv_job.exceptions.put(exc_info())
            serv_job.finish()
        finally:
            LOG.debug(
                "shutting down listener, waiting %0.2fs for %d of %d worker(s)...",
                shutdown_delay,
                len(worker_pool),
                total_launches,
            )
            # use shutdown_delay to avoid cutting off connections
            deadline = time() + shutdown_delay
            while time() < deadline:
                # wait for all running workers to exit
                if all(w.done for w in worker_pool):
                    break
                sleep(0.1)
            else:  # pragma: no cover
                worker_pool = list(w for w in worker_pool if not w.done)
                LOG.debug("closing remaining %d worker(s)", len(worker_pool))
                for worker in worker_pool:
                    worker.close()
