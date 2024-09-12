# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from logging import getLogger
from time import time
from traceback import format_exception
from typing import TYPE_CHECKING, Callable

from .worker import Worker

if TYPE_CHECKING:
    from socket import socket

    from .job import Job

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

LOG = getLogger(__name__)


class ConnectionManager:
    # allow extra time before closing socket if needed
    SHUTDOWN_DELAY = 0.5

    __slots__ = (
        "_deadline",
        "_deadline_exceeded",
        "_job",
        "_limit",
        "_next_poll",
        "_poll",
        "_socket",
    )

    def __init__(
        self, job: Job, srv_socket: socket, limit: int = 1, poll: float = 0.5
    ) -> None:
        assert limit > 0
        assert poll > 0
        self._deadline: float | None = None
        self._deadline_exceeded = False
        self._job = job
        self._limit = limit
        self._next_poll = 0.0
        self._poll = poll
        self._socket = srv_socket

    def __enter__(self) -> ConnectionManager:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _can_continue(self, continue_cb: Callable[[], bool] | None) -> bool:
        """Check timeout and callback status.

        Args:
            continue_cb: Indicates whether to continue.

        Returns:
            True if callback returns True and timeout has been be hit otherwise False.
        """
        now = time()
        if self._next_poll > now:
            return True
        self._next_poll = now + self._poll
        # check if callback returns False
        if continue_cb is not None and not continue_cb():
            LOG.debug("continue_cb() returned False")
            return False
        # check for a timeout
        if self._deadline and self._deadline <= now:
            LOG.debug("exceeded serve deadline")
            self._deadline_exceeded = True
            return False
        return True

    def close(self) -> None:
        """Set job state to finished and raise any errors encountered by workers.

        Args:
            None

        Returns:
            None
        """
        self._job.finish()
        if not self._job.exceptions.empty():
            exc_type, exc_obj, exc_tb = self._job.exceptions.get()
            LOG.error(
                "Unexpected exception:\n%s",
                "".join(format_exception(exc_type, exc_obj, exc_tb)),
            )
            # re-raise exception from worker once all workers are closed
            raise exc_obj

    @staticmethod
    def _join_workers(workers: list[Worker], timeout: float = 0) -> list[Worker]:
        """Attempt to join workers.

        Args:
            workers: Collection of workers.
            timeout: Maximum time in seconds to wait.

        Returns:
            Workers that do not join before the timeout is reached.
        """
        deadline = time() + timeout
        return [x for x in workers if not x.join(timeout=max(deadline - time(), 0))]

    def serve(
        self,
        timeout: int,
        continue_cb: Callable[[], bool] | None = None,
        shutdown_delay: float = SHUTDOWN_DELAY,
    ) -> bool:
        """Manage workers and serve job contents.

        Args:
            timeout: Maximum time to serve in seconds.
            continue_cb: Indicates whether to continue.
            shutdown_delay: Time in seconds to wait before calling shutdown on
                            sockets of active workers.

        Returns:
            True unless the timeout is exceeded.
        """
        assert self._job.pending or self._job.forever
        assert shutdown_delay >= 0
        assert timeout >= 0
        if continue_cb is not None and not callable(continue_cb):
            raise TypeError("continue_cb must be callable")

        self._deadline_exceeded = False
        start_time = time()
        self._deadline = start_time + timeout if timeout else None

        launches = 0
        running = 0
        workers: list[Worker] = []
        LOG.debug("accepting requests (workers: %d, timeout: %r)", self._limit, timeout)
        try:
            while not self._job.is_complete() and self._can_continue(continue_cb):
                # launch workers
                if running < self._limit:
                    if not self._job.accepting.wait(0.05):
                        # wait for accepting flag to be set
                        continue
                    worker = Worker.launch(self._socket, self._job)
                    if worker is not None:
                        workers.append(worker)
                        running = len(workers)
                        launches += 1

                # manage workers
                if running >= self._limit:
                    LOG.debug("worker limit (%d) hit, waiting...", running)
                    if self._job.worker_complete.wait(1):
                        self._job.worker_complete.clear()
                    workers = self._join_workers(workers)
                    running = len(workers)
                    LOG.debug("removed completed workers (%d active)", running)

        finally:
            LOG.debug(
                "serve exit: %d request(s) in %0.3fs, waiting for %d worker(s)...",
                launches,
                time() - start_time,
                running,
            )
            if not self._job.is_complete():
                LOG.debug("job not complete")
                self._job.finish()
            # use shutdown_delay to avoid cutting off connections
            workers = self._join_workers(workers, timeout=shutdown_delay)
            # close remaining active workers
            if workers:
                LOG.debug("closing remaining active workers: %d", len(workers))
                for worker in workers:
                    worker.close()
                # join remaining workers
                if self._join_workers(workers, timeout=30):
                    LOG.error("Failed to close %d workers", len(workers))
                    raise RuntimeError("Failed to close workers")

        # return False only if there was a timeout
        return not self._deadline_exceeded
