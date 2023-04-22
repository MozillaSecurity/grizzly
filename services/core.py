# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio
from logging import getLogger
from threading import Thread

from .webtransport import WebTransportServer

LOG = getLogger(__name__)


class WebServices:
    """Class for running additional web services."""

    def __init__(self, thread, loop, services):
        """Initialize new WebServices instance.

        Args:
            thread (Thread): Active thread.
            loop (AbstractEventLoop): Active asyncio event loop.
        """
        self._loop = loop
        self._thread = thread
        self.services = services

    def cleanup(self):
        for task in asyncio.all_tasks(loop=self._loop):
            task.cancel()

        self._loop.stop()
        self._thread.join()

    @classmethod
    def start_services(cls, cert, key):
        LOG.debug("starting web services")

        services = {}
        loop = asyncio.new_event_loop()

        # Start WebTransport service
        wt_service = WebTransportServer()
        loop.create_task(wt_service.start(cert, key))
        # TODO: this fails if we open the socket in wt_service.start()
        # I'm not sure how to use Events with async (haven't looked)
        assert wt_service.port
        services["wt"] = {"port": wt_service.port}

        thread = Thread(target=loop.run_forever, daemon=True)
        thread.start()
        return cls(thread, loop, services)
