# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio
from operator import itemgetter
from threading import Thread

from .webtransport import WebTransportServer


class WebServices:
    """Class for running additional web services"""

    def __init__(self, thread, loop, services):
        """Initialize new WebServices instance

        Args:
            loop (AbstractEventLoop): Active asyncio event loop
            services (list): List of running services
        """
        self._thread = thread
        self._loop = loop

        self.services = services

    async def is_running(self):
        for service in self.services:
            await service.is_running()

    def cleanup(self):
        """Stops all running services and join's the service thread"""
        self._loop.call_soon_threadsafe(self._loop.stop)

        if self._thread is not None:
            self._thread.join()

    @classmethod
    def start_services(cls, cert, key):
        """Start all available services

        Args:
            cert (Path): Path to the certificate file
            key (Path): Path to the certificate's private key
        """
        loop = asyncio.new_event_loop()

        # Start WebTransport service
        wt_service = WebTransportServer()
        loop.create_task(wt_service.start(cert, key))

        # Run the loop in a new thread
        thread = Thread(target=loop.run_forever, daemon=True)
        thread.start()

        ext_services = cls(thread, loop, [wt_service])

        # Ensure that all services have started.
        asyncio.run(ext_services.is_running())

        return ext_services
