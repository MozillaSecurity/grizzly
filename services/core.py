# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio
from threading import Thread

from .webtransport import WebTransportServer


class WebServices:
    """Class for running additional web services."""

    def __init__(self, thread, loop, services):
        """Initialize new WebServices instance.

        Args:
            thread (Thread): Active thread.
            loop (AbstractEventLoop): Active asyncio event loop.
        """
        self._thread = thread
        self._loop = loop

        self.services = services

    def cleanup(self):
        for task in asyncio.all_tasks(loop=self._loop):
            task.cancel()

        self._loop.stop()
        self._thread.join()

    @classmethod
    def start_services(cls, cert, key):
        services = []
        loop = asyncio.new_event_loop()

        # Start WebTransport service
        wt_service = WebTransportServer()
        services.append({"name": "wt", "port": wt_service.port})
        loop.create_task(wt_service.start(cert, key))

        thread = Thread(target=loop.run_forever, daemon=True)
        thread.start()
        return cls(thread, loop, services)
