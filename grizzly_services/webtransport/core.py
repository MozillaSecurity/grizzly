# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio
import sys
import threading
from logging import WARNING, getLogger
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from ..base import GrizzlyBaseService
from .wpt_h3_server.webtransport_h3_server import (
    SessionTicketStore,
    WebTransportH3Protocol,
    server_is_running,
)

getLogger("quic").setLevel(WARNING)

LOG = getLogger(__name__)


class WebTransportServer(GrizzlyBaseService):
    def __init__(self, port: int, cert: Path, key: Path) -> None:
        """A WebTransport service.

        Args:
            port: The port on which to listen on.
            cert: The path to the certificate file.
            key: The path to the certificate's private key.
        """
        self._port = port
        self._cert = cert
        self._key = key

        self._loop = None
        self._server_thread = None
        self._started = False

    @property
    def port(self):
        """The port on which the service is listening"""
        return self._port

    def is_running(self):
        """Check if the service is running"""
        for _ in range(3):
            LOG.debug("attempting to connect to webtransport server")
            result = server_is_running("127.0.0.1", self.port, timeout=1.0)
            if result is True:
                return result

        return False

    def start(self) -> None:
        """Start the server."""

        def _start_service() -> None:
            configuration = QuicConfiguration(
                alpn_protocols=H3_ALPN,
                is_client=False,
                max_datagram_frame_size=65536,
            )

            LOG.info("Starting WebTransport service on port %s", self.port)
            configuration.load_cert_chain(self._cert, self._key)
            ticket_store = SessionTicketStore()

            # On Windows, the default event loop is ProactorEventLoop, but it
            # doesn't seem to work when aioquic detects a connection loss.
            # Use SelectorEventLoop to work around the problem.
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            self._loop.run_until_complete(
                serve(
                    "127.0.0.1",
                    self.port,
                    configuration=configuration,
                    create_protocol=WebTransportH3Protocol,
                    session_ticket_fetcher=ticket_store.pop,
                    session_ticket_handler=ticket_store.add,
                )
            )
            self._loop.run_forever()

        self._server_thread = threading.Thread(target=_start_service, daemon=True)
        self._server_thread.start()
        self._started = True

    def cleanup(self) -> None:
        """Stop the server."""

        async def _stop_loop() -> None:
            self._loop.stop()

        if self._started:
            asyncio.run_coroutine_threadsafe(_stop_loop(), self._loop)
            self._server_thread.join()
            LOG.info("Stopped WebTransport service on port %s", self._port)
        self._started = False
