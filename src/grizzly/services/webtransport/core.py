# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import asyncio
from asyncio import AbstractEventLoop
from logging import getLogger
from os.path import abspath, dirname, join
from platform import system
from threading import Thread
from typing import TYPE_CHECKING

from aioquic.asyncio import serve  # type: ignore[attr-defined]
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from ..base import BaseService
from .wpt_h3_server import webtransport_h3_server
from .wpt_h3_server.webtransport_h3_server import (
    SessionTicketStore,
    WebTransportH3Protocol,
    _connect_to_server,
)

if TYPE_CHECKING:
    from pathlib import Path

# Override global _doc_root
webtransport_h3_server._doc_root = join(  # pylint: disable=protected-access
    dirname(abspath(__file__)),
    "wpt_h3_server",
    "handlers",
)

LOG = getLogger(__name__)


class WebTransportServer(BaseService):
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

        self._loop: AbstractEventLoop | None = None
        self._server_thread: Thread | None = None
        self._started: bool = False

    @property
    def location(self) -> str:
        return "grz_webtransport_server"

    @property
    def port(self) -> int:
        """The port on which the service is listening"""
        return self._port

    def url(self, _query: str) -> bytes:
        """URL for Sapphire.set_dynamic_response

        Args:
            _query: Unused query string.
        """
        return b"https://127.0.0.1:%d" % (self._port,)

    async def is_ready(self) -> None:
        """Wait until the service is ready"""
        await _connect_to_server("127.0.0.1", self.port)

    def start(self) -> None:
        """Start the server."""

        def _start_service() -> None:
            configuration = QuicConfiguration(
                alpn_protocols=H3_ALPN,
                is_client=False,
                max_datagram_frame_size=65536,
            )

            LOG.debug("Starting WebTransport service on port %s", self.port)
            configuration.load_cert_chain(self._cert, self._key)
            ticket_store = SessionTicketStore()

            # On Windows, the default event loop is ProactorEventLoop, but it
            # doesn't seem to work when aioquic detects a connection loss.
            # Use SelectorEventLoop to work around the problem.
            if system() == "Windows":
                asyncio.set_event_loop_policy(
                    asyncio.WindowsSelectorEventLoopPolicy()  # type: ignore
                )
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

        self._server_thread = Thread(target=_start_service, daemon=True)
        self._server_thread.start()
        self._started = True

    def cleanup(self) -> None:
        """Stop the server."""

        async def _stop_loop() -> None:
            if self._loop is not None:
                self._loop.stop()

        if self._started:
            if self._loop is not None:
                asyncio.run_coroutine_threadsafe(_stop_loop(), self._loop)
            if self._server_thread is not None:
                self._server_thread.join()
            LOG.debug("Stopped WebTransport service on port %s", self._port)
        self._started = False
