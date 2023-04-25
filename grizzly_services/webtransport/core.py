# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio
import ssl
from logging import WARNING, getLogger

from aioquic.asyncio import connect, serve
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from sapphire import create_listening_socket

from ..base import GrizzlyBaseService
from .wt_server import WebTransportProtocol

getLogger("quic").setLevel(WARNING)

LOG = getLogger(__name__)


class WebTransportServer(GrizzlyBaseService):
    def __init__(self):
        self._port = None

    @property
    def port(self):
        """The port on which the service is listening"""
        return self._port

    async def is_running(self):
        """Returns a boolean which indicates if the service is running"""

        async def connect_to_server():
            """Attempts to connect to the Quic service"""
            config = QuicConfiguration(
                alpn_protocols=H3_ALPN,
                is_client=True,
                verify_mode=ssl.CERT_NONE,
            )

            async with connect("127.0.0.1", self.port, configuration=config) as client:
                await client.ping()

        for _ in range(3):
            try:
                LOG.debug("attempting to connect to webtransport server")
                await asyncio.wait_for(connect_to_server(), timeout=3)
            except asyncio.TimeoutError:
                LOG.debug("connection timed out")
                await asyncio.sleep(1)
            else:
                return True

        return False

    async def start(self, cert, key):
        """Start the WebTransport Service

        Args:
            cert (Path): Path to the certificate file
            key (Path): Path to the certificate's private key
        """
        sock = create_listening_socket()
        self._port = sock.getsockname()[1]
        sock.close()

        configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=False,
            max_datagram_frame_size=65536,
        )
        configuration.load_cert_chain(cert, key)
        LOG.info("Starting WebTransport service on port %s", self.port)
        await serve(
            "127.0.0.1",
            self.port,
            configuration=configuration,
            create_protocol=WebTransportProtocol,
        )
