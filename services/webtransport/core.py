# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger

from aioquic.asyncio import serve
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from sapphire import create_listening_socket

from .wt_server import WebTransportProtocol

LOG = getLogger(__name__)


class WebTransportServer:
    def __init__(self):
        self._socket = create_listening_socket()
        self.port = self._socket.getsockname()[1]

    async def start(self, cert, key):
        # TODO: it'd be nice to open and close the socket here
        self._socket.close()
        configuration = QuicConfiguration(
            alpn_protocols=H3_ALPN,
            is_client=False,
            max_datagram_frame_size=65536,
        )
        configuration.load_cert_chain(cert, key)
        LOG.debug("starting WebTransport service on port %d", self.port)
        await serve(
            "127.0.0.1",
            self.port,
            configuration=configuration,
            create_protocol=WebTransportProtocol,
        )
