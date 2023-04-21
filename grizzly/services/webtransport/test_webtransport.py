# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
import asyncio

import pytest

from sapphire import CertificateBundle

from ..core import WebServices
from .core import WebTransportServer


def test_webtransport_01():
    """Verify that the WebTransport service started and shutdown gracefully"""
    cert = CertificateBundle.create()
    try:
        port = WebServices.get_free_port()
        web_transport = WebTransportServer(port, cert.host, cert.key)
        assert not web_transport._started

        web_transport.start()

        # Check that all services are running
        assert web_transport._started
        asyncio.run(asyncio.wait_for(web_transport.is_ready(), timeout=3.0))

        assert web_transport.location == "grz_webtransport_server"
        assert isinstance(web_transport.url(""), bytes)

        web_transport.cleanup()

        assert not web_transport._started
        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(asyncio.wait_for(web_transport.is_ready(), timeout=1.0))
    finally:
        cert.cleanup()
