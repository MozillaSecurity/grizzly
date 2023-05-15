# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from grizzly.common.utils import CertificateBundle
from grizzly_services import WebServices

from .core import WebTransportServer


def test_webtransport_01():
    """Verify that the WebTransport service started and shutdown gracefully"""
    cert = CertificateBundle.create()
    try:
        port = WebServices.get_free_port()
        web_transport = WebTransportServer(port, cert.host, cert.key)
        assert web_transport._started is False

        web_transport.start()

        # Check that all services are running
        assert web_transport._started is True
        assert web_transport.is_running() is True

        web_transport.cleanup()

        assert web_transport._started is False
        assert web_transport.is_running() is False
    finally:
        cert.cleanup()
