# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio

from grizzly.common.utils import CertificateBundle
from .core import WebServices


def test_service_01():
    """Verify that services are started and that event loop/thread are closed on cleanup"""
    cert = CertificateBundle.create()
    try:
        ext_services = WebServices.start_services(cert.host, cert.key)
        assert len(ext_services.services.keys()) == 1

        # Check that all services are running
        for service in ext_services.services.values():
            assert asyncio.run(service.is_running()) is True

        ext_services.cleanup()

        # Check that all services have stopped
        assert ext_services._thread.is_alive() is False
    finally:
        cert.cleanup()
