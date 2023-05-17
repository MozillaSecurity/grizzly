# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from ..common.utils import CertificateBundle
from .core import WebServices


def test_service_01():
    """Verify that services are started and shutdown gracefully"""
    cert = CertificateBundle.create()
    try:
        ext_services = WebServices.start_services(cert.host, cert.key)
        assert len(ext_services.services) == 1

        # Check that all services are running
        assert ext_services.is_running() is True

        ext_services.cleanup()

        # Check that all services have stopped
        assert ext_services.is_running() is False
    finally:
        cert.cleanup()
