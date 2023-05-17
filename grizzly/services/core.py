# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger

from sapphire import create_listening_socket

from .webtransport.core import WebTransportServer

LOG = getLogger(__name__)


class WebServices:
    """Class for running additional web services"""

    def __init__(self, services):
        """Initialize new WebServices instance

        Args:
            services (list): List of running services
        """
        self.services = services

    @staticmethod
    def get_free_port():
        """Returns an open port"""
        sock = create_listening_socket()
        port = sock.getsockname()[1]
        sock.close()

        return port

    def is_running(self):
        for service in self.services:
            if service.is_running() is False:
                LOG.info("Failed to start service: %s", service.__class__.__name__)
                return False

        return True

    def cleanup(self):
        """Stops all running services and join's the service thread"""
        for service in self.services:
            service.cleanup()

    @classmethod
    def start_services(cls, cert, key):
        """Start all available services

        Args:
            cert (Path): Path to the certificate file
            key (Path): Path to the certificate's private key
        """
        # Start WebTransport service
        wt_port = cls.get_free_port()
        wt_service = WebTransportServer(wt_port, cert, key)
        wt_service.start()

        ext_services = cls([wt_service])

        # Ensure that all services have started.
        ext_services.is_running()

        return ext_services
