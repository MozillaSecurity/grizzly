# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from enum import Enum
from logging import getLogger

from sapphire import create_listening_socket

from .webtransport.core import WebTransportServer

LOG = getLogger(__name__)


class ServiceName(Enum):
    """Enum for listing available services"""

    WEBTRANSPORT = 1


class WebServices:
    """Class for running additional web services"""

    def __init__(self, services):
        """Initialize new WebServices instance

        Args:
            services (dict of ServiceName: GrizzlyBaseService): List of running services
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
        for name, service in self.services.values():
            if not service.is_running():
                LOG.info("Failed to start service: %s", ServiceName(name).name)
                return False

        return True

    def cleanup(self):
        """Stops all running services and join's the service thread"""
        for _, service in self.services.items():
            service.cleanup()

    @classmethod
    def start_services(cls, cert, key):
        """Start all available services

        Args:
            cert (Path): Path to the certificate file
            key (Path): Path to the certificate's private key
        """
        services = {}
        # Start WebTransport service
        wt_port = cls.get_free_port()
        services[ServiceName.WEBTRANSPORT] = WebTransportServer(wt_port, cert, key)
        services[ServiceName.WEBTRANSPORT].start()

        ext_services = cls(services)

        # Ensure that all services have started.
        ext_services.is_running()

        return ext_services
