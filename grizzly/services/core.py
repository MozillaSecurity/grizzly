# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio
from enum import Enum
from logging import getLogger
from typing import Dict

from sapphire import create_listening_socket

from .base import GrizzlyBaseService
from .webtransport.core import WebTransportServer

LOG = getLogger(__name__)


class ServiceName(Enum):
    """Enum for listing available services"""

    WEB_TRANSPORT = 1


class WebServices:
    """Class for running additional web services"""

    def __init__(self, services: Dict[ServiceName, GrizzlyBaseService]):
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

    async def is_running(self, timeout=20):
        """Polls all available services to ensure they are running and accessible.

        Args:
            timeout (int): Total time to wait.

        Returns:
            bool: Indicates if all services started successfully.
        """
        tasks = {}
        for name, service in self.services.items():
            task = asyncio.create_task(service.is_ready())
            tasks[name] = task

        try:
            await asyncio.wait_for(asyncio.gather(*tasks.values()), timeout)
        except asyncio.TimeoutError:
            for name, task in tasks.items():
                if not task.done():
                    LOG.warning("Failed to start service (%s)", ServiceName(name).name)
            return False

        return True

    def cleanup(self):
        """Stops all running services and join's the service thread"""
        for service in self.services.values():
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
        services[ServiceName.WEB_TRANSPORT] = WebTransportServer(wt_port, cert, key)
        services[ServiceName.WEB_TRANSPORT].start()

        ext_services = cls(services)
        assert asyncio.run(ext_services.is_running())

        return ext_services
