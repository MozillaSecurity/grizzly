# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import asyncio
from collections.abc import Mapping
from enum import Enum
from logging import getLogger
from pathlib import Path
from typing import cast

from sapphire import ServerMap, create_listening_socket

from .base import BaseService
from .webtransport.core import WebTransportServer

LOG = getLogger(__name__)


class ServiceName(Enum):
    """Enum for listing available services"""

    WEB_TRANSPORT = 1


class WebServices:
    """Class for running additional web services"""

    def __init__(self, services: Mapping[ServiceName, BaseService]):
        """Initialize new WebServices instance

        Args:
            services (dict of ServiceName: BaseService): Collection of services.
        """
        self.services = services

    @staticmethod
    def get_free_port() -> int:
        """Returns an open port"""
        sock = create_listening_socket()
        port = cast(int, sock.getsockname()[1])
        sock.close()

        return port

    async def is_running(self, timeout: float = 20) -> bool:
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

    def cleanup(self) -> None:
        """Stops all running services and join's the service thread"""
        for service in self.services.values():
            service.cleanup()

    def map_locations(self, server_map: ServerMap) -> None:
        """Configure server map"""
        for service in self.services.values():
            server_map.set_dynamic_response(
                service.location, service.url, mime_type="text/plain", required=False
            )

    @classmethod
    def start_services(cls, cert: Path, key: Path) -> "WebServices":
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
