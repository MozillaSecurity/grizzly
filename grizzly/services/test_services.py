# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor

from pytest import mark

from sapphire import CertificateBundle, ServerMap

from .core import WebServices


@mark.asyncio
async def test_service_01():
    """Verify that services are started and shutdown gracefully"""
    cert = CertificateBundle.create()
    try:
        loop = get_event_loop()
        with ThreadPoolExecutor() as executor:
            ext_services = await loop.run_in_executor(
                executor, WebServices.start_services, cert.host, cert.key
            )

            # Check that all services are running
            assert len(ext_services.services) == 1
            assert await ext_services.is_running()

            server_map = ServerMap()
            ext_services.map_locations(server_map)
            assert len(server_map.dynamic) == 1

            # Check that all services have stopped
            ext_services.cleanup()
            assert not await ext_services.is_running(timeout=0.1)
    finally:
        cert.cleanup()
