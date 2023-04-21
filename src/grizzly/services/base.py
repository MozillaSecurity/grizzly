# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from abc import ABC, abstractmethod


class BaseService(ABC):
    """Base service class"""

    @property
    @abstractmethod
    def location(self) -> str:
        """Location to use with Sapphire.set_dynamic_response"""

    @property
    @abstractmethod
    def port(self) -> int:
        """The port on which the server is listening"""

    @abstractmethod
    def url(self, _query: str) -> bytes:
        """Returns the URL of the server."""

    @abstractmethod
    async def is_ready(self) -> None:
        """Wait until the service is ready"""

    @abstractmethod
    def cleanup(self) -> None:
        """Stop the server."""
