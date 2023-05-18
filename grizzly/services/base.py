# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from abc import ABC, abstractmethod


class GrizzlyBaseService(ABC):
    """Base service class"""

    @property
    @abstractmethod
    def port(self):
        """The port on which the service is listening"""

    @property
    @abstractmethod
    def url(self):
        """Returns the URL and callback for Sapphire.set_dynamic_response"""

    @abstractmethod
    async def is_ready(self):
        """Wait until the service is ready"""

    @abstractmethod
    def cleanup(self):
        """Stop the server."""
