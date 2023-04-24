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

    @abstractmethod
    async def is_running(self):
        """Returns a boolean which indicates if the service is running"""
