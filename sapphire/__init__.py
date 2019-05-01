# coding=utf-8
"""
Sapphire HTTP server
"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .core import Sapphire, SERVED_ALL, SERVED_NONE, SERVED_REQUEST, SERVED_TIMEOUT

__all__ = ("Sapphire", "SERVED_ALL", "SERVED_NONE", "SERVED_REQUEST", "SERVED_TIMEOUT")
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]
