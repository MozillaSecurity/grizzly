# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .corpman import TestCase, CorpusManager
import loader as cmloader


__all__ = ("TestCase", "CorpusManager", "loader")
__author__ = "Jesse Schwartzentruber"
__credits__ = ["Jesse Schwartzentruber"]


loader = cmloader.Loader()
