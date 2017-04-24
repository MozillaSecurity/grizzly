# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging

from .corpman import TestCase, CorpusManager

__author__ = "Jesse Schwartzentruber"
__credits__ = ["Jesse Schwartzentruber"]


log = logging.getLogger("corpman_init") # pylint: disable=invalid-name


def _find_managers():
    import importlib
    import os
    import sys

    here = os.path.dirname(__file__)
    log.debug('looking for CorpusManagers in: %s', here)
    known = {}
    for sub in os.listdir(here):
        if sub.endswith(".py") and sub not in {'__init__.py', 'corpman.py', 'tests.py'}:
            log.debug('processing: %s', sub)
            try:
                # a lovely hack for pytest's sake. __future__.absolute_import doesn't seem to affect importlib?
                try:
                    lib = importlib.import_module('.%s' % os.path.splitext(sub)[0], 'grizzly.corpman')
                except ImportError:
                    lib = importlib.import_module('.%s' % os.path.splitext(sub)[0], 'corpman')
            except ImportError as e:
                log.warning('ImportError for %s: %s', os.path.splitext(sub)[0], e)
                continue
            for clsname in dir(lib):
                cls = getattr(lib, clsname)
                if isinstance(cls, type) and issubclass(cls, CorpusManager):
                    if not isinstance(cls.key, str):
                        raise RuntimeError('Key for %s should be a string, not "%s"' % (cls.__name__, cls.key))
                    if cls.key.lower() != cls.key:
                        raise RuntimeError('Key for %s should be lowercase, not "%s"' % (cls.__name__, cls.key))
                    if cls.key in known:
                        raise RuntimeError(
                            'Key collision! "%s" is use by %s and %s',
                            cls.key,
                            known[cls.key].__name__,
                            cls.__name__)
                    globals()[clsname] = cls
                    known[cls.key] = cls
    return known


class Loader(object):
    def __init__(self):
        self._managers = None


    def get(self, manager_key):
        if self._managers is None:
            self._managers = _find_managers()
        return self._managers[manager_key]


    def list(self):
        if self._managers is None:
            self._managers = _find_managers()
        return self._managers


loader = Loader()
