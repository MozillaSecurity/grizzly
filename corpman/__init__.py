# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

__author__ = "Jesse Schwartzentruber"
__credits__ = ["Jesse Schwartzentruber"]


import logging as log
from corpman import TestCase, CorpusManager

def _find_managers():
    import importlib
    import os
    import sys

    here = os.path.dirname(__file__)
    known = {}
    for sub in os.listdir(here):
        if sub.endswith(".py") and sub not in {'__init__.py', 'corpman.py'}:
            try:
                lib = importlib.import_module('.%s' % os.path.splitext(sub)[0], 'corpman')
            except ImportError as e:
                log.warn('ImportError for %s: %s', os.path.splitext(sub)[0], e)
                continue
            for clsname in dir(lib):
                cls = getattr(lib, clsname)
                log.debug('Checking out %s...', cls)
                if isinstance(cls, type) and issubclass(cls, CorpusManager):
                    if cls.key.lower() != cls.key:
                        raise RuntimeError('Key for %s should be lowercase, not "%s"', cls.__name__, cls.key)
                    if cls.key in known:
                        log.warn('The name "%s" already in use by %s, skipping %s', cls.key, known[cls.key].__name__, cls.__name__)
                        continue
                    globals()[clsname] = cls
                    known[cls.key] = cls
                else:
                    log.debug('-> nope, %s is a %s', cls, type(cls))
    return known

managers = _find_managers()

