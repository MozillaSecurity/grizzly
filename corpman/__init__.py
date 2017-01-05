# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

__author__ = "Jesse Schwartzentruber"
__credits__ = ["Jesse Schwartzentruber"]


import logging
from corpman import Template, TestCase, CorpusManager


log = logging.getLogger("grizzly") # pylint: disable=invalid-name


def _find_managers():
    import importlib
    import os
    import sys

    here = os.path.dirname(__file__)
    known = {}
    for sub in os.listdir(here):
        if sub.endswith(".py") and sub not in {'__init__.py', 'corpman.py', 'tests.py'}:
            try:
                lib = importlib.import_module('.%s' % os.path.splitext(sub)[0], 'corpman')
            except ImportError:
                log.warning('ImportError for %s', os.path.splitext(sub)[0], exc_info=True)
                continue
            for clsname in dir(lib):
                cls = getattr(lib, clsname)
                log.debug('Checking out %s...', cls)
                if isinstance(cls, type) and issubclass(cls, CorpusManager):
                    if not isinstance(cls.key, str):
                        raise RuntimeError('Key for %s should be a string, not "%s"' % (cls.__name__, cls.key))
                    if cls.key.lower() != cls.key:
                        raise RuntimeError('Key for %s should be lowercase, not "%s"' % (cls.__name__, cls.key))
                    if cls.key in known:
                        log.warning('The name "%s" already in use by %s, skipping %s',
                                    cls.key,
                                    known[cls.key].__name__,
                                    cls.__name__)
                        continue
                    globals()[clsname] = cls
                    known[cls.key] = cls
                else:
                    log.debug('-> nope, %s is a %s', cls, type(cls))
    return known


managers = _find_managers()
