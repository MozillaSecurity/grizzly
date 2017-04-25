# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import importlib
import logging
import os

from .corpman import CorpusManager

__all__ = ("Loader")
__author__ = "Jesse Schwartzentruber"
__credits__ = ["Jesse Schwartzentruber", "Tyson Smith"]


log = logging.getLogger("corpman_loader") # pylint: disable=invalid-name


class Loader(object):
    def __init__(self):
        self._managers = None


    def _find_managers(self):
        if self._managers is not None:
            # This is here to avoid reloading the managers dict multiple times.
            # It is a workaround to allow the logger to be set in Grizzly before it is used here.
            return
        here = os.path.abspath(os.path.dirname(__file__))
        log.debug('looking for CorpusManagers in: %s', here)
        self._managers = {}
        ignore_list = ('__init__.py', 'corpman.py', 'loader.py', 'tests.py')
        for sub in os.listdir(here):
            if sub.endswith(".py") and sub not in ignore_list:
                log.debug('processing: %s', sub)
                try:
                    # a lovely hack for pytest's sake. __future__.absolute_import doesn't seem to affect importlib?
                    try:
                        lib = importlib.import_module('.%s' % os.path.splitext(sub)[0], 'grizzly.corpman')
                    except ImportError:
                        lib = importlib.import_module('.%s' % os.path.splitext(sub)[0], 'corpman')
                except ImportError as err:
                    log.warning('ImportError for %s: %s', os.path.splitext(sub)[0], err)
                    continue
                for clsname in dir(lib):
                    cls = getattr(lib, clsname)
                    if isinstance(cls, type) and issubclass(cls, CorpusManager):
                        if not isinstance(cls.key, str):
                            raise RuntimeError(
                                'Key for %s should be a string, not "%s"' % (cls.__name__, cls.key))
                        if cls.key.lower() != cls.key:
                            raise RuntimeError(
                                'Key for %s should be lowercase, not "%s"' % (cls.__name__, cls.key))
                        if cls.key in self._managers:
                            raise RuntimeError('Key collision! "%s" is use by %s and %s' % (
                                cls.key,
                                self._managers[cls.key].__name__,
                                cls.__name__))
                        globals()[clsname] = cls
                        self._managers[cls.key] = cls


    def get(self, manager_key):
        self._find_managers()
        return self._managers.get(manager_key, None)


    def list(self):
        self._find_managers()
        return self._managers.keys()
