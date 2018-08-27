
import importlib
import logging
import os

import grizzly.corpman

log = logging.getLogger("adapter_loader")  # pylint: disable=invalid-name

__adapters__ = dict()

def load():
    here = os.path.abspath(os.path.dirname(__file__))
    for sub in os.listdir(here):
        if not os.path.isdir(os.path.join(here, sub)):
            continue
        log.debug('processing: %s', sub)
        try:
            lib = importlib.import_module(
                ".%s" % os.path.splitext(sub)[0],
                package="grizzly.corpman.adapters")
        except ImportError as err:
            log.warning("ImportError for %s: %s", os.path.splitext(sub)[0], err)
            continue

        for clsname in dir(lib):
            cls = getattr(lib, clsname)
            if isinstance(cls, type) and issubclass(cls, grizzly.corpman.Adapter):
                # sanity checks
                if not isinstance(cls.NAME, str):
                    raise RuntimeError(
                        "Key for %s should be a string, not '%s'" % (cls.__name__, cls.NAME))
                if cls.NAME.lower() != cls.NAME:
                    raise RuntimeError(
                        "Key for %s should be lowercase, not '%s'" % (cls.__name__, cls.NAME))
                if cls.NAME in __adapters__:
                    raise RuntimeError("Key collision! '%s' is use by %s and %s" % (
                        cls.NAME,
                        __adapters__[cls.NAME].__name__,
                        cls.__name__))
                __adapters__[cls.NAME] = cls


def get(name):
    return __adapters__.get(name, None)


def names():
    return __adapters__.keys()


load()
