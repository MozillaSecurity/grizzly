import importlib
import logging
import os
import sys
import traceback

from grizzly.common import Adapter

log = logging.getLogger("grizzly")  # pylint: disable=invalid-name

__all__ = ("get", "load", "names")
__adapters__ = dict()

def get(name):
    return __adapters__.get(name.lower(), None)

def load(path=None, skip_failures=True):
    assert not __adapters__, "adapters have already been loaded"
    if path is None:
        path = os.path.dirname(__file__)
    path = os.path.abspath(path)
    log.debug("loading adapters from %r", path)
    sys.path.append(path)
    for sub in os.listdir(path):
        if not os.path.isfile(os.path.join(path, sub, "__init__.py")):
            continue
        log.debug("scanning %r", sub)
        try:
            lib = importlib.import_module(sub)
        except Exception:  # pylint: disable=broad-except
            if not skip_failures:
                raise
            exc_type, exc_obj, exc_tb = sys.exc_info()
            tbinfo = traceback.extract_tb(exc_tb)[-1]
            log.debug("raised %s: %s (%s:%d)", exc_type.__name__, exc_obj, tbinfo[0], tbinfo[1])
            continue
        for clsname in dir(lib):
            cls = getattr(lib, clsname)
            if isinstance(cls, type) and issubclass(cls, Adapter):
                if clsname == "Adapter":
                    continue
                log.debug("sanity checking %r", clsname)
                if not isinstance(cls.NAME, str):
                    raise RuntimeError(
                        "%s.NAME must be 'str' not %r" % (cls.__name__, type(cls.NAME).__name__))
                if cls.NAME.lower() != cls.NAME:
                    raise RuntimeError(
                        "%s.NAME %r must be lowercase" % (cls.__name__, cls.NAME))
                if cls.NAME in __adapters__:
                    raise RuntimeError(
                        "Name collision! %r is used by %r and %r" % (
                            cls.NAME,
                            __adapters__[cls.NAME].__name__,
                            cls.__name__))
                __adapters__[cls.NAME] = cls
        else:
            log.debug("ignored %r", sub)
    log.debug("%d adapters loaded", len(__adapters__))

def names():
    return __adapters__.keys()
