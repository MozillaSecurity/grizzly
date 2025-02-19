# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from contextlib import suppress
from logging import getLogger
from shutil import move, rmtree
from time import time
from typing import TYPE_CHECKING

from .utils import grz_tmp, interprocess_lock

if TYPE_CHECKING:
    from pathlib import Path


_ACTIVE_CACHE = None
CACHE_PATH = grz_tmp("cache")
CACHE_TIME = int(time())
LOCK_ID = "cache"
LOG = getLogger(__name__)
MAX_AGE = 86400


def _active_cache(max_age: int = MAX_AGE) -> Path:
    """Retrieve the active cache directory. Create one if needed.

    Args:
        max_age: Maximum age of active cache (relative to process launch time).

    Returns:
        Directory to use to store and retrieve cached content.
    """
    global _ACTIVE_CACHE  # pylint: disable=global-statement
    assert max_age >= 0
    if _ACTIVE_CACHE is None:
        with interprocess_lock(LOCK_ID):
            limit = CACHE_TIME - max_age
            # find most recent active entry
            for entry in sorted(CACHE_PATH.iterdir(), reverse=True):
                with suppress(ValueError):
                    if int(entry.name) > limit and entry.is_dir():
                        _ACTIVE_CACHE = entry
                        LOG.debug("active cache found: '%s'", _ACTIVE_CACHE)
                        break
            else:
                # create a new active entry if one does not exist
                _ACTIVE_CACHE = CACHE_PATH / str(CACHE_TIME)
                _ACTIVE_CACHE.mkdir(parents=True)
                LOG.debug("active cache created: '%s'", _ACTIVE_CACHE)
    return _ACTIVE_CACHE


def add_cached(key: str, src: Path) -> Path:
    """Move a file or directory into the cache.

    Args:
        key: Identifier used to lookup cached data.
        src: File or directory to cache.

    Returns:
        Directory containing cached content.
    """
    dst = _active_cache() / key
    with interprocess_lock(LOCK_ID):
        dst.mkdir(parents=True, exist_ok=True)
        if (dst / src.name).exists():
            LOG.debug("add_cache: '%s' exists in '%s'", (dst / src.name), dst)
        else:
            move(src, dst)
    return dst


def clear_cached(max_age: int = MAX_AGE * 2) -> None:
    """Remove expired content from cache.

    Args:
        max_age: Maximum age of cache directory (relative to process launch time).

    Returns:
        None
    """
    assert max_age >= 0
    limit = CACHE_TIME - max_age
    with interprocess_lock(LOCK_ID):
        # iterate over all directories in CACHE_PATH
        for entry in (x for x in CACHE_PATH.iterdir() if x.is_dir()):
            with suppress(ValueError):
                # remove only expired
                if int(entry.name) <= limit:
                    LOG.debug("removing old cache entry: '%s'", entry)
                    rmtree(entry, ignore_errors=True)


def find_cached(key: str) -> Path | None:
    """Find data in local cache.

    Args:
        key: Identifier used to lookup cached data.

    Returns:
        Directory containing cached content or None if no valid entry is found.
    """
    path = _active_cache() / key
    with interprocess_lock(LOCK_ID):
        if path.is_dir():
            return path
    return None
