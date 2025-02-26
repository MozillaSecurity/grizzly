# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import sys  # mypy looks for `sys.version_info`
from contextlib import closing, contextmanager, suppress
from importlib.metadata import EntryPoint, PackageNotFoundError, entry_points, version
from logging import getLogger
from os import getenv
from pathlib import Path
from sqlite3 import IntegrityError, connect
from tempfile import gettempdir
from time import perf_counter, sleep, time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

__all__ = (
    "HARNESS_FILE",
    "grz_tmp",
    "iter_entry_points",
    "package_version",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


GRZ_TMP = Path(getenv("GRZ_TMP", gettempdir()), "grizzly")
HARNESS_FILE = Path(__file__).parent / "harness.html"
LOCK_DB = GRZ_TMP / "lock.db"
LOG = getLogger(__name__)


def grz_tmp(*subdir: str | Path) -> Path:
    """Create (if needed) a temporary working directory in a known location.

    Args:
        subdir: Nested directories.

    Returns:
        Path within the temporary working directory.
    """
    path = Path(GRZ_TMP, *subdir)
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def interprocess_lock(name: str, timeout: int = 60) -> Generator[None]:
    """A cross process locking mechanism.

    Args:
        name: Identifier of lock to acquire.
        timeout: Time to wait (seconds) to acquire lock before raising RuntimeError.

    Yields:
        None
    """
    assert name
    assert timeout > 0
    # prevent a possible but unlikely deadlock (remove old databases)
    with suppress(FileNotFoundError, PermissionError):
        if LOCK_DB.stat().st_mtime < (time() - (timeout * 3)):
            LOCK_DB.unlink(missing_ok=True)
    # connect() should have a timeout greater than the passed timeout
    with closing(connect(LOCK_DB, timeout=60)) as con:
        # create db if needed
        con.execute("CREATE TABLE IF NOT EXISTS locks (name TEXT PRIMARY KEY)")
        # acquire lock
        deadline = perf_counter() + timeout
        while perf_counter() < deadline:
            with suppress(IntegrityError), con:
                con.execute("INSERT INTO locks (name) VALUES (?)", (name,))
                break
            # avoid DoS'ing the database
            sleep(0.2)
        else:
            raise RuntimeError(f"Failed to acquire lock after {timeout}s")
        yield
        # release lock (if this fails it will create a deadlock)
        with con:
            con.execute("DELETE FROM locks WHERE name = ?", (name,))


def iter_entry_points(group: str) -> Generator[EntryPoint]:  # pragma: no cover
    """Compatibility wrapper code for importlib.metadata.entry_points()

    Args:
        group: See entry_points().

    Yields:
        EntryPoint
    """
    # TODO: remove this function when support for Python 3.9 is dropped
    assert group
    if sys.version_info >= (3, 10):
        yield from entry_points().select(group=group)
    else:
        raise AssertionError("Unsupported Python version")


def package_version(name: str, default: str = "unknown") -> str:
    """Get version of an installed package.

    Args:
        name: Package name.
        default: String to use if package is not found.

    Returns:
        Version string.
    """
    with suppress(PackageNotFoundError):
        return version(name)
    # package is not installed
    return default
