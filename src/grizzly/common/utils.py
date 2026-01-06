# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from contextlib import suppress
from importlib.metadata import PackageNotFoundError, version
from logging import getLogger
from os import getenv
from pathlib import Path
from tempfile import gettempdir

__all__ = (
    "HARNESS_FILE",
    "grz_tmp",
    "package_version",
)
__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


GRZ_TMP = Path(getenv("GRZ_TMP", gettempdir()), "grizzly")
HARNESS_FILE = Path(__file__).parent / "harness.html"
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
