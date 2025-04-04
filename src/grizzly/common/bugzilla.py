# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

import binascii
from base64 import b64decode
from logging import getLogger
from os import environ
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from types import MappingProxyType
from typing import TYPE_CHECKING
from zipfile import ZipFile

from bugsy import Bug, Bugsy
from bugsy.errors import BugsyException
from requests.exceptions import ConnectionError as RequestsConnectionError

from .utils import grz_tmp

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable

# attachments that can be ignored
IGNORE_EXTS = frozenset(
    (
        "c",
        "cpp",
        "diff",
        "diffs",
        "exe",
        "gz",
        "idl",
        "log",
        "patch",
        "php",
        "py",
        "tar",
        "txt",
        "xul",
    )
)
# TODO: support all target assets
KNOWN_ASSETS = MappingProxyType({"prefs": "prefs.js"})
LOG = getLogger(__name__)


class BugzillaBug:
    __slots__ = ("_bug", "_data")

    def __init__(self, bug: Bug, ignore: Iterable[str] = IGNORE_EXTS) -> None:
        self._bug = bug
        self._data = Path(
            mkdtemp(prefix=f"bug{bug.id}-", dir=grz_tmp("bugzilla"))
        ).resolve()
        self._fetch_attachments(ignore)

    def __enter__(self) -> BugzillaBug:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def _fetch_attachments(
        self, ignore: Iterable[str], require_extension: bool = True
    ) -> None:
        """Download bug attachments.

        Arguments:
            ignore: File extensions to ignore.
            require_extension: Attachment must have a file extension.

        Returns:
            None
        """
        for attachment in self._bug.get_attachments():
            # pylint: disable=too-many-boolean-expressions
            if (
                attachment.is_obsolete
                or attachment.content_type == "text/x-phabricator-request"
                or not attachment.file_name
                or (require_extension and "." not in attachment.file_name)
                or attachment.file_name.split(".")[-1] in ignore
            ):
                continue
            target = (self._data / attachment.file_name).resolve()
            # check file name
            if target.is_dir() or not target.is_relative_to(self._data):
                LOG.debug(
                    "bug %d: skipping attachment %r", self._bug.id, attachment.file_name
                )
                continue
            # decode data
            try:
                data = b64decode(attachment.data or "")
            except binascii.Error as exc:
                LOG.warning(
                    "Failed to decode attachment: %r (%s)", attachment.file_name, exc
                )
                continue
            target.write_bytes(data)

    def _unpack_archives(self) -> None:
        """Unpack and remove archives.

        Arguments:
            None

        Returns:
            None
        """
        for num, entry in enumerate(self._data.iterdir()):
            if entry.suffix.lower() == ".zip" and entry.is_file():
                dst = self._data / f"unpacked_{num:02d}_{entry.stem}"
                LOG.debug("unpacking %s to '%s'", entry, dst)
                with ZipFile(entry) as zip_fp:
                    zip_fp.extractall(path=dst)
                entry.unlink()
            # TODO: add support for other archive types

    def assets(self, ignore: tuple[str] | None = None) -> Generator[tuple[str, Path]]:
        """Scan files for assets.

        Arguments:
            ignore: Assets not to include in output.

        Yields:
            Asset name and path.
        """
        for asset, file in KNOWN_ASSETS.items():
            if not ignore or asset not in ignore:
                asset_path = self._data / file
                if asset_path.is_file():
                    yield asset, asset_path

    def cleanup(self) -> None:
        """Remove attachment data.

        Arguments:
            None

        Returns:
            None
        """
        if self._data.exists():
            rmtree(self._data)

    @classmethod
    def load(cls, bug_id: int) -> BugzillaBug | None:
        """Load bug information from a Bugzilla instance.

        Arguments:
            bug_id: Bug to load.

        Returns:
            BugzillaBug
        """
        api_key = environ.get("BZ_API_KEY")
        # default root matches Bugsy
        api_root = environ.get("BZ_API_ROOT", "https://bugzilla.mozilla.org/rest")
        bugzilla = Bugsy(api_key=api_key, bugzilla_url=api_root)
        try:
            return cls(bugzilla.get(bug_id))
        except BugsyException as exc:
            LOG.error("%s", exc.msg)
            # Access Denied
            if api_key is None and exc.code == 102:
                LOG.warning(
                    "Set BZ_API_KEY in your environment or download the testcase "
                    "manually to run with grizzly.replay."
                )
        except RequestsConnectionError as exc:
            LOG.error("Unable to connect to %r (%s)", bugzilla.bugzilla_url, exc)
        return None

    @property
    def path(self) -> Path:
        """Directory containing downloaded bug attachments.

        Arguments:
            None

        Returns:
            Path to directory.
        """
        return self._data

    def testcases(self) -> list[Path]:
        """Create a list of potential test cases.

        Arguments:
            None

        Returns:
            Files and directories that could potentially be test cases.
        """
        # unpack archives
        self._unpack_archives()
        testcases = [x for x in self._data.iterdir() if x.is_dir()]
        # scan base directory for files, filtering out assets
        files = tuple(
            x
            for x in self._data.iterdir()
            if x.is_file() and x.name.lower() not in KNOWN_ASSETS.values()
        )
        # first, if base directory contains multiple files add it as a single test case
        if len(files) > 1:
            testcases.append(self._data)
        # finally, add each individual file as a potential test case
        testcases.extend(files)
        return testcases
