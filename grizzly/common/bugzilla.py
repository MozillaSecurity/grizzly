# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import binascii
from base64 import b64decode
from logging import getLogger
from os import environ
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp
from zipfile import ZipFile

from bugsy import Bugsy
from bugsy.errors import BugsyException
from requests.exceptions import ConnectionError as RequestsConnectionError

from .utils import grz_tmp

# attachments that can be ignored
IGNORE_EXTS = frozenset({"c", "cpp", "diff", "exe", "log", "patch", "php", "py", "txt"})
# TODO: support all target assets
KNOWN_ASSETS = {"prefs": "prefs.js"}
LOG = getLogger(__name__)


class BugzillaBug:
    __slots__ = ("_bug", "_data")

    def __init__(self, bug):
        self._bug = bug
        self._data = Path(mkdtemp(prefix=f"bug{bug.id}-", dir=grz_tmp("bugzilla")))
        self._fetch_attachments()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def _fetch_attachments(self) -> None:
        """Download bug attachments.

        Arguments:
            None

        Returns:
            None
        """
        for attachment in self._bug.get_attachments():
            if (
                attachment.is_obsolete
                or attachment.content_type == "text/x-phabricator-request"
                or attachment.file_name.split(".")[-1] in IGNORE_EXTS
            ):
                continue
            try:
                data = b64decode(attachment.data)
            except binascii.Error as exc:
                LOG.warning(
                    "Failed to decode attachment: %r (%s)", attachment.file_name, exc
                )
                continue
            (self._data / attachment.file_name).write_bytes(data)

    def _unpack_archives(self):
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

    def assets(self, ignore=None):
        """Scan files for assets.

        Arguments:
            ignore (list(str)): Assets not to include in output.

        Yields:
            tuple(str, Path): Name and path to asset.
        """
        for asset, file in KNOWN_ASSETS.items():
            if not ignore or asset not in ignore:
                asset_path = self._data / file
                if asset_path.is_file():
                    yield asset, asset_path

    def cleanup(self):
        """Remove attachment data.

        Arguments:
            None

        Returns:
            None
        """
        rmtree(self._data)

    @classmethod
    def load(cls, bug_id):
        """Load bug information from a Bugzilla instance.

        Arguments:
            bug_id (int): Bug to load.

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
        except RequestsConnectionError as exc:
            LOG.error("Unable to connect to %r (%s)", bugzilla.bugzilla_url, exc)
        return None

    def testcases(self):
        """Create a list of potential test cases.

        Arguments:
            None

        Returns:
            list(Path): Files and directories that could potentially be test cases.
        """
        # unpack archives
        self._unpack_archives()
        testcases = list(x for x in self._data.iterdir() if x.is_dir())
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
