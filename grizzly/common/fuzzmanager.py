# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Interface for getting Crash and Bucket data from CrashManager API"""
from __future__ import annotations

import json
from contextlib import contextmanager
from logging import getLogger
from pathlib import Path
from re import search
from shutil import copyfileobj, rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from typing import Any, Dict, Generator, cast
from zipfile import BadZipFile, ZipFile

from Collector.Collector import Collector
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo

from .reporter import Quality
from .storage import TEST_INFO
from .utils import grz_tmp

FM_CONFIG = Path.home() / ".fuzzmanagerconf"
LOG = getLogger(__name__)


class CrashEntry:
    """Get the CrashEntry data for the specified CrashManager crash.

    Attributes:
        crash_id: the server ID for the crash
        see crashmanager.serializers.CrashEntrySerializer
    """

    RAW_FIELDS = frozenset({"rawCrashData", "rawStderr", "rawStdout"})

    __slots__ = (
        "_crash_id",
        "_coll",
        "_contents",
        "_data",
        "_storage",
        "_sig_filename",
        "_url",
    )

    def __init__(self, crash_id: int) -> None:
        """Initialize CrashEntry.

        Arguments:
            crash_id: ID of the requested crash on the server side
        """
        assert isinstance(crash_id, int)
        self._crash_id = crash_id
        self._coll = Collector()
        self._contents: list[Path] | None = None
        self._data: dict[str, Any] | None = None
        self._storage: Path | None = None
        self._sig_filename: Path | None = None
        self._url = (
            f"{self._coll.serverProtocol}://{self._coll.serverHost}:"
            f"{self._coll.serverPort}/crashmanager/rest/crashes/{crash_id}/"
        )

    @property
    def crash_id(self) -> int:
        return self._crash_id

    def __enter__(self) -> CrashEntry:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def __getattr__(self, name: str) -> Any:
        if self._data is None or (name in self.RAW_FIELDS and name not in self._data):
            need_raw = "1" if name in self.RAW_FIELDS else "0"
            # TODO: handle 403 and 404?
            self._data = cast(
                Dict[str, Any],
                self._coll.get(self._url, params={"include_raw": need_raw}).json(),
            )
        if name not in self._data:
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{name}' "
                f"(has: {list(self._data)})"
            )
        return self._data[name]

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            super().__setattr__(name, value)
            return
        if name != "testcase_quality":
            raise AttributeError("can't set attribute")
        self._coll.patch(self._url, data={name: value})
        if self._data:
            self._data[name] = value

    def cleanup(self) -> None:
        """Cleanup any resources held by this instance.

        Arguments:
            None

        Returns:
            None
        """
        if self._storage is not None:
            rmtree(self._storage, ignore_errors=True)
        if self._sig_filename is not None:
            rmtree(self._sig_filename.parent)

    @staticmethod
    def _subset(tests: list[Path], subset: list[int]) -> list[Path]:
        """Select a subset of tests directories. Subset values are sanitized to
        avoid raising.

        Arguments:
            tests: Directories on disk where testcases exists.
            subset: Indices of corresponding directories to select.

        Returns:
            Directories that have been selected.
        """
        assert isinstance(subset, list)
        assert tests
        count = len(tests)
        # deduplicate and limit requested indices to valid range
        keep = {max(count + x, 0) if x < 0 else min(x, count - 1) for x in subset}
        LOG.debug("using TestCase(s) with index %r", keep)
        # build list of items to preserve
        return [tests[i] for i in sorted(keep)]

    def testcases(
        self, subset: list[int] | None = None, ext: str | None = None
    ) -> list[Path]:
        """Download the testcase data from CrashManager.

        Arguments:
            subset: Indices of corresponding directories to select.
            ext: Overwrite file extension used with downloaded testcase.

        Returns:
            Directories on disk where testcases exists.
        """
        if self._contents is None:
            assert self._storage is None
            response = self._coll.get(f"{self._url}download/")

            if "content-disposition" not in response.headers:
                raise RuntimeError(
                    f"Server sent malformed response: {response!r}"
                )  # pragma: no cover

            with NamedTemporaryFile(
                dir=grz_tmp("fuzzmanager"),
                prefix=f"crash-{self.crash_id}-",
                suffix=Path(self.testcase).suffix,
            ) as data:
                data.write(response.content)
                data.seek(0)
                # self._storage should be removed when self.cleanup() is called
                self._storage = Path(
                    mkdtemp(
                        prefix=f"crash-{self.crash_id}-", dir=grz_tmp("fuzzmanager")
                    )
                )
                try:
                    with ZipFile(data) as zip_fp:
                        zip_fp.extractall(path=self._storage)
                    # test case directories are named sequentially
                    # an archive with three test directories would have:
                    # - 'foo-2' (oldest)
                    # - 'foo-1'
                    # - 'foo-0' (most recent)
                    # see FuzzManagerReporter for more info
                    self._contents = sorted(
                        (x.parent for x in self._storage.rglob(TEST_INFO)),
                        reverse=True,
                    )
                except BadZipFile as exc:
                    LOG.debug("downloaded data is not a valid zip")
                    if ext is None:
                        match = search(
                            r'filename="(?P<name>.+)"',
                            response.headers["content-disposition"],
                        )
                        if match:
                            # if nothing is found fallback to html
                            file_name = match.group("name")
                            if "." in file_name:
                                ext = file_name.split(".")[-1] or "html"
                            else:
                                ext = "html"
                    assert ext is not None
                    if ext.lower().endswith("zip"):
                        LOG.error("Error loading test case: %s", exc)
                        self._contents = []
                    else:
                        # load raw test case
                        test_file = self._storage / f"test.{ext}"
                        data.seek(0)
                        with test_file.open("wb") as dst:
                            copyfileobj(data, dst)
                        self._contents = [test_file]

        if subset and self._contents:
            return self._subset(self._contents, subset)
        return self._contents

    def create_signature(self, binary: Path) -> Path:
        """Create a CrashManager signature from this crash.
        If self.bucket is set, self.bucket.signature_path() should be used instead.

        Arguments:
            binary: binary location, needed to create a program configuration

        Returns:
            Signature file.
        """
        if self._sig_filename is not None:
            return self._sig_filename

        success = False
        tmpd = Path(
            mkdtemp(prefix=f"crash-sig-{self._crash_id}-", dir=grz_tmp("fuzzmanager"))
        )
        try:
            sig_basename = f"{self._crash_id}.signature"
            sig_filename = tmpd / sig_basename

            cfg = ProgramConfiguration.fromBinary(binary)
            fm_crash = CrashInfo.fromRawCrashData(
                self.rawStdout, self.rawStderr, cfg, auxCrashData=self.rawCrashData
            )
            fm_sig = fm_crash.createCrashSignature()
            if fm_sig is None:
                raise RuntimeError(str(fm_crash.failureReason))
            sig_filename.write_text(fm_sig.rawSignature)

            sigmeta_filename = sig_filename.with_suffix(".metadata")
            sigmeta_filename.write_text(
                json.dumps(
                    {
                        "size": 1,
                        "frequent": False,
                        "shortDescription": fm_crash.createShortSignature(),
                        "testcase__quality": Quality.UNREDUCED,
                    }
                )
            )
            success = True
        finally:  # pragma: no cover
            if not success:
                rmtree(tmpd)

        self._sig_filename = sig_filename
        return self._sig_filename


class Bucket:
    """Get Bucket data for a specified CrashManager bucket."""

    def __init__(self, bucket_id: int) -> None:
        """Initialize a Bucket instance.

        Arguments:
            bucket_id: ID of the requested bucket on the server.
        """
        assert isinstance(bucket_id, int)
        self._bucket_id = bucket_id
        self._sig_filename: Path | None = None
        self._coll = Collector()
        self._url = (
            f"{self._coll.serverProtocol}://{self._coll.serverHost}:"
            f"{self._coll.serverPort}/crashmanager/rest/buckets/{bucket_id}/"
        )
        self._data: dict[str, Any] | None = None

    @property
    def bucket_id(self) -> int:
        return self._bucket_id

    def __enter__(self) -> Bucket:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def __getattr__(self, name: str) -> Any:
        if self._data is None:
            self._data = self._coll.get(self._url).json()
        if name not in self._data:
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{name}'"
                f" (has: {list(self._data)})"
            )
        return self._data[name]

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            super().__setattr__(name, value)
            return
        raise AttributeError("can't set attribute")

    def cleanup(self) -> None:
        """Cleanup any resources held by this instance.

        Arguments:
            None

        Returns:
            None
        """
        if self._sig_filename is not None:
            rmtree(self._sig_filename.parent)

    def iter_crashes(
        self, quality_filter: int | None = None
    ) -> Generator[CrashEntry, None, None]:
        """Fetch all crash IDs for this FuzzManager bucket.
        Only crashes with testcases are returned.

        Arguments:
            quality_filter: Filter crashes by quality value (None for all)

        Yields:
            CrashEntry objects.
        """

        def _get_results(
            endpoint: str, params: dict[str, str] | None = None
        ) -> Generator[dict[str, Any], None, None]:
            """
            Function to get paginated results from FuzzManager

            Args:
                endpoint: FuzzManager REST API to query (eg. "crashes").
                params: Params to pass through to requests.get.

            Returns:
                Objects (dict) returned by FuzzManager.
            """
            LOG.debug("first request to /%s/", endpoint)

            url = (
                f"{self._coll.serverProtocol}://{self._coll.serverHost}:"
                f"{self._coll.serverPort}/crashmanager/rest/{endpoint}/"
            )

            response: dict[str, Any] = self._coll.get(url, params=params).json()

            while True:
                LOG.debug(
                    "got %d/%d %s",
                    len(response["results"]),
                    response["count"],
                    endpoint,
                )
                while response["results"]:
                    yield response["results"].pop()

                if response["next"] is None:
                    break

                LOG.debug("next request to /%s/", endpoint)
                response = self._coll.get(response["next"]).json()

        # Get all crashes for bucket
        query_args = [
            ("op", "AND"),
            ("bucket", self.bucket_id),
        ]
        if quality_filter is not None:
            query_args.append(("testcase__quality", quality_filter))
        query = json.dumps(dict(query_args))

        n_yielded = 0
        for crash in _get_results(
            "crashes", params={"query": query, "include_raw": "0"}
        ):
            if not crash["testcase"]:
                LOG.warning("crash %d has no testcase, skipping", crash["id"])
                continue

            n_yielded += 1
            LOG.debug("yielding crash #%d", n_yielded)
            result = CrashEntry(cast(int, crash["id"]))
            result._data = crash  # pylint: disable=protected-access
            yield result

    def signature_path(self) -> Path:
        """Download the bucket data from CrashManager.

        Arguments:
            None

        Returns:
            Signature file.
        """
        if self._sig_filename is not None:
            return self._sig_filename

        success = False
        tmpd = Path(
            mkdtemp(prefix=f"bucket-{self._bucket_id}-", dir=grz_tmp("fuzzmanager"))
        )
        try:
            sig_basename = f"{self._bucket_id}.signature"
            sig_filename = tmpd / sig_basename
            sig_filename.write_text(self.signature)
            sigmeta_filename = sig_filename.with_suffix(".metadata")
            sigmeta_filename.write_text(
                json.dumps(
                    {
                        "size": self.size,
                        "frequent": self.frequent,
                        "shortDescription": self.shortDescription,
                        "testcase__quality": self.best_quality,
                    }
                )
            )
            success = True
        finally:  # pragma: no cover
            if not success:
                rmtree(tmpd)

        self._sig_filename = sig_filename
        return self._sig_filename


@contextmanager
def load_fm_data(
    crash_id: int, load_bucket: bool = False
) -> Generator[tuple[CrashEntry, Bucket | None], None, None]:
    """Load CrashEntry including Bucket from FuzzManager.

    Arguments:
        crash_id: Crash ID to load.
        load_bucket: Attempt to load bucket.

    Yields:
        Data loaded from FuzzManager.
    """
    with CrashEntry(crash_id) as crash:
        # load signature if needed
        if load_bucket and crash.bucket:
            with Bucket(crash.bucket) as bucket:
                yield crash, bucket
        else:
            yield crash, None
