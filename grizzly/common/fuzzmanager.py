# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Interface for getting Crash and Bucket data from CrashManager API"""
import json
from contextlib import contextmanager
from logging import getLogger
from os import unlink
from pathlib import Path
from shutil import rmtree
from tempfile import mkdtemp, mkstemp

from Collector.Collector import Collector

from .utils import grz_tmp

LOG = getLogger(__name__)


class Bucket:
    """Get Bucket data for a specified CrashManager bucket."""

    def __init__(self, bucket_id):
        """Initialize a Bucket instance.

        Arguments:
            bucket_id (int): ID of the requested bucket on the server side
        """
        assert isinstance(bucket_id, int)
        self._bucket_id = bucket_id
        self._sig_filename = None
        self._coll = Collector()
        self._url = "%s://%s:%d/crashmanager/rest/buckets/%d/" % (
            self._coll.serverProtocol,
            self._coll.serverHost,
            self._coll.serverPort,
            bucket_id,
        )
        self._data = None

    @property
    def bucket_id(self):
        return self._bucket_id

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def __getattr__(self, name):
        if self._data is None:
            self._data = self._coll.get(self._url).json()
        if name not in self._data:
            raise AttributeError(
                "'%s' object has no attribute '%s' (has: %s)"
                % (type(self).__name__, name, list(self._data))
            )
        return self._data[name]

    def __setattr__(self, name, value):
        if name.startswith("_"):
            super().__setattr__(name, value)
            return
        raise AttributeError("can't set attribute")

    def cleanup(self):
        """Cleanup any resources held by this instance.

        Arguments:
            None

        Returns:
            None
        """
        if self._sig_filename is not None:
            rmtree(str(self._sig_filename.parent))

    def iter_crashes(self, quality_filter=None):
        """Fetch all crash IDs for this FuzzManager bucket.
        Only crashes with testcases are returned.

        Arguments:
            quality_filter (int): Filter crashes by quality value (None for all)

        Returns:
            generator: generator of CrashEntry
        """

        def _get_results(endpoint, params=None):
            """
            Function to get paginated results from FuzzManager

            Args:
                endpoint (str): FuzzManager REST API to query (eg. "crashes").
                params (dict): Params to pass through to requests.get

            Returns:
                generator: objects returned by FuzzManager (as dicts)
            """
            LOG.debug("first request to /%s/", endpoint)

            url = "%s://%s:%d/crashmanager/rest/%s/" % (
                self._coll.serverProtocol,
                self._coll.serverHost,
                self._coll.serverPort,
                endpoint,
            )

            response = self._coll.get(url, params=params).json()

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
            result = CrashEntry(crash["id"])
            result._data = crash  # pylint: disable=protected-access
            yield result

    def signature_path(self):
        """Download the bucket data from CrashManager.

        Arguments:
            None

        Returns:
            Path: Path on disk where signature exists.
        """
        if self._sig_filename is not None:
            return self._sig_filename

        tmpd = Path(
            mkdtemp(
                prefix="bucket-%d-" % (self._bucket_id,), dir=grz_tmp("fuzzmanager")
            )
        )
        try:
            sig_basename = "%d.signature" % (self._bucket_id,)
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
        except:  # noqa pragma: no cover pylint: disable=bare-except
            rmtree(str(tmpd))
            raise

        self._sig_filename = sig_filename
        return self._sig_filename


class CrashEntry:
    """Get the CrashEntry data for the specified CrashManager crash.

    Attributes:
        crash_id (int): the server ID for the crash
        see crashmanager.serializers.CrashEntrySerializer
    """

    RAW_FIELDS = frozenset({"rawCrashData", "rawStderr", "rawStdout"})

    def __init__(self, crash_id):
        """Initialize CrashEntry.

        Arguments:
            crash_id (int): ID of the requested crash on the server side
        """
        assert isinstance(crash_id, int)
        self._crash_id = crash_id
        self._coll = Collector()
        self._url = "%s://%s:%d/crashmanager/rest/crashes/%d/" % (
            self._coll.serverProtocol,
            self._coll.serverHost,
            self._coll.serverPort,
            crash_id,
        )
        self._data = None
        self._tc_filename = None

    @property
    def crash_id(self):
        return self._crash_id

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()

    def __getattr__(self, name):
        if self._data is None or (name in self.RAW_FIELDS and name not in self._data):
            need_raw = "1" if name in self.RAW_FIELDS else "0"
            # TODO: handle 403 and 404?
            self._data = self._coll.get(
                self._url, params={"include_raw": need_raw}
            ).json()
        if name not in self._data:
            raise AttributeError(
                "'%s' object has no attribute '%s' (has: %s)"
                % (type(self).__name__, name, list(self._data))
            )
        return self._data[name]

    def __setattr__(self, name, value):
        if name.startswith("_"):
            super().__setattr__(name, value)
            return
        if name != "testcase_quality":
            raise AttributeError("can't set attribute")
        self._coll.patch(self._url, data={name: value})
        if self._data:
            self._data[name] = value

    def cleanup(self):
        """Cleanup any resources held by this instance.

        Arguments:
            None

        Returns:
            None
        """
        if self._tc_filename is not None:
            self._tc_filename.unlink()

    def testcase_path(self):
        """Download the testcase data from CrashManager.

        Arguments:
            None

        Returns:
            Path: Path on disk where testcase exists_
        """
        if self._tc_filename is not None:
            return self._tc_filename

        dlurl = self._url + "download/"
        response = self._coll.get(dlurl)

        if "content-disposition" not in response.headers:
            raise RuntimeError(
                "Server sent malformed response: %r" % (response,)
            )  # pragma: no cover

        handle, filename = mkstemp(
            dir=grz_tmp("fuzzmanager"),
            prefix="crash-%d-" % (self.crash_id,),
            suffix=Path(self.testcase).suffix,
        )
        try:
            with open(handle, "wb") as output:
                output.write(response.content)
        except:  # noqa pragma: no cover pylint: disable=bare-except
            unlink(filename)
            raise
        self._tc_filename = Path(filename)
        return self._tc_filename


@contextmanager
def load_fm_data(crash_id, load_bucket=False):
    """Load CrashEntry including Bucket from FuzzManager.

    Arguments:
        crash_id (int): Crash ID to load.
        load_bucket (bool): Attempt to load bucket.

    Yields:
        2-tuple(CrashEntry, Bucket): Data loaded from FuzzManager.
    """
    with CrashEntry(crash_id) as crash:
        # load signature if needed
        if load_bucket and crash.bucket:
            with Bucket(crash.bucket) as bucket:
                yield crash, bucket
        else:
            yield crash, None
