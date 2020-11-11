# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import json
from logging import getLogger
from os import unlink
from pathlib import Path
from shutil import rmtree
import sys
from tempfile import mkdtemp, mkstemp

from Collector.Collector import Collector

from .args import ReduceFuzzManagerIDArgs
from .core import ReduceManager
from ..common.reporter import FuzzManagerReporter
from ..main import configure_logging
from ..session import Session


LOG = getLogger(__name__)


class CrashEntry(object):
    """Get the CrashEntry data for the specified CrashManager crash.

    Attributes:
        see crashmanager.serializers.CrashEntrySerializer
    """

    def __init__(self, crash_id):
        """Initialize CrashEntry.

        Arguments:
            crash_id (int): ID of the requested crash on the server side
        """
        self._coll = Collector()
        self._url = "%s://%s:%d/crashmanager/rest/crashes/%d/" % (
            self._coll.serverProtocol,
            self._coll.serverHost,
            self._coll.serverPort,
            crash_id,
        )
        self._data = None
        self._tc_filename = None
        self._sig_filename = None

    @classmethod
    def iter_bucket(cls, bucket_id, quality_filter=None):
        """Fetch all crash IDs for the specified FuzzManager bucket.
        Only crashes with testcases are returned.

        Args:
            bucket_id (int): ID of the requested bucket on the server side
            quality_filter (int): Filter crashes by quality value (None for all)

        Returns:
            generator: generator of crash ID (int)
        """
        coll = Collector()

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

            url = "%s://%s:%d/crashmanager/rest/%s/" \
                % (coll.serverProtocol, coll.serverHost, coll.serverPort, endpoint)

            response = coll.get(url, params=params).json()

            while True:
                LOG.debug("got %d/%d %s", len(response["results"]), response["count"], endpoint)
                while response["results"]:
                    yield response["results"].pop()

                if response["next"] is None:
                    break

                LOG.debug("next request to /%s/", endpoint)
                response = coll.get(response["next"]).json()

        # Get all crashes for bucket
        query_args = [
            ("op", "AND"),
            ("bucket", bucket_id),
        ]
        if quality_filter is not None:
            query_args.append(("testcase__quality", quality_filter))
        query = json.dumps(dict(query_args))

        n_yielded = 0
        for crash in _get_results("crashes", params={"query": query, "include_raw": "0"}):

            if not crash["testcase"]:
                LOG.warning("crash %d has no testcase, skipping", crash["id"])
                continue

            n_yielded += 1
            LOG.debug("yielding crash #%d", n_yielded)
            result = cls(crash["id"])
            result._data = crash  # pylint: disable=protected-access
            yield result

    def __getattr__(self, name):
        if self._data is None:
            self._data = self._coll.get(self._url, params={"include_raw": "0"}).json()
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
        if self._sig_filename is not None:
            rmtree(str(self._sig_filename.parent))

    def testcase_path(self):
        """Download the testcase data from CrashManager.

        Arguments:
            None

        Returns:
            Path: Path on disk where testcase exists.
        """
        if self._tc_filename is not None:
            return self._tc_filename

        dlurl = self._url + "download/"
        response = self._coll.get(dlurl)

        if "content-disposition" not in response.headers:
            raise RuntimeError("Server sent malformed response: %r" % (response,))

        handle, filename = mkstemp(
            prefix="grizzly-reduce-%d-" % (self.id,), suffix=Path(self.testcase).suffix
        )
        try:
            with open(handle, "wb") as output:
                output.write(response.content)
        except:  # noqa pylint: disable=bare-except
            unlink(filename)
            raise
        self._tc_filename = Path(filename)
        return self._tc_filename

    def bucket_path(self):
        """Download the bucket data from CrashManager.

        Arguments:
            None

        Returns:
            Path: Path on disk where signature exists.
        """
        if self._sig_filename is not None:
            return self._sig_filename

        if self.bucket is None:
            return None

        bucket_url = "%s://%s:%d/crashmanager/rest/buckets/%d/" % (
            self._coll.serverProtocol,
            self._coll.serverHost,
            self._coll.serverPort,
            self.bucket,
        )
        bucket_data = self._coll.get(bucket_url).json()

        tmpd = Path(mkdtemp(prefix="grizzly-reduce-"))
        try:
            sig_basename = "%d.signature" % (self.bucket,)
            sig_filename = tmpd / sig_basename
            sig_filename.write_text(bucket_data["signature"])
            sigmeta_filename = sig_filename.with_suffix(".metadata")
            sigmeta_filename.write_text(
                json.dumps(
                    {
                        "size": bucket_data["size"],
                        "frequent": bucket_data["frequent"],
                        "shortDescription": bucket_data["shortDescription"],
                        "testcase__quality": bucket_data["best_quality"],
                    }
                )
            )
        except:  # noqa pylint: disable=bare-except
            rmtree(str(tmpd))
            raise

        self._sig_filename = sig_filename
        return self._sig_filename


def main(args):
    """CLI for `grizzly.reduce.crash`.

    Arguments:
        args (argparse.Namespace): Result from `ReduceArgs.parse_args`.

    Returns:
        int: 0 for success. non-0 indicates a problem.
    """
    configure_logging(args.log_level)
    crash = CrashEntry(args.input)
    try:
        # download the crash
        args.input = str(crash.testcase_path())
        if args.sig is None and crash.bucket_path() is not None:
            args.sig = str(crash.bucket_path())
        if args.tool is None:
            args.tool = crash.tool

        # call grizzly.reduce
        result = ReduceManager.main(args)

        # update quality
        # map Session.EXIT_* -> FuzzManagerReporter.QUAL_*
        # default back to UNREDUCED
        # most errors will not be related to the testcase
        # so they should be retried later
        quality = {
            Session.EXIT_SUCCESS: FuzzManagerReporter.QUAL_REDUCED_RESULT,
            Session.EXIT_FAILURE: FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE,
        }.get(
            result, FuzzManagerReporter.QUAL_UNREDUCED
        )
        LOG.info(
            "reducer finished -> exit(%d) -> Q%d",
            result,
            quality,
        )
        crash.testcase_quality = quality
    finally:
        crash.cleanup()
    return result


if __name__ == "__main__":
    sys.exit(main(ReduceFuzzManagerIDArgs().parse_args()))
