# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import collections
import json
import logging
import os
import sys
import tempfile

from Collector.Collector import Collector

from .args import ReducerFuzzManagerIDQualityArgs
from .crash import main as reduce_crash
from ..main import console_init_logging


LOG = logging.getLogger("grizzly.reduce.bucket")


def bucket_crashes(bucket_id, quality_filter):
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
    query = json.dumps(collections.OrderedDict(query_args))

    n_yielded = 0
    for crash in _get_results("crashes", params={"query": query, "include_raw": "0"}):

        if not crash["testcase"]:
            LOG.warning("crash %d has no testcase, skipping", crash["id"])
            continue

        n_yielded += 1
        LOG.debug("yielding crash #%d", n_yielded)
        yield crash["id"]


def get_signature(bucket_id):
    """
    Download the signature for the specified FuzzManager bucket.

    Args:
        bucket_id (int): ID of the requested bucket on the server side

    Returns:
        str: temp filename to the JSON signature. caller must remove filename when done
    """
    coll = Collector()

    url = "%s://%s:%d/crashmanager/rest/buckets/%d/" \
        % (coll.serverProtocol, coll.serverHost, coll.serverPort, bucket_id)

    response = coll.get(url).json()

    sig_fd, sig_fn = tempfile.mkstemp(suffix=".json")
    with os.fdopen(sig_fd, "w") as sig_fp:
        sig_fp.write(response["signature"])

    return sig_fn


def main(args):
    LOG.info("Trying all crashes in bucket %d until one reduces", args.input)

    # if no signature specified, download the signature from FM
    rm_sig = False
    if not args.sig:
        args.sig = get_signature(args.input)
        rm_sig = True

    try:
        for crash_id in bucket_crashes(args.input, args.quality):

            # reduce.main expects input to be a crash ID
            args.input = crash_id

            if reduce_crash(args) == 0:
                # success!
                return 0

        # none of the testcases reduced
        return 1

    finally:
        if rm_sig:
            os.unlink(args.sig)


if __name__ == "__main__":
    console_init_logging()
    sys.exit(main(ReducerFuzzManagerIDQualityArgs().parse_args()))
