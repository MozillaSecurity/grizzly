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

from .reduce import main as reduce_main
from .args import BucketReducerArgs


log = logging.getLogger("grizzly.reduce.bucket")


def download_all(bucket_id):
    """
    Download all testcases for the specified FuzzManager bucket.

    Args:
        bucket_id (int): ID of the requested bucket on the server side

    Returns:
        generator: generator of (crash_id, temp_filename) tuples
                   caller must remove temp_filename
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
        log.debug("first request to /%s/", endpoint)

        url = "%s://%s:%d/crashmanager/rest/%s/" \
            % (coll.serverProtocol, coll.serverHost, coll.serverPort, endpoint)

        response = coll.get(url, params=params).json()

        while True:
            log.debug("got %d/%d %s", len(response["results"]), response["count"], endpoint)
            while response["results"]:
                yield response["results"].pop()

            if response["next"] is None:
                break

            log.debug("next request to /%s/", endpoint)
            response = coll.get(response["next"]).json()

    # Get all crashes for bucket
    query = json.dumps(collections.OrderedDict((
        ("op", "OR"),
        ("bucket", bucket_id)
    )))

    n_yielded = 0
    for crash in _get_results("crashes", params={"query": query, "include_raw": "0"}):

        if not crash["testcase"]:
            log.warning("crash %d has no testcase, skipping", crash["id"])
            continue

        log.debug("crash %d, downloading testcase...", crash["id"])

        url = "%s://%s:%d/crashmanager/rest/crashes/%s/download/" \
            % (coll.serverProtocol, coll.serverHost, coll.serverPort, crash["id"])

        response = coll.get(url)

        if 'content-disposition' not in response.headers:
            raise RuntimeError("Server sent malformed response: %r" % (response,))

        testcase_fd, testcase_fn = tempfile.mkstemp(suffix=os.path.splitext(crash["testcase"])[1])
        with os.fdopen(testcase_fd, "wb") as testcase_fp:
            testcase_fp.write(response.content)

        n_yielded += 1
        log.debug("yielding crash #%d", n_yielded)
        yield (crash["id"], testcase_fn)


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
    log.info("Trying all crashes in bucket %d until one reduces", args.input)

    # if no signature specified, download the signature from FM
    rm_sig = False
    if not args.sig:
        args.sig = get_signature(args.input)
        rm_sig = True

    try:
        for crash_id, testcase in download_all(args.input):
            try:
                # reduce.main expects input to be a path to testcase
                args.input = testcase

                if reduce_main(args) == 0:
                    # success!
                    return 0

            finally:
                os.unlink(testcase)

        # none of the testcases reduced
        return 1

    finally:
        if rm_sig:
            os.unlink(args.sig)


if __name__ == "__main__":
    log_level = logging.INFO
    log_fmt = "[%(asctime)s] %(message)s"
    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    sys.exit(main(BucketReducerArgs().parse_args()))
