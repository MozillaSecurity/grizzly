# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import logging
import os
import re
import sys
import tempfile

from Collector.Collector import Collector

from .args import ReducerFuzzManagerIDArgs
from .reduce import main as reduce_main
from ..main import console_init_logging
from ..common import FuzzManagerReporter


LOG = logging.getLogger("grizzly.reduce.crash")


def crashentry_data(crash_id, raw=False):
    """Get the CrashEntry data for the specified FuzzManager crash

    Args:
        crash_id (int): ID of the requested crash on the server side
        raw (bool): include rawCrashData, rawStderr, rawStdout in result

    Returns:
        dict: crash entry data (crashmanager.models.CrashEntry)
    """
    coll = Collector()

    LOG.debug("crash %d, downloading metadata...", crash_id)

    url = "%s://%s:%d/crashmanager/rest/crashes/%s/" \
        % (coll.serverProtocol, coll.serverHost, coll.serverPort, crash_id)

    return coll.get(url, params={"include_raw": "1" if raw else "0"}).json()


def download_crash(crash_id):
    """Download testcase for the specified FuzzManager crash.

    Args:
        crash_id (int): ID of the requested crash on the server side

    Returns:
        str: Temporary filename of the testcase. Caller must remove when finished.
    """
    coll = Collector()

    LOG.debug("crash %d, downloading testcase...", crash_id)

    url = "%s://%s:%d/crashmanager/rest/crashes/%s/download/" \
        % (coll.serverProtocol, coll.serverHost, coll.serverPort, crash_id)

    response = coll.get(url)

    disp_m = re.match(r'^attachment; filename="(.*)"$',
                      response.headers.get("content-disposition", ""))

    if disp_m is None:
        raise RuntimeError("Server sent malformed response: %r" % (response,))

    prefix = "crash.%d." % (crash_id,)
    suffix = os.path.splitext(disp_m.group(1))[1]
    testcase_fd, testcase_fn = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    with os.fdopen(testcase_fd, "wb") as testcase_fp:
        testcase_fp.write(response.content)

    return testcase_fn


def change_quality(crash_id, quality):
    """Update a FuzzManager crash entry quality.

    Args:
        crash_id (int): Crash ID on FuzzManager server
        quality (int): Quality constant defined in FuzzManagerReporter.QUAL_*

    Returns:
        None
    """
    LOG.info("Updating crash %d to quality %s", crash_id, FuzzManagerReporter.quality_name(quality))
    coll = Collector()

    url = "%s://%s:%d/crashmanager/rest/crashes/%d/" \
        % (coll.serverProtocol, coll.serverHost, coll.serverPort, crash_id)
    try:
        Collector().patch(url, data={"testcase_quality": quality})
    except RuntimeError as exc:
        # let 404's go .. evidently the crash was deleted
        if str(exc) == "Unexpected HTTP response: 404":
            LOG.warning("Failed to update (404), does the crash still exist?")
        else:
            raise


def main(args):
    LOG.info("Trying crash %d", args.input)

    crash_id = args.input
    testcase = download_crash(crash_id)
    tool_override = args.tool is None
    crash = crashentry_data(crash_id)
    quality = crash["testcase_quality"]
    if tool_override:
        args.tool = crash["tool"]
        LOG.info("Using toolname from crash: %s", args.tool)
    fm_reporter = args.fuzzmanager

    try:
        # reduce.main expects input to be a path to testcase
        args.input = testcase

        def _on_result(result):
            # only update quality of the original crash if we are reporting to FuzzManager
            if not fm_reporter:
                return

            if result == FuzzManagerReporter.QUAL_REDUCED_ORIGINAL:
                # reduce succeeded
                change_quality(crash_id, result)

            elif result == FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE:
                if quality == FuzzManagerReporter.QUAL_UNREDUCED:
                    # override result to request platform specific reduction
                    result = FuzzManagerReporter.QUAL_REQUEST_SPECIFIC
                change_quality(crash_id, result)

            # for these cases, something went wrong. a reduce log/result would be really valuable
            elif result in {FuzzManagerReporter.QUAL_REDUCER_BROKE,
                            FuzzManagerReporter.QUAL_REDUCER_ERROR}:
                # for now just change the quality
                change_quality(crash_id, result)

            else:
                LOG.error("Got unhandled quality: %s", FuzzManagerReporter.quality_name(result))

        _was_interesting = [False]

        def _on_interesting():
            if _was_interesting[0]:
                return
            LOG.info("Crash %d reproduced!", crash_id)
            if fm_reporter:
                change_quality(crash_id, FuzzManagerReporter.QUAL_REPRODUCIBLE)
            _was_interesting[0] = True

        return reduce_main(args, interesting_cb=_on_interesting, result_cb=_on_result)

    finally:
        os.unlink(testcase)
        if tool_override:
            args.tool = None


if __name__ == "__main__":
    console_init_logging()
    sys.exit(main(ReducerFuzzManagerIDArgs().parse_args()))
