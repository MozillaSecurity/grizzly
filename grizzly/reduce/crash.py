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

from .reduce import main as reduce_main
from .args import ReducerFuzzManagerIDArgs
from ..reporter import FuzzManagerReporter


log = logging.getLogger("grizzly.reduce.crash")


def download_crash(crash_id):
    """Download testcase for the specified FuzzManager crash.

    Args:
        crash_id (int): ID of the requested crash on the server side

    Returns:
        str: Temporary filename of the testcase. Caller must remove when finished.
    """
    coll = Collector()

    log.debug("crash %d, downloading testcase...", crash_id)

    url = "%s://%s:%d/crashmanager/rest/crashes/%s/download/" \
        % (coll.serverProtocol, coll.serverHost, coll.serverPort, crash_id)

    response = coll.get(url)

    disp_m = re.match(r'^attachment; filename="(.*)"$',
                      response.headers.get("content-disposition", ""))

    if disp_m is None:
        raise RuntimeError("Server sent malformed response: %r" % (response,))

    testcase_fd, testcase_fn = tempfile.mkstemp(suffix=os.path.splitext(disp_m.group(1))[1])
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
    log.info("Updating crash %d to quality %s", crash_id, FuzzManagerReporter.quality_name(quality))
    coll = Collector()

    url = "%s://%s:%d/crashmanager/rest/crashes/%d/" \
        % (coll.serverProtocol, coll.serverHost, coll.serverPort, crash_id)
    try:
        Collector().patch(url, data={"testcase_quality": quality})
    except RuntimeError as exc:
        # let 404's go .. evidently the crash was deleted
        if str(exc) == "Unexpected HTTP response: 404":
            log.warning("Failed to update (404), does the crash still exist?")
        else:
            raise


def main(args):
    log.info("Trying crash %d", args.input)

    crash_id = args.input
    testcase = download_crash(crash_id)
    fm_reporter = args.fuzzmanager or args.s3_fuzzmanager

    try:
        # reduce.main expects input to be a path to testcase
        args.input = testcase

        def _on_result(result):
            # only update quality of the original crash if we are reporting to FuzzManager
            if not fm_reporter:
                return

            # reduce succeeded, mark original crash as reduced
            if result == FuzzManagerReporter.QUAL_REDUCED_RESULT:
                change_quality(crash_id, FuzzManagerReporter.QUAL_REDUCED_ORIGINAL)

            # not reproducible, mark it as such
            elif result == FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE:
                change_quality(crash_id, result)

            # for these cases, something went wrong. a reduce log/result would be really valuable
            elif result in {FuzzManagerReporter.QUAL_REDUCER_BROKE,
                            FuzzManagerReporter.QUAL_REDUCER_ERROR}:
                # for now just change the quality
                change_quality(crash_id, result)

            else:
                log.error("Got unhandled quality: %s", FuzzManagerReporter.quality_name(result))

        _was_interesting = [False]

        def _on_interesting():
            if _was_interesting[0]:
                return
            if fm_reporter:
                change_quality(crash_id, FuzzManagerReporter.QUAL_REPRODUCIBLE)
            _was_interesting[0] = True

        return reduce_main(args, interesting_cb=_on_interesting, result_cb=_on_result)

    finally:
        os.unlink(testcase)


if __name__ == "__main__":
    log_level = logging.INFO
    log_fmt = "[%(asctime)s] %(message)s"
    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    sys.exit(main(ReducerFuzzManagerIDArgs().parse_args()))
