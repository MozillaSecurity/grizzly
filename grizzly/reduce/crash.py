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
from .reduce import ReductionJob
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


class CrashReductionJob(ReductionJob):
    __slots__ = ['_crash_id', '_fm_reporter', '_quality', '_testcase_path', '_tool_override',
                 '_was_interesting']

    def __init__(self, *args, **kwds):
        super(CrashReductionJob, self).__init__(*args, **kwds)
        self._crash_id = None
        self._fm_reporter = False
        self._quality = None
        self._testcase_path = None
        self._tool_override = False
        self._was_interesting = False

    def on_result(self, result_code):
        # only update quality of the original crash if we are reporting to FuzzManager
        if not self._fm_reporter:
            return

        if result_code == FuzzManagerReporter.QUAL_REDUCED_ORIGINAL:
            # reduce succeeded
            change_quality(self._crash_id, result_code)

        elif result_code == FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE:
            if self._quality == FuzzManagerReporter.QUAL_UNREDUCED:
                # override result to request platform specific reduction
                result_code = FuzzManagerReporter.QUAL_REQUEST_SPECIFIC
            change_quality(self._crash_id, result_code)

        # for these cases, something went wrong. a reduce log/result would be really valuable
        elif result_code in {FuzzManagerReporter.QUAL_REDUCER_BROKE,
                             FuzzManagerReporter.QUAL_REDUCER_ERROR}:
            # for now just change the quality
            change_quality(self._crash_id, result_code)

        else:
            LOG.error("Got unhandled quality: %s", FuzzManagerReporter.quality_name(result_code))

    def on_interesting_crash(self, *args, **kwds):
        super(CrashReductionJob, self).on_interesting_crash(*args, **kwds)
        if self._was_interesting:
            return
        LOG.info("Crash %d reproduced!", self._crash_id)
        if self._fm_reporter:
            change_quality(self._crash_id, FuzzManagerReporter.QUAL_REPRODUCIBLE)
        self._was_interesting = True

    def run(self, *args, **kwds):
        try:
            return super(CrashReductionJob, self).run(*args, **kwds)
        finally:
            os.unlink(self._testcase_path)

    @classmethod
    def from_args(cls, args, target, status):
        LOG.info("Trying crash %d", args.input)

        try:
            crash_id = args.input
            testcase = download_crash(crash_id)
            tool_override = args.tool is None
            crash = crashentry_data(crash_id)
            quality = crash["testcase_quality"]
            if tool_override:
                args.tool = crash["tool"]
                LOG.info("Using toolname from crash: %s", args.tool)

            # reduce.main expects input to be a path to testcase
            args.input = testcase

            job = super(CrashReductionJob, cls).from_args(args, target, status)
            job._fm_reporter = args.fuzzmanager
            job._crash_id = crash_id
            job._tool_override = tool_override
            job._quality = quality
            job._testcase_path = testcase
            return job

        except:  # noqa
            os.unlink(testcase)
            raise


if __name__ == "__main__":
    sys.exit(CrashReductionJob.main(ReducerFuzzManagerIDArgs().parse_args()))
