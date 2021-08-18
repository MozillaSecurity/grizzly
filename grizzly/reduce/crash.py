# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger

from ..common.fuzzmanager import Bucket, CrashEntry
from ..common.reporter import Quality
from ..common.utils import Exit
from ..main import configure_logging
from .args import ReduceFuzzManagerIDArgs
from .core import ReduceManager

LOG = getLogger(__name__)


def main(args):
    """CLI for `grizzly.reduce.crash`.

    Arguments:
        args (argparse.Namespace): Result from `ReduceArgs.parse_args`.

    Returns:
        int: 0 for success. non-0 indicates a problem.
    """
    configure_logging(args.log_level)
    crash = CrashEntry(args.input)
    initial_quality = Quality(crash.testcase_quality)
    LOG.info("Loaded crash %d (%s)", crash.crash_id, initial_quality.name)
    bucket = None
    try:
        # download the crash
        args.input = str(crash.testcase_path())
        if args.sig is None and crash.bucket is not None:
            bucket = Bucket(crash.bucket)
            args.sig = str(bucket.signature_path())
        if args.tool is None:
            LOG.info("Setting default --tool=%s from CrashEntry", crash.tool)
            args.tool = crash.tool

        # call grizzly.reduce
        result = ReduceManager.main(args)

        # update quality
        # map Exit.* -> Quality.*
        # default back to UNREDUCED
        # most errors will not be related to the testcase
        # so they should be retried later
        if args.fuzzmanager:
            quality = {
                Exit.ERROR: Quality.REDUCER_ERROR,
                Exit.ABORT: initial_quality,
                Exit.SUCCESS: Quality.ORIGINAL,
                Exit.FAILURE: Quality.NOT_REPRODUCIBLE,
            }.get(result, Quality.UNREDUCED)
            # don't ever set things back to REDUCING, default to UNREDUCED in that case.
            # REDUCING is only used in automation, so ABORT should never happen.
            if quality == Quality.REDUCING:
                quality = Quality.UNREDUCED
            LOG.info(
                "reducer finished -> exit(%d) -> %s (Q%d)",
                result,
                quality.name,
                quality,
            )
            crash.testcase_quality = quality.value
    finally:
        crash.cleanup()
        if bucket is not None:
            bucket.cleanup()
    return result


if __name__ == "__main__":
    raise SystemExit(main(ReduceFuzzManagerIDArgs().parse_args()))
