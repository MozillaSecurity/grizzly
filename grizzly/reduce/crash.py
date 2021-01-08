# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger

from .args import ReduceFuzzManagerIDArgs
from .core import ReduceManager
from ..common.fuzzmanager import Bucket, CrashEntry
from ..common.reporter import FuzzManagerReporter
from ..main import configure_logging
from ..session import Session


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
    bucket = None
    try:
        # download the crash
        args.input = str(crash.testcase_path())
        if args.sig is None and crash.bucket is not None:
            bucket = Bucket(crash.bucket)
            args.sig = str(bucket.signature_path())
        if args.tool is None:
            args.tool = crash.tool

        # call grizzly.reduce
        result = ReduceManager.main(args)

        # update quality
        # map Session.EXIT_* -> FuzzManagerReporter.QUAL_*
        # default back to UNREDUCED
        # most errors will not be related to the testcase
        # so they should be retried later
        if args.fuzzmanager:
            quality = {
                Session.EXIT_ERROR: FuzzManagerReporter.QUAL_REDUCER_ERROR,
                Session.EXIT_ABORT: crash.testcase_quality,
                Session.EXIT_SUCCESS: FuzzManagerReporter.QUAL_REDUCED_ORIGINAL,
                Session.EXIT_FAILURE: FuzzManagerReporter.QUAL_NOT_REPRODUCIBLE,
            }.get(
                result, FuzzManagerReporter.QUAL_UNREDUCED
            )
            # don't ever set things back to Q4, default to Q5 for that case.
            # Q4 is only used in automation, so ABORT should never happen.
            if quality == FuzzManagerReporter.QUAL_REDUCING:
                quality = FuzzManagerReporter.QUAL_UNREDUCED
            LOG.info(
                "reducer finished -> exit(%d) -> Q%d",
                result,
                quality,
            )
            crash.testcase_quality = quality
    finally:
        crash.cleanup()
        if bucket is not None:
            bucket.cleanup()
    return result


if __name__ == "__main__":
    raise SystemExit(main(ReduceFuzzManagerIDArgs().parse_args()))
