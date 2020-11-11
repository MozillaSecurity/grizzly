# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
import sys

from .args import ReduceFuzzManagerIDQualityArgs
from .crash import CrashEntry, main as crash_main
from ..main import configure_logging
from ..session import Session


LOG = getLogger(__name__)


def main(args):
    """CLI for `grizzly.reduce.bucket`.

    Arguments:
        args (argparse.Namespace): Result from `ReduceArgs.parse_args`.

    Returns:
        int: 0 for success. non-0 indicates a problem.
    """
    configure_logging(args.log_level)
    LOG.info("Trying all crashes in bucket %d until one reduces", args.input)
    # ensure --tool is reset for each call to grizzly.reduce.crash.main()
    orig_tool = args.tool

    # if no crashes in bucket, return success
    result = Session.EXIT_SUCCESS

    # create a fake CrashEntry used only to download the signature once
    crash = CrashEntry(0)
    crash._data = {"bucket": args.input}  # pylint: disable=protected-access
    try:
        if args.sig is None:
            args.sig = str(crash.bucket_path())

        for crash in CrashEntry.iter_bucket(args.input, args.quality):
            args.input = crash.id
            args.tool = orig_tool

            # call grizzly.reduce.crash
            result = crash_main(args)
            if result == 0:
                break

    finally:
        crash.cleanup()
    return result


if __name__ == "__main__":
    sys.exit(main(ReduceFuzzManagerIDQualityArgs().parse_args()))
