# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from argparse import Namespace
from logging import getLogger
from typing import Callable

from ..common.fuzzmanager import Bucket
from ..common.utils import Exit, configure_logging
from .args import ReplayFuzzManagerIDQualityArgs
from .crash import main as crash_main

LOG = getLogger(__name__)


def bucket_main(args: Namespace, tool_main: Callable[[Namespace], int]) -> int:
    """CLI for `grizzly.reduce.bucket` and `grizzly.replay.bucket`.

    Arguments:
        args: Result from `parse_args()`.
        tool_main: Main function from a supported Grizzly tool.

    Returns:
        0 for success. non-0 indicates a problem.
    """
    assert callable(tool_main)
    configure_logging(args.log_level)
    LOG.info("Trying each crash in bucket %d until successful", args.input)

    # ensure --tool is reset for each call to tool_main()
    orig_tool = args.tool

    # if no crashes in bucket, return success
    result = Exit.SUCCESS

    with Bucket(args.input) as bucket:
        if args.sig is None:
            args.sig = bucket.signature_path()

        for crash in bucket.iter_crashes(args.quality):
            args.input = crash.crash_id
            args.tool = orig_tool

            # call grizzly tool
            result = Exit(tool_main(args))
            if result in {Exit.SUCCESS, Exit.ABORT}:
                break

    return result


if __name__ == "__main__":
    raise SystemExit(
        bucket_main(ReplayFuzzManagerIDQualityArgs().parse_args(), crash_main)
    )
