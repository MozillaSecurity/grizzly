# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from logging import getLogger

from ..common.fuzzmanager import load_fm_data
from ..main import configure_logging
from .args import ReplayFuzzManagerIDArgs
from .replay import ReplayManager

LOG = getLogger(__name__)


def main(args):
    """CLI for `grizzly.replay.crash`.

    Arguments:
        args (argparse.Namespace): Result from `ReplayArgs.parse_args`.

    Returns:
        int: 0 for success. non-0 indicates a problem.
    """
    configure_logging(args.log_level)
    with load_fm_data(args.input, load_bucket=not args.sig) as (crash, bucket):
        LOG.info("Loaded crash %d from FuzzManager", crash.crash_id)
        # call grizzly.replay
        return ReplayManager.main(modify_args(args, crash, bucket))


def modify_args(args, crash, bucket):
    """

    Arguments:
        args (argparse.Namespace): Result from `ReplayArgs.parse_args`.



    Returns:
        args (argparse.Namespace): Modified arguments.
    """
    args.original_crash_id = args.input
    args.input = str(crash.testcase_path())
    if args.tool is None:
        LOG.info("Setting default --tool=%s from CrashEntry", crash.tool)
        args.tool = crash.tool

    # load signature if needed
    if bucket is not None:
        args.sig = str(bucket.signature_path())

    return args


if __name__ == "__main__":
    raise SystemExit(main(ReplayFuzzManagerIDArgs().parse_args()))
