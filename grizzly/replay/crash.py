# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from json import loads
from logging import getLogger
from typing import TYPE_CHECKING

from ..common.fuzzmanager import Bucket, CrashEntry, load_fm_data
from ..common.utils import configure_logging
from .args import ReplayFuzzManagerIDArgs
from .replay import ReplayManager

if TYPE_CHECKING:
    from argparse import Namespace

LOG = getLogger(__name__)


def main(args: Namespace | None = None) -> int:
    """CLI for `grizzly.replay.crash`.

    Arguments:
        args: Result from `ReplayFuzzManagerIDArgs.parse_args`.

    Returns:
        Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
    """
    args = args or ReplayFuzzManagerIDArgs().parse_args()
    configure_logging(args.log_level)
    with load_fm_data(args.input, load_bucket=not args.sig) as (crash, bucket):
        LOG.info("Loaded crash %d from FuzzManager", crash.crash_id)
        # call grizzly.replay
        return ReplayManager.main(modify_args(args, crash, bucket))


def modify_args(args: Namespace, crash: CrashEntry, bucket: Bucket | None) -> Namespace:
    """

    Arguments:
        args: Result from `ReplayFuzzManagerIDArgs.parse_args`.
        crash: Crash entry to process.
        bucket: Bucket that contains crash.

    Returns:
        Modified arguments.
    """
    # if we did not pass --sig, and the crash is not bucketed
    # auto-generate a signature from crash data so we know what to expect
    if not args.sig and not bucket:
        try:
            fm_sig_file = crash.create_signature(args.binary)
            meta = loads(fm_sig_file.with_suffix(".metadata").read_text())
            LOG.info(
                "Using crash data to generate signature: %s",
                meta["shortDescription"],
            )
            args.sig = fm_sig_file
        except RuntimeError as exc:
            LOG.warning("Failed to generate signature from crash data: %s", exc)

    args.original_crash_id = args.input
    # use the newest test case when not using a harness and test_index is not specified
    if args.no_harness and not args.test_index:
        args.test_index = [-1]
    args.input = crash.testcases(subset=args.test_index, ext=args.test_ext)
    # set tool name using crash entry
    if args.tool is None:
        LOG.info("Setting default --tool=%s from CrashEntry", crash.tool)
        args.tool = crash.tool
    # load signature if needed
    if bucket is not None:
        args.sig = bucket.signature_path()
        LOG.info("Using signature from bucket: %d", bucket.bucket_id)

    return args


if __name__ == "__main__":
    raise SystemExit(main())
