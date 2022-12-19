# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import json
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
    # if we did not pass --sig, and the crash is not bucketed
    # auto-generate a signature from crash data so we know what to expect
    if not args.sig and not bucket:
        try:
            fm_sig_file = crash.create_signature(args.binary)
            meta = json.loads(fm_sig_file.with_suffix(".metadata").read_text())
            LOG.info(
                "Using crash data to generate signature: %s",
                meta["shortDescription"],
            )
            args.sig = fm_sig_file
        except RuntimeError as exc:
            LOG.warning("Failed to generate signature from crash data: %s", exc)

    args.original_crash_id = args.input
    args.input = crash.testcase_path()
    if args.tool is None:
        LOG.info("Setting default --tool=%s from CrashEntry", crash.tool)
        args.tool = crash.tool

    # load signature if needed
    if bucket is not None:
        args.sig = bucket.signature_path()
        LOG.info("Using signature from bucket: %d", bucket.bucket_id)

    return args


if __name__ == "__main__":
    raise SystemExit(main(ReplayFuzzManagerIDArgs().parse_args()))
