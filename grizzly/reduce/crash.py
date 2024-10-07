# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

from ..common.fuzzmanager import load_fm_data
from ..common.reporter import Quality
from ..common.utils import Exit, configure_logging
from ..replay.crash import modify_args
from .args import ReduceFuzzManagerIDArgs
from .core import ReduceManager

if TYPE_CHECKING:
    from argparse import Namespace

LOG = getLogger(__name__)


def main(args: Namespace | None = None) -> int:
    """CLI for `grizzly.reduce.crash`.

    Arguments:
        args: Result from `ReduceArgs.parse_args`.

    Returns:
        Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
    """
    args = args or ReduceFuzzManagerIDArgs().parse_args()
    configure_logging(args.log_level)
    with load_fm_data(args.input, load_bucket=not args.sig) as (crash, bucket):
        LOG.info(
            "Loaded crash %d (%s) from FuzzManager",
            crash.crash_id,
            Quality(crash.testcase_quality).name,
        )
        # call grizzly.reduce
        result = ReduceManager.main(modify_args(args, crash, bucket))

        # update quality
        # map Exit.* -> Quality.*
        # default back to UNREDUCED
        # most errors will not be related to the testcase
        # so they should be retried later
        if args.fuzzmanager:
            quality = {
                Exit.ERROR: Quality.REDUCER_ERROR,
                Exit.ABORT: Quality(crash.testcase_quality),
                Exit.SUCCESS: Quality.ORIGINAL,
                Exit.FAILURE: Quality(args.no_repro_quality),
            }.get(Exit(result), Quality.UNREDUCED)
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

    return result


if __name__ == "__main__":
    raise SystemExit(main())
