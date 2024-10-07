# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

from ..common.bugzilla import BugzillaBug
from ..common.utils import Exit, configure_logging
from .args import ReplayFuzzBugzillaArgs
from .replay import ReplayManager

if TYPE_CHECKING:
    from argparse import Namespace

LOG = getLogger(__name__)


def main(args: Namespace | None = None) -> int:
    """CLI for `grizzly.replay.bugzilla`.

    Arguments:
        args: Result from `ReplayArgs.parse_args`.

    Returns:
        Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
    """
    args = args or ReplayFuzzBugzillaArgs().parse_args()
    configure_logging(args.log_level)
    bug = BugzillaBug.load(args.input)
    if bug is None:
        LOG.info("Failed to load Bug %d from Bugzilla", args.input)
        return Exit.ERROR
    LOG.info("Loaded Bug %d from Bugzilla", args.input)
    with bug:
        args.asset.extend(
            # favor assets provided via the command line over the bug attachments
            bug.assets(ignore=tuple(x[0] for x in args.asset))
        )
        testcases = bug.testcases()
        if not testcases:
            LOG.error("No test case data attached to bug %d", args.input)
            return Exit.ERROR
        args.input = testcases
        return ReplayManager.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
