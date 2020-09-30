# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import getLogger
from pathlib import Path

from ..replay.args import ReplayArgs
from .strategies import DEFAULT_STRATEGIES, STRATEGIES


LOG = getLogger(__name__)


class ReduceArgs(ReplayArgs):

    def __init__(self):
        super().__init__()

        # these arguments have other defaults vs how they are defined in ReplayArgs
        self.parser.set_defaults(
            include_test=True,
            logs='.',
        )

        reduce_args = self.parser.add_argument_group("Reduce Arguments")
        reduce_args.add_argument(
            "--no-analysis", action="store_true",
            help="Disable analysis to auto-set --repeat/--min-crashes.")
        reduce_args.add_argument(
            "--strategy", nargs="+", default=DEFAULT_STRATEGIES, metavar="STRATEGY",
            dest="strategies",
            help="One or more strategies (space-separated). Available: %s (default: %s)"
            % (" ".join(sorted(STRATEGIES)), " ".join(DEFAULT_STRATEGIES)))

    def sanity_check(self, args):
        super().sanity_check(args)

        # if logs is specified, we need it to be a directory (whether existent or not)
        if Path(args.logs).is_file():
            self.parser.error("'--logs' cannot be a file")

        # check that specified strategies exist
        for strategy in args.strategies:
            if strategy not in STRATEGIES:
                self.parser.error("Unrecognized '--strategy': '%s'" % (strategy,))

        if not args.no_analysis:
            # analysis is enabled, but repeat/min_crashes specified. doesn't make sense
            errors = []
            if args.repeat != self.parser.get_default("repeat"):
                errors.append("'--repeat'")
            if args.min_crashes != self.parser.get_default("min_crashes"):
                errors.append("'--min-crashes'")
            if errors:
                error_str = " and ".join(errors)
                LOG.warning(
                    "%s specified, with analysis enabled, they will be ignored",
                    error_str
                )
