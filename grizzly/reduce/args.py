# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""CLI argument parsing for Grizzly reduction.
"""
from argparse import ArgumentParser
from logging import getLogger
from pathlib import Path
import sys

from ..args import SortingHelpFormatter
from ..common.reporter import FuzzManagerReporter
from ..replay.args import ReplayArgs
from .strategies import DEFAULT_STRATEGIES, STRATEGIES


LOG = getLogger(__name__)


class _ArgparserExitReducerError(ArgumentParser):
    def exit(self, status=0, message=None):
        if message is not None:
            print(message, file=sys.stderr)
        if status != 0:
            LOG.debug("overriding original argparse exit code (%d)", status)
            status = FuzzManagerReporter.QUAL_REDUCER_ERROR
        sys.exit(status)


class ReduceArgs(ReplayArgs):
    """Argument parser for `grizzly.reduce`.

    Takes all arguments defined for `grizzly.replay`, and a few specific to reduction.
    """

    def __init__(self):
        """Initialize argument parser.
        """
        self.parser = _ArgparserExitReducerError(
                formatter_class=SortingHelpFormatter,
                conflict_handler="resolve")
        super().__init__()

        # these arguments have other defaults vs how they are defined in ReplayArgs
        self.parser.set_defaults(
            include_test=True,
            logs='.',
        )

        reduce_args = self.parser.add_argument_group("Reduce Arguments")
        reduce_args.add_argument(
            "--skip-dd-unmarked", action="store_false", dest="all_files",
            help="Only reduce files containing DDBEGIN/END (default: all files)")
        reduce_args.add_argument(
            "--no-analysis", action="store_true",
            help="Disable analysis to auto-set --repeat/--min-crashes.")
        reduce_args.add_argument(
            "--static-timeout", action="store_true",
            help="Disable automatically updating the iteration timeout.")
        reduce_args.add_argument(
            "--strategy", nargs="+", default=DEFAULT_STRATEGIES, metavar="STRATEGY",
            dest="strategies",
            help="One or more strategies (space-separated). Available: %s (default: %s)"
            % (" ".join(sorted(STRATEGIES)), " ".join(DEFAULT_STRATEGIES)))

    def sanity_check(self, args):
        """Sanity check reducer args.

        Arguments:
            args (argparse.Namespace): Result from `parse_args()`.

        Raises:
            SystemExit: on error, `ArgumentParser.error()` is called, which will exit.
        """
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
