# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""CLI argument parsing for Grizzly reduction.
"""
from logging import getLogger
from pathlib import Path

from ..replay.args import ReplayArgs
from .strategies import DEFAULT_STRATEGIES, STRATEGIES


LOG = getLogger(__name__)


class ReduceArgs(ReplayArgs):
    """Argument parser for `grizzly.reduce`.

    Takes all arguments defined for `grizzly.replay`, and a few specific to reduction.
    """

    def __init__(self):
        """Initialize argument parser."""
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
            "--report-period", type=int,
            help="Periodically report the best testcase for long-running strategies."
            " (value in seconds, default: no)")
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

        if args.report_period is not None:
            if args.report_period <= 0:
                self.parser.error("Invalid --report-period (value is in seconds)")
            if args.report_period < 60:
                self.parser.error("Very short --report-period (value is in seconds)")

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


class ReduceFuzzManagerIDArgs(ReduceArgs):

    def __init__(self):
        """Initialize argument parser."""
        super().__init__()

        # madhax alert!
        #
        # We need to modify the meaning of the 'input' positional to accept an int ID instead of a
        # local testcase. This is not possible with the public argparse API.
        #
        # refs: https://stackoverflow.com/questions/32807319/disable-remove-argument-in-argparse
        #       https://bugs.python.org/issue19462

        # look up the action for the positional `input` arg
        action = None
        for arg in self.parser._actions:
            if arg.dest == "input" and not arg.option_strings:
                action = arg
                break
        assert action is not None

        # modify it's type and help string
        action.type = int
        action.help = "FuzzManager ID to reduce"

        # ... and Bob's your uncle
        self._sanity_skip.add("input")


class ReduceFuzzManagerIDQualityArgs(ReduceFuzzManagerIDArgs):

    def __init__(self):
        """Initialize argument parser."""
        super().__init__()
        self.parser.add_argument(
            "--quality", type=int,
            help="Only try crashes with a given quality value")

    def sanity_check(self, args):
        super().sanity_check(args)

        if args.quality is not None and args.quality < 0:
            self.parser.error("'--quality' value cannot be negative")
