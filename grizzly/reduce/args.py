# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""CLI argument parsing for Grizzly reduction.
"""
from argparse import Namespace
from logging import getLogger
from pathlib import Path

from ..common.reporter import Quality
from ..replay.args import LOCAL_INPUT_HELP, ReplayCommonArgs
from .strategies import DEFAULT_STRATEGIES, STRATEGIES

LOG = getLogger(__name__)


class ReduceCommonArgs(ReplayCommonArgs):
    """Argument parser for `grizzly.reduce`.

    Takes all arguments defined for `grizzly.replay`, and a few specific to reduction.
    """

    def __init__(self) -> None:
        """Initialize argument parser."""
        super().__init__()

        # these arguments have defaults that vary from ReplayCommonArgs
        self.parser.set_defaults(output=Path.cwd())

        reduce_args = self.parser.add_argument_group("Reduce Arguments")
        reduce_args.add_argument(
            "--no-analysis",
            action="store_true",
            help="Disable analysis to auto-set --repeat/--min-crashes.",
        )
        reduce_args.add_argument(
            "--report-period",
            type=int,
            help="Periodically report the best testcase for long-running strategies."
            " (value in seconds, default: no)",
        )
        reduce_args.add_argument(
            "--static-timeout",
            action="store_true",
            help="Disable automatically updating the iteration timeout.",
        )
        reduce_args.add_argument(
            "--strategy",
            nargs="+",
            choices=STRATEGIES,
            default=DEFAULT_STRATEGIES,
            dest="strategies",
            help="One or more strategies. (default: %(default)s)",
        )

    def sanity_check(self, args: Namespace) -> None:
        """Sanity check reducer args.

        Arguments:
            args: Result from `parse_args()`.

        Raises:
            SystemExit: on error, `ArgumentParser.error()` is called, which will exit.
        """
        super().sanity_check(args)

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
                    error_str,
                )


class ReduceArgs(ReduceCommonArgs):
    # NOTE: If updated changes may also need to be added to ReplayArgs
    def __init__(self) -> None:
        super().__init__()
        self.parser.add_argument("input", type=Path, nargs="+", help=LOCAL_INPUT_HELP)

        self.launcher_grp.add_argument(
            "--entry-point",
            type=Path,
            help="Specify file to use as testcase entry-point when it cannot be"
            " automatically determined.",
        )

    def sanity_check(self, args: Namespace) -> None:
        super().sanity_check(args)

        for test in args.input:
            if not test.exists():
                self.parser.error(f"'{test}' does not exist")

        if args.no_harness and len(args.input) > 1:
            self.parser.error("'--no-harness' cannot be used with multiple testcases")


class ReduceFuzzManagerIDArgs(ReduceCommonArgs):
    def __init__(self) -> None:
        """Initialize argument parser."""
        super().__init__()
        self.parser.add_argument("input", type=int, help="FuzzManager ID to reduce")

        self.parser.add_argument(
            "--no-repro-quality",
            choices=[x.value for x in Quality],
            default=Quality.NOT_REPRODUCIBLE.value,
            type=int,
            help="Quality value reported when issue does not reproduce "
            "(default: %(default)s).",
        )

        self.parser.add_argument("--test-ext", help="Overwrite testcase file extension")

        self.parser.add_argument(
            "--test-index",
            default=[],
            type=int,
            nargs="+",
            help="Select a testcase to run when multiple testcases are loaded. "
            "Testscases are ordered oldest to newest. "
            "0 == oldest, n-1 == most recent (default: run all testcases)",
        )

    def sanity_check(self, args: Namespace) -> None:
        super().sanity_check(args)

        if args.no_harness and len(args.test_index) > 1:
            self.parser.error(
                "'--test-index' only supports a single value with '--no-harness'"
            )


class ReduceFuzzManagerIDQualityArgs(ReduceFuzzManagerIDArgs):
    def __init__(self) -> None:
        """Initialize argument parser."""
        super().__init__()
        self.parser.add_argument(
            "--quality",
            choices=[x.value for x in Quality],
            type=int,
            help="Only try crashes with a given quality value.",
        )
