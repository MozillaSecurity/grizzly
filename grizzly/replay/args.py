# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from argparse import SUPPRESS
from pathlib import Path

from ..args import CommonArgs

LOCAL_INPUT_HELP = (
    "A directory containing testcase data or a single file to use as a testcase."
)


class ReplayCommonArgs(CommonArgs):
    def __init__(self):
        super().__init__()
        self.parser.set_defaults(logs=None)

        replay_args = self.parser.add_argument_group("Replay Arguments")
        replay_args.add_argument(
            "--any-crash",
            action="store_true",
            help="Any crash is interesting, not only crashes which match the original"
            " signature.",
        )
        replay_args.add_argument(
            "--idle-delay",
            type=int,
            default=30,
            help="Number of seconds to wait before polling for idle"
            " (default: %(default)s)",
        )
        replay_args.add_argument(
            "--idle-threshold",
            type=int,
            default=0,
            help="CPU usage threshold to mark the process as idle (default: disabled)",
        )
        replay_args.add_argument(
            "--min-crashes",
            type=int,
            default=1,
            help="Require the testcase to crash n times before accepting the result."
            " Helpful for intermittent testcases (default: %(default)sx)",
        )
        # hidden argument to add original crash ID as metadata when reported
        replay_args.add_argument("--original-crash-id", type=int, help=SUPPRESS)
        replay_args.add_argument(
            "--repeat",
            type=int,
            default=1,
            help="Run the testcase n times."
            " Helpful for intermittent testcases (default: %(default)sx)",
        )
        replay_args.add_argument(
            "--sig", type=Path, help="Signature (JSON) file to match."
        )

        self.reporter_grp.add_argument(
            "--include-test",
            action="store_true",
            help="Include the testcase when reporting results.",
        )

    def sanity_check(self, args):
        super().sanity_check(args)

        if args.any_crash and args.sig is not None:
            self.parser.error("signature is ignored when running with --any-crash")

        if args.idle_threshold and args.idle_delay <= 0:
            self.parser.error("--idle-delay value must be positive")

        if args.logs is None and (args.pernosco or args.rr):
            self.parser.error("--logs must be set when using rr")

        if args.min_crashes < 1:
            self.parser.error("--min-crashes value must be positive")

        if args.repeat < 1:
            self.parser.error("--repeat value must be positive")

        if args.sig and not args.sig.is_file():
            self.parser.error(f"signature file not found: '{args.sig}'")


class ReplayArgs(ReplayCommonArgs):
    def __init__(self):
        super().__init__()
        self.parser.add_argument("input", type=Path, nargs="+", help=LOCAL_INPUT_HELP)

    def sanity_check(self, args):
        super().sanity_check(args)

        for test in args.input:
            if not test.exists():
                self.parser.error(f"'{test}' does not exist")

        if args.no_harness and len(args.input) > 1:
            self.parser.error("'--no-harness' cannot be used with multiple testcases")


class ReplayFuzzManagerIDArgs(ReplayCommonArgs):
    def __init__(self):
        """Initialize argument parser."""
        super().__init__()
        self.parser.add_argument("input", type=int, help="FuzzManager ID to replay")

        self.parser.add_argument(
            "--test-index",
            type=int,
            nargs="+",
            help="Select a testcase to run when multiple testcases are loaded. "
            "Testscases are ordered oldest to newest. "
            "0 == oldest, n-1 == most recent (default: run all testcases)",
        )

    def sanity_check(self, args):
        super().sanity_check(args)

        if args.no_harness and not args.test_index:
            self.parser.error("'--no-harness' requires '--test-index'")


class ReplayFuzzManagerIDQualityArgs(ReplayFuzzManagerIDArgs):
    def __init__(self):
        """Initialize argument parser."""
        super().__init__()
        self.parser.add_argument(
            "--quality", type=int, help="Only try crashes with a given quality value"
        )

    def sanity_check(self, args):
        super().sanity_check(args)

        if args.quality is not None and args.quality < 0:
            self.parser.error("'--quality' value cannot be negative")
