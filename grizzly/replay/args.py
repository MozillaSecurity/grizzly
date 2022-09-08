# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from argparse import SUPPRESS
from pathlib import Path

from ..args import CommonArgs


class ReplayArgs(CommonArgs):
    def __init__(self):
        super().__init__()
        self.parser.set_defaults(logs=None)
        self.parser.add_argument(
            "input",
            type=Path,
            help="Accepted input includes: "
            "1) A directory containing testcase data. "
            "2) A directory with one or more subdirectories containing testcase data. "
            "3) A zip archive containing testcase data or subdirectories containing"
            " testcase data. "
            "4) A single file to be used as a testcase. "
            "When using a directory it must contain a 'test_info.json' file.",
        )

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
        replay_args.add_argument(
            "--no-harness",
            action="store_true",
            help="Don't use the harness for redirection. Implies '--relaunch=1'.",
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
        replay_args.add_argument(
            "--test-index",
            type=int,
            nargs="+",
            help="Select a testcase to run when multiple testcases are loaded. "
            "Testscases are ordered oldest to newest. Indexing is 0 based. "
            "0 == Oldest, n-1 == Newest (default: run all testcases)",
        )

        self.launcher_grp.add_argument(
            "--post-launch-delay",
            type=int,
            default=None,
            help="Number of seconds to wait after launching browser before "
            " running the test. This provides an opportunity to connect debuggers. ",
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

        if "input" not in self._sanity_skip and not args.input.exists():
            self.parser.error("'%s' does not exist" % (args.input,))

        if args.logs is None and (args.pernosco or args.rr):
            self.parser.error("--logs must be set when using rr")

        if args.min_crashes < 1:
            self.parser.error("--min-crashes value must be positive")

        if args.post_launch_delay is not None and args.post_launch_delay < 0:
            self.parser.error("--post-launch-delay value must be positive")

        if args.repeat < 1:
            self.parser.error("--repeat value must be positive")

        if args.sig and not args.sig.is_file():
            self.parser.error("signature file not found: '%s'" % (args.sig,))

    def update_arg(self, name, new_type, help_msg):
        # madhax alert!
        #
        # We need to modify the meaning of the 'input' positional to accept an int ID
        # instead of a local testcase.
        # This is not possible with the public argparse API.
        #
        # refs: stackoverflow.com/questions/32807319/disable-remove-argument-in-argparse
        #       bugs.python.org/issue19462

        # look up the action for the positional `input` arg
        action = None
        for arg in self.parser._actions:  # pylint: disable=protected-access
            if arg.dest == name and not arg.option_strings:
                action = arg
                break
        assert action is not None

        # modify its type and help string
        action.type = new_type
        action.help = help_msg

        # ... and Bob's your uncle
        self._sanity_skip.add("input")


class ReplayFuzzManagerIDArgs(ReplayArgs):
    def __init__(self):
        """Initialize argument parser."""
        super().__init__()
        self.update_arg("input", int, "FuzzManager ID to replay")


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
