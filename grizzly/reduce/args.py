# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os.path

from .reduce import ReductionJob
from .strategies import strategies_by_name
from ..args import CommonArgs


class ReducerArgs(CommonArgs):

    def __init__(self):
        super(ReducerArgs, self).__init__()
        self.parser.add_argument(
            "input",
            help="Test case or directory containing test cases")
        self.parser.add_argument(
            "--sig",
            help="Signature to reduce (JSON)")
        self.parser.add_argument(
            "--no-harness", action="store_true",
            help="Don't use the harness for sapphire redirection")
        self.parser.add_argument(
            "--any-crash", action="store_true",
            help="Any crash is interesting, not only crashes which match the original first crash")
        self.parser.add_argument(
            "--skip", type=int, default=0,
            help="Return interesting = False for the first n reductions (default: %(default)s)")
        self.parser.add_argument(
            "--repeat", type=int, default=1,
            help="Try to run the testcase multiple times, for intermittent testcases (default: %(default)sx)")
        self.parser.add_argument(
            "--min-crashes", type=int, default=1,
            help="Require the testcase to crash n times before accepting the result. (default: %(default)sx)")
        self.parser.add_argument(
            "--idle-timeout", type=int, default=60,
            help="Number of seconds to wait before polling testcase for idle (default: %(default)s)")
        self.parser.add_argument(
            "--idle-poll", type=int, default=3,
            help="Number of seconds to poll the process before evaluating threshold (default: %(default)s)")
        self.parser.add_argument(
            "--idle-threshold", type=int, default=25,
            help="CPU usage threshold to mark the process as idle (default: %(default)s)")
        self.parser.add_argument(
            "--environ",
            help="File containing line separated environment variables (VAR=value) to be set in the "
            "firefox process.")
        self.parser.add_argument(
            "--reduce-file",
            help="Value passed to lithium's --testcase option, needed for testcase cache "
            "(default: input param)")
        self.parser.add_argument(
            "--no-cache", action="store_true",
            help="Disable testcase caching")
        self.parser.add_argument(
            "--no-analysis", action="store_true",
            help="Disable analysis to auto-set --repeat/--min-crashes.")
        self.parser.add_argument(
            "--strategy", nargs="+", default=list(), metavar="STRATEGY", dest="strategies",
            help="One or more strategies (space-separated). Available: %s (default: %s)"
            % (" ".join(sorted(strategies_by_name())), " ".join(ReductionJob.DEFAULT_STRATEGIES)))

    def sanity_check(self, args):
        super(ReducerArgs, self).sanity_check(args)

        if "input" not in self._sanity_skip:
            if not (os.path.isdir(args.input)
                    or (os.path.isfile(args.input) and (args.input.lower().endswith(".zip")
                                                        or args.input.lower().endswith(".html")))):
                self.parser.error("Testcase should be a folder, zip, or html file")

        if args.sig is not None and not os.path.isfile(args.sig):
            self.parser.error("file not found: %r" % args.sig)

        if args.repeat < 1:
            self.parser.error("'--repeat' value must be positive")

        if args.min_crashes < 1:
            self.parser.error("'--min-crashes' value must be positive")

        if args.environ is not None and not os.path.isfile(args.environ):
            self.parser.error("file not found: %r" % args.environ)

        if args.strategies:
            known_strategies = set(strategies_by_name())
            for strategy in args.strategies:
                if strategy not in known_strategies:
                    self.parser.error("invalid strategy: %s" % (strategy,))
        else:
            args.strategies = None

        if args.reduce_file is None:
            args.reduce_file = args.input


class ReducerFuzzManagerIDArgs(ReducerArgs):

    def __init__(self):
        super(ReducerFuzzManagerIDArgs, self).__init__()

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


class ReducerFuzzManagerIDQualityArgs(ReducerFuzzManagerIDArgs):

    def __init__(self):
        super(ReducerFuzzManagerIDQualityArgs, self).__init__()
        self.parser.add_argument("--quality", type=int,
                                 help="Only try crashes with a given quality value")

    def sanity_check(self, args):
        super(ReducerFuzzManagerIDQualityArgs, self).sanity_check(args)

        if args.quality is not None and args.quality < 0:
            self.parser.error("'--quality' value must be positive or zero")
