# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from os.path import isfile

from ..args import CommonArgs


class ReplayArgs(CommonArgs):

    def __init__(self):
        super().__init__()
        self.parser.add_argument(
            "input",
            help="Accepted input includes: " \
                "1) A directory containing testcase data. " \
                "2) A directory with one or more subdirectories containing testcase data. " \
                "3) A zip archive containing testcase data or subdirectories containing testcase data. " \
                "4) A single file to be used as a testcase. " \
                "When using a directory it must contain a 'test_info.json' file.")

        replay_args = self.parser.add_argument_group("Replay Arguments")
        replay_args.add_argument(
            "--any-crash", action="store_true",
            help="Any crash is interesting, not only crashes which match the original signature.")
        replay_args.add_argument(
            "--idle-delay", type=int, default=30,
            help="Number of seconds to wait before polling for idle (default: %(default)s)")
        replay_args.add_argument(
            "--idle-threshold", type=int, default=0,
            help="CPU usage threshold to mark the process as idle (default: disabled)")
        replay_args.add_argument(
            "-l", "--logs",
            help="Location to save logs. If the path exists it must be empty, if it " \
                "does not exist it will be created.")
        replay_args.add_argument(
            "--min-crashes", type=int, default=1,
            help="Require the testcase to crash n times before accepting the result." \
                " Helpful for intermittent testcases (default: %(default)sx)")
        replay_args.add_argument(
            "--no-harness", action="store_true",
            help="Don't use the harness for redirection. Implies '--relaunch=1'.")
        replay_args.add_argument(
            "--repeat", type=int, default=1,
            help="Run the testcase n times." \
                " Helpful for intermittent testcases (default: %(default)sx)")
        replay_args.add_argument(
            "--sig",
            help="Signature (JSON) file to match.")
        replay_args.add_argument(
            "--test-index", type=int, nargs="+",
            help="Select a testcase to run when multiple testcases are loaded. " \
                 "Testscases are ordered oldest to newest. Indexing is 0 based. " \
                 "0 == Oldest, n-1 == Newest (default: run all testcases)")

        self.launcher_grp.add_argument(
            "--rr", action="store_true",
            help="Use RR (Linux only)")

        self.reporter_grp.add_argument(
            "--include-test", action="store_true",
            help="Include the testcase when reporting results.")

    def sanity_check(self, args):
        super().sanity_check(args)

        if args.any_crash and args.sig is not None:
            self.parser.error("signature is ignored when running with '--any-crash'")

        if args.idle_threshold and args.idle_delay <= 0:
            self.parser.error("'--idle-delay' value must be positive")

        if args.min_crashes < 1:
            self.parser.error("'--min-crashes' value must be positive")

        if args.no_harness:
            args.relaunch = 1

        if args.repeat < 1:
            self.parser.error("'--repeat' value must be positive")

        if args.rr and args.valgrind:
            self.parser.error("'--rr' and '--valgrind' cannot be used together")

        if args.sig is not None and not isfile(args.sig):
            self.parser.error("signature file not found: %r" % (args.sig,))
