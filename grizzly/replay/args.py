# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from os.path import isfile, isdir, join as pathjoin

from ..args import CommonArgs


class ReplayArgs(CommonArgs):

    def __init__(self):
        super(ReplayArgs, self).__init__()
        self.parser.add_argument(
            "input",
            help="Directory containing test case data or file to use as a test case." \
                "When using a directory it must contain a 'test_info.json' file.")

        replay_args = self.parser.add_argument_group("Replay Arguments")
        replay_args.add_argument(
            "--any-crash", action="store_true",
            help="Any crash is interesting, not only crashes which match the original signature.")
        replay_args.add_argument(
            "--idle-threshold", type=int, default=25,
            help="CPU usage threshold to mark the process as idle (default: %(default)s)")
        replay_args.add_argument(
            "--idle-timeout", type=int, default=60,
            help="Number of seconds to wait before polling testcase for idle (default: %(default)s)")
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
            help="Don't use the harness for redirection")
        replay_args.add_argument(
            "--repeat", type=int, default=1,
            help="Run the testcase n times." \
                " Helpful for intermittent testcases (default: %(default)sx)")
        replay_args.add_argument(
            "--sig",
            help="Signature (JSON) file to match.")

        self.launcher_grp.add_argument(
            "--rr", action="store_true",
            help="Use RR (Linux only)")

        self.reporter_grp.add_argument(
            "--include-test", action="store_true",
            help="Include the testcase when reporting results.")

        self.parser.epilog = "For addition help check out the wiki:" \
            " https://github.com/MozillaSecurity/grizzly/wiki"

    def sanity_check(self, args):
        super(ReplayArgs, self).sanity_check(args)

        if "input" not in self._sanity_skip and isdir(args.input):
            if not isfile(pathjoin(args.input, "test_info.json")):
                self.parser.error("Test case folder must contain 'test_info.json'")

        if args.any_crash and args.sig is not None:
            self.parser.error("signature is ignored when running with '--any-crash'")

        if args.min_crashes < 1:
            self.parser.error("'--min-crashes' value must be positive")

        if args.repeat < 1:
            self.parser.error("'--repeat' value must be positive")

        if args.sig is not None and not isfile(args.sig):
            self.parser.error("signature file not found: %r" % (args.sig,))
