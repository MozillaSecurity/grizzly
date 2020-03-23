# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import os.path

from ..args import CommonArgs


class ReplayArgs(CommonArgs):

    def __init__(self):
        super(ReplayArgs, self).__init__()
        self.parser.add_argument(
            "input",
            help="Directory containing test case")
        self.parser.add_argument(
            "--any-crash", action="store_true",
            help="Any crash is interesting, not only crashes which match the original first crash")
        self.parser.add_argument(
            "--idle-timeout", type=int, default=60,
            help="Number of seconds to wait before polling testcase for idle (default: %(default)s)")
        self.parser.add_argument(
            "--idle-threshold", type=int, default=25,
            help="CPU usage threshold to mark the process as idle (default: %(default)s)")
        self.parser.add_argument(
            "--min-crashes", type=int, default=1,
            help="Require the testcase to crash n times before accepting the result. (default: %(default)sx)")
        self.parser.add_argument(
            "--no-harness", action="store_true",
            help="Don't use the harness for redirection")
        self.parser.add_argument(
            "--repeat", type=int, default=1,
            help="Try to run the testcase multiple times, for intermittent testcases (default: %(default)sx)")
        self.parser.add_argument(
            "--rr", action="store_true",
            help="Use RR (Linux only)")
        self.parser.add_argument(
            "--sig",
            help="Signature (JSON) file to match (Requires FuzzManager)")

    def sanity_check(self, args):
        super(ReplayArgs, self).sanity_check(args)

        if not os.path.isdir(args.input) or not os.path.isfile(os.path.join(args.input, "test_info.json")):
            self.parser.error("Test case must be a folder containing a test_info.json")

        if args.min_crashes < 1:
            self.parser.error("'--min-crashes' value must be positive")

        if args.repeat < 1:
            self.parser.error("'--repeat' value must be positive")

        if args.sig is not None and not os.path.isfile(args.sig):
            self.parser.error("signature file not found: %r" % (args.sig,))
