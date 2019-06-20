# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
import argparse
import os.path
import tempfile

import grizzly.adapters
from .target import available as available_targets

# ref: https://stackoverflow.com/questions/12268602/sort-argparse-help-alphabetically
class SortingHelpFormatter(argparse.HelpFormatter):
    @staticmethod
    def __sort_key(action):
        for opt in action.option_strings:
            if opt.startswith("--"):
                return [opt]
        return action.option_strings

    def add_usage(self, usage, actions, groups, prefix=None):
        actions = sorted(actions, key=self.__sort_key)
        super(SortingHelpFormatter, self).add_usage(usage, actions, groups, prefix)

    def add_arguments(self, actions):
        actions = sorted(actions, key=self.__sort_key)
        super(SortingHelpFormatter, self).add_arguments(actions)


class CommonArgs(object):
    IGNORABLE = ("log-limit", "memory", "timeout")

    def __init__(self):
        self._sanity_skip = set()

        self.parser = argparse.ArgumentParser(formatter_class=SortingHelpFormatter)

        self.parser.add_argument(
            "binary",
            help="Firefox binary to run")
        self.parser.add_argument(
            "-e", "--extension", action="append",
            help="Install an extension. Specify the path to the xpi or the directory"
                 " containing the unpacked extension. To install multiple extensions"
                 " specify multiple times")
        self.parser.add_argument(
            "--fuzzmanager", action="store_true",
            help="Report results to FuzzManager")
        self.parser.add_argument(
            "--ignore", nargs="+", default=list(),
            help="Space separated ignore list. ie: %s (default: nothing)" % " ".join(self.IGNORABLE))
        self.parser.add_argument(
            "--launch-timeout", type=int, default=300,
            help="Number of seconds to wait before LaunchError is raised (default: %(default)s)")
        self.parser.add_argument(
            "--log-limit", type=int,
            help="Log file size limit in MBs (default: 'no limit')")
        self.parser.add_argument(
            "-m", "--memory", type=int,
            help="Browser process memory limit in MBs (default: 'no limit')")
        self.parser.add_argument(
            "--platform", default="ffpuppet",
            help="Platforms available: %s (default: %%(default)s)" % ", ".join(available_targets()))
        self.parser.add_argument(
            "-p", "--prefs",
            help="prefs.js file to use")
        self.parser.add_argument(
            "--relaunch", type=int, default=1000,
            help="Number of iterations performed before relaunching the browser (default: %(default)s)")
        self.parser.add_argument(
            "--soft-asserts", action="store_true",
            help="Detect soft assertions")
        self.parser.add_argument(
            "-t", "--timeout", type=int, default=60,
            help="Iteration timeout in seconds (default: %(default)s)")
        self.parser.add_argument(
            "--tool",
            help="Override tool name used when reporting issues to FuzzManager")
        self.parser.add_argument(
            "--valgrind", action="store_true",
            help="Use Valgrind (Linux only)")
        self.parser.add_argument(
            "-w", "--working-path",
            help="Working directory. Intended to be used with ram-drives."
                 " (default: %r)" % tempfile.gettempdir())
        self.parser.add_argument(
            "--xvfb", action="store_true",
            help="Use Xvfb (Linux only)")

    def parse_args(self, argv=None):
        args = self.parser.parse_args(argv)
        self.sanity_check(args)
        return args

    def sanity_check(self, args):
        if not os.path.isfile(args.binary):
            self.parser.error("file not found: %r" % args.binary)

        # sanitize ignore list
        args.ignore = {arg.lower() for arg in args.ignore}
        for ignore_token in args.ignore:
            if ignore_token not in self.IGNORABLE:
                self.parser.error("Unrecognized ignore value: %s" % ignore_token)

        if "input" not in self._sanity_skip and args.input:
            if not os.path.exists(args.input):
                self.parser.error("%r does not exist" % args.input)
            elif os.path.isdir(args.input) and not os.listdir(args.input):
                self.parser.error("%r is empty" % args.input)

        if args.working_path is not None and not os.path.isdir(args.working_path):
            self.parser.error("%r is not a directory" % args.working_path)

        if args.extension is not None:
            for ext in args.extension:
                if not os.path.exists(ext):
                    self.parser.error("%r does not exist" % ext)
                if not os.path.isdir(ext) or (os.path.isfile(ext) and ext.endswith(".xpi")):
                    self.parser.error("Extension must be a folder or .xpi")

        if args.platform.lower() not in set(available_targets()):
            self.parser.error("Unsupported platform %r" % args.platform)

        if args.prefs is not None and not os.path.isfile(args.prefs):
            self.parser.error("file not found: %r" % args.prefs)

        if "tool" not in self._sanity_skip:
            if args.tool is not None and not args.fuzzmanager:
                self.parser.error("--tool can only be given with --fuzzmanager")


class GrizzlyArgs(CommonArgs):
    def __init__(self):
        self.adapters = sorted(grizzly.adapters.names())
        super(GrizzlyArgs, self).__init__()
        self._sanity_skip.add("tool")
        self.parser.add_argument(
            "adapter",
            help="Available adapters: %s" % ", ".join(self.adapters))
        self.parser.add_argument(
            "--accepted-extensions", nargs="+",
            help="Space separated list of supported file extensions. ie: html svg (default: all)")
        self.parser.add_argument(
            "-c", "--cache", type=int, default=0,
            help="Maximum number of additional test cases to include in report (default: %(default)s)")
        self.parser.add_argument(
            "--coverage", action="store_true",
            help="Enable coverage collection")
        self.parser.add_argument(
            "-i", "--input",
            help="Test case or directory containing test cases")
        self.parser.add_argument(
            "--mime",
            help="Specify a mime type")
        self.parser.add_argument(
            "--rr", action="store_true",
            help="Use RR (Linux only)")
        self.parser.add_argument(
            "--s3-fuzzmanager", action="store_true",
            help="Report large attachments (if any) to S3 and then the crash & S3 link to FuzzManager")

    def sanity_check(self, args):
        super(GrizzlyArgs, self).sanity_check(args)

        if args.adapter.lower() not in self.adapters:
            msg = ["Adapter %r does not exist." % args.adapter.lower()]
            if self.adapters:
                msg.append("Available adapters: %s" % ", ".join(self.adapters))
            else:
                msg.append("No adapters available.")
            self.parser.error(" ".join(msg))

        if args.fuzzmanager and args.s3_fuzzmanager:
            self.parser.error("--fuzzmanager and --s3-fuzzmanager are mutually exclusive")

        if args.tool is not None and not (args.fuzzmanager or args.s3_fuzzmanager):
            self.parser.error("--tool can only be given with --fuzzmanager/--s3-fuzzmanager")
