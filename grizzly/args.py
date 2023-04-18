# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from argparse import ArgumentParser, HelpFormatter
from logging import CRITICAL, DEBUG, ERROR, INFO, WARNING
from os import getenv
from os.path import exists
from pathlib import Path
from platform import system

from .common.plugins import scan as scan_plugins
from .common.plugins import scan_target_assets
from .common.utils import DEFAULT_TIME_LIMIT, TIMEOUT_DELAY


# ref: https://stackoverflow.com/questions/12268602/sort-argparse-help-alphabetically
class SortingHelpFormatter(HelpFormatter):
    @staticmethod
    def __sort_key(action):
        for opt in action.option_strings:
            if opt.startswith("--"):
                return [opt]
        return action.option_strings

    def add_usage(self, usage, actions, groups, prefix=None):
        actions = sorted(actions, key=self.__sort_key)
        super().add_usage(usage, actions, groups, prefix)

    def add_arguments(self, actions):
        actions = sorted(actions, key=self.__sort_key)
        super().add_arguments(actions)


class CommonArgs:
    IGNORABLE = ("log-limit", "memory", "timeout")
    DEFAULT_IGNORE = ("log-limit", "timeout")

    def __init__(self):
        # log levels for console logging
        self._level_map = {
            "CRIT": CRITICAL,
            "ERROR": ERROR,
            "WARN": WARNING,
            "INFO": INFO,
            "DEBUG": DEBUG,
        }

        self.parser = ArgumentParser(
            formatter_class=SortingHelpFormatter, conflict_handler="resolve"
        )

        targets = scan_plugins("grizzly_targets")
        if not targets:
            self.parser.error("No Platforms (Targets) are installed")

        self.parser.add_argument("binary", type=Path, help="Firefox binary to run")
        self.parser.add_argument(
            "--log-level",
            choices=sorted(self._level_map),
            default="INFO",
            help="Configure console logging (default: %(default)s)",
        )

        # build 'asset' help string
        assets = scan_target_assets()
        asset_msg = []
        for target in sorted(assets):
            if assets[target]:
                asset_msg.append(f"{target}: {', '.join(sorted(assets[target]))}.")

        self.launcher_grp = self.parser.add_argument_group("Launcher Arguments")
        self.launcher_grp.add_argument(
            "--asset",
            action="append",
            default=[],
            metavar=("ASSET", "PATH"),
            nargs=2,
            help=f"Specify target specific asset files. {''.join(asset_msg)}",
        )
        self.launcher_grp.add_argument(
            "-e",
            "--extension",
            help="DEPRECATED. Install an extension. Specify the path to the xpi or the"
            " directory containing the unpacked extension.",
        )
        self.launcher_grp.add_argument(
            "--display-launch-failures",
            action="store_true",
            help="Output launch failure logs to console. (default: %(default)s)",
        )
        headless_choices = ["default"]
        if system().startswith("Linux"):
            headless_choices.append("xvfb")
        self.launcher_grp.add_argument(
            "--headless",
            choices=headless_choices,
            const="default",
            default="default" if self.is_headless() else None,
            nargs="?",
            help="Headless mode. 'default' uses browser's built-in headless mode.",
        )
        self.launcher_grp.add_argument(
            "--launch-attempts",
            type=int,
            default=3,
            help="Number of attempts to launch the browser before LaunchError is raised"
            " (default: %(default)s)",
        )
        self.launcher_grp.add_argument(
            "--launch-timeout",
            type=int,
            default=300,
            help="Number of seconds to wait before LaunchError is raised"
            " (default: %(default)s)",
        )
        self.launcher_grp.add_argument(
            "--log-limit",
            type=int,
            default=0,
            help="Browser log file size limit in MBs (default: 'no limit')",
        )
        self.launcher_grp.add_argument(
            "-m",
            "--memory",
            type=int,
            default=0,
            help="Browser process memory limit in MBs (default: 'no limit')",
        )
        self.launcher_grp.add_argument(
            "--no-harness",
            action="store_true",
            help="Don't use the harness for redirection. Implies '--relaunch=1'.",
        )
        self.launcher_grp.add_argument(
            "--platform",
            default="ffpuppet",
            choices=sorted(targets),
            help="Target to use (default: %(default)s)",
        )
        self.launcher_grp.add_argument(
            "--post-launch-delay",
            type=int,
            default=0,
            help="Delay after launching browser before continuing. "
            "This provides an opportunity to connect debuggers. "
            ">0 - delay in seconds; 0 - continue immediately; -1 - skip. "
            "(default: %(default)s)",
        )
        self.launcher_grp.add_argument(
            "-p", "--prefs", help="DEPRECATED. prefs.js file to use"
        )
        self.launcher_grp.add_argument(
            "--relaunch",
            type=int,
            default=1000,
            help="Number of iterations performed before relaunching the browser"
            " (default: %(default)s)",
        )
        self.launcher_grp.add_argument(
            "--time-limit",
            type=int,
            default=None,
            help="Maximum expected execution time of a test case."
            " If time-limit is reached before the test case has closed"
            " the harness will attempt to close the test. If this fails for any reason"
            " '--timeout' is the fallback."
            " Browser build types and debuggers can affect the amount of time"
            " required for test case execution to complete."
            " (default: fuzzing - set by 'Adapter.TIME_LIMIT'; reduce/replay - "
            f"duration from loaded test case or minimum {DEFAULT_TIME_LIMIT}s)",
        )
        self.launcher_grp.add_argument(
            "-t",
            "--timeout",
            type=int,
            default=None,
            help="Test case execution (iteration) timeout."
            " If timeout is reached before the test case has closed"
            " the target will be closed."
            " Typically this should be '--time-limit' + a few seconds."
            f" (default: '--test-limit' + {TIMEOUT_DELAY}s)",
        )
        if system().startswith("Linux"):
            self.launcher_grp.add_argument(
                "--xvfb", action="store_true", help="DEPRECATED. Use Xvfb."
            )
        else:
            self.parser.set_defaults(xvfb=False)

        self.reporter_grp = self.parser.add_argument_group("Reporter Arguments")
        self.reporter_grp.add_argument(
            "--fuzzmanager", action="store_true", help="Report results to FuzzManager"
        )
        self.reporter_grp.add_argument(
            "--ignore",
            nargs="*",
            choices=self.IGNORABLE,
            default=self.DEFAULT_IGNORE,
            help="Result types to ignore. Pass zero args to disable. NOTE: 'memory'"
            " only applies to OOMs detected by Grizzly. (default: %(default)s)",
        )
        self.reporter_grp.add_argument(
            "-l",
            "--logs",
            default=Path.cwd(),
            type=Path,
            help="Location to save logs and test cases. (default: %(default)s)",
        )
        self.reporter_grp.add_argument(
            "--tool",
            help="Override tool name used when reporting issues to FuzzManager",
        )

        if system().startswith("Linux"):
            dbg_group = self.launcher_grp.add_mutually_exclusive_group()
            dbg_group.add_argument(
                "--pernosco",
                action="store_true",
                help="Use rr. Trace intended to be used with Pernosco.",
            )
            dbg_group.add_argument("--rr", action="store_true", help="Use rr.")
            dbg_group.add_argument(
                "--valgrind", action="store_true", help="Use Valgrind."
            )
        else:
            self.parser.set_defaults(
                pernosco=False,
                rr=False,
                valgrind=False,
            )

        self.parser.epilog = (
            "For addition help check out the wiki:"
            " https://github.com/MozillaSecurity/grizzly/wiki"
        )

    @staticmethod
    def is_headless():
        if (
            system().startswith("Linux")
            and not getenv("DISPLAY")
            and not getenv("WAYLAND_DISPLAY")
        ):
            return True
        return False

    def parse_args(self, argv=None):
        args = self.parser.parse_args(argv)
        self.sanity_check(args)
        return args

    def sanity_check(self, args):
        if not args.binary.is_file():
            self.parser.error(f"file not found: '{args.binary!s}'")

        if args.launch_attempts < 1:
            self.parser.error("--launch-attempts must be >= 1")

        args.log_level = self._level_map[args.log_level]

        if args.log_limit < 0:
            self.parser.error("--log-limit must be >= 0")
        args.log_limit *= 1_048_576

        # if logs is specified, we need it to be a directory (whether existent or not)
        if args.logs and args.logs.is_file():
            self.parser.error("--logs cannot be a file")

        if args.memory < 0:
            self.parser.error("--memory must be >= 0")
        args.memory *= 1_048_576

        if args.no_harness:
            if args.time_limit is not None:
                self.parser.error("--time-limit cannot be used with --no-harness")
            # --no-harness implies --relaunch 1
            args.relaunch = 1

        if args.relaunch < 1:
            self.parser.error("--relaunch must be >= 1")

        if args.pernosco or args.rr:
            # currently we only support rr on Linux
            settings = "/proc/sys/kernel/perf_event_paranoid"
            value = int(Path(settings).read_text())
            if value > 1:
                self.parser.error(f"rr needs {settings} <= 1, but it is {value}")

        # TODO: remove deprecated 'extension' from args
        if args.extension:  # pragma: no cover
            args.asset.append(["extension", args.extension])

        # TODO: remove deprecated 'prefs' from args
        if args.prefs:  # pragma: no cover
            args.asset.append(["prefs", args.prefs])

        # check args.platform before args.asset since it is used
        if args.asset:
            supported_assets = scan_target_assets()[args.platform]
            for asset, path in args.asset:
                if not supported_assets or asset not in supported_assets:
                    self.parser.error(
                        f"Asset {asset!r} not supported by target {args.platform!r}"
                    )
                if not exists(path):
                    self.parser.error(
                        f"Failed to add asset {asset!r} cannot find {path!r}"
                    )

        if args.time_limit is not None and args.time_limit < 1:
            self.parser.error("--time-limit must be >= 1")

        if args.timeout is not None and args.timeout < 0:
            self.parser.error("--timeout must be >= 0")

        if args.time_limit and args.timeout and args.timeout < args.time_limit:
            self.parser.error("--timeout must be >= --time-limit")

        if args.tool:
            if not args.fuzzmanager:
                self.parser.error("--tool requires --fuzzmanager")
            if len(args.tool.split()) != 1 or args.tool.strip() != args.tool:
                self.parser.error("--tool cannot contain whitespace")

        if args.xvfb:  # pragma: no cover
            args.headless = "xvfb"


class GrizzlyArgs(CommonArgs):
    def __init__(self):
        super().__init__()

        adapters = scan_plugins("grizzly_adapters")
        if not adapters:
            self.parser.error("No Adapters are installed")

        self.parser.add_argument(
            "adapter", choices=sorted(adapters), help="Adapter to use."
        )
        self.parser.add_argument(
            "--enable-profiling",
            action="store_true",
            help="Record profiling data. The data can be viewed by running the"
            " status reporter while running Grizzly.",
        )
        self.parser.add_argument(
            "-i",
            "--input",
            type=Path,
            help="Test case or directory containing test cases.",
        )
        self.parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Maximum number of iterations to be performed. (default: 'no limit')",
        )
        self.parser.add_argument(
            "--smoke-test",
            action="store_true",
            help="Perform a small number of iterations to check if everything is"
            " working as expected. Exit immediately if a result is found.",
        )
        self.parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Output console updates every iteration. By default the number"
            " of iterations between console updates doubles each update."
            " Updates are always printed when a result is detected or the"
            " target is relaunched.",
        )

        self.launcher_grp.add_argument(
            "--coverage", action="store_true", help="Enable coverage collection."
        )
        self.launcher_grp.add_argument(
            "--runtime",
            type=int,
            default=0,
            help="Maximum runtime in seconds. Checked after each iteration."
            " (default: 'no limit')",
        )

        self.reporter_grp.add_argument(
            "-c",
            "--collect",
            type=int,
            default=1,
            help="Maximum number of test cases to include in the report."
            " (default: %(default)s)",
        )
        self.reporter_grp.add_argument(
            "--limit-reports",
            type=int,
            default=5,
            help="Maximum number of times a unique result will be submitted."
            " This includes results submitted by parallel and previously run"
            " (within 24h) processes. This can help avoid spamming duplicate results."
            " The first time a result is seen it will always be submitted."
            " (default: %(default)s) - Use 0 for 'no limit'",
        )

    def sanity_check(self, args):
        super().sanity_check(args)

        if args.collect < 1:
            self.parser.error("--collect must be greater than 0")

        if args.input and not args.input.exists():
            self.parser.error(f"'{args.input}' does not exist")

        if args.limit < 0:
            self.parser.error("--limit must be >= 0")

        if args.limit_reports < 0:
            self.parser.error("--limit-reports must be >= 0")

        if args.runtime < 0:
            self.parser.error("--runtime must be >= 0")

        if args.smoke_test:
            if args.limit == 0:
                # set iteration limit for smoke-test
                args.limit = 10
