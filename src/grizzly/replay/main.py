# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

from FTB.Signatures.CrashInfo import CrashSignature

from sapphire import Sapphire

from ..common.cache import clear_cached
from ..common.frontend import (
    ConfigError,
    Exit,
    configure_logging,
    display_time_limits,
    get_certs,
    time_limits,
)
from ..common.plugins import load_plugin
from ..common.reporter import FailedLaunchReporter
from ..common.storage import TestCaseLoadFailure, load_testcases
from ..common.utils import package_version
from ..services import WebServices
from ..target import Target, TargetLaunchError, TargetLaunchTimeout
from .args import ReplayArgs
from .replay import ReplayManager

if TYPE_CHECKING:
    from argparse import Namespace

    from .replay import ReplayResult

LOG = getLogger(__name__)


def main(args: Namespace | None = None) -> int:
    """CLI for `grizzly.reduce`.

    Arguments:
        args: Result from `ReplayArgs.parse_args`.

    Returns:
        Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
    """
    args = args or ReplayArgs().parse_args()
    configure_logging(args.log_level)

    LOG.info("Starting Grizzly Replay")
    LOG.debug("grizzly-framework version: %s", package_version("grizzly-framework"))
    if args.display != "default":
        LOG.info("Browser display mode: %s", args.display)
    if args.ignore:
        LOG.info("Ignoring: %s", ", ".join(args.ignore))
    if args.pernosco:
        LOG.info("Running with RR (Pernosco mode)")
    elif args.rr:
        LOG.info("Running with RR")
    elif args.valgrind:
        LOG.info("Running with Valgrind. This will be SLOW!")

    signature = CrashSignature.fromFile(args.sig) if args.sig else None

    try:
        testcases, asset_mgr, env_vars = load_testcases(
            args.input, entry_point=args.entry_point
        )
    except TestCaseLoadFailure as exc:
        LOG.error("Error: %s", str(exc))
        return Exit.ERROR

    if not args.tool:
        args.tool = ReplayManager.lookup_tool(testcases) or "grizzly-replay"

    certs = None
    results: list[ReplayResult] | None = None
    target: Target | None = None
    ext_services = None
    try:
        # check if hangs are expected
        expect_hang = ReplayManager.expect_hang(args.ignore, signature, testcases)
        # calculate test time limit and timeout
        time_limit, timeout = time_limits(
            args.time_limit, args.timeout, tests=testcases
        )
        display_time_limits(time_limit, timeout, args.no_harness)
        # calculate repeat and relaunch
        repeat = max(args.min_crashes, args.repeat)
        relaunch = min(args.relaunch, repeat)
        LOG.info(
            "Repeat: %d, Minimum crashes: %d, Relaunch %d",
            repeat,
            args.min_crashes,
            relaunch,
        )
        if not args.use_http:
            certs = get_certs()
        LOG.debug("initializing the Target")
        target = load_plugin(args.platform, "grizzly_targets", Target)(
            args.binary,
            args.launch_timeout,
            args.log_limit,
            args.memory,
            certs=certs,
            display_mode=args.display,
            pernosco=args.pernosco,
            rr=args.rr,
            valgrind=args.valgrind,
        )
        assert target
        if env_vars is not None:
            LOG.debug("adding environment loaded from test case")
            target.merge_environment(env_vars)

        # use asset manager created from test case content if available
        if asset_mgr:
            target.asset_mgr = asset_mgr
            # target is now responsible for `asset_mgr`
            asset_mgr = None
        # TODO: prioritize specified assets over included
        target.asset_mgr.add_batch(args.asset)
        target.process_assets()

        if certs and not target.https():
            LOG.warning("Target does not support HTTPS, using HTTP")
            certs.cleanup()
            certs = None

        LOG.debug("starting sapphire server")
        # launch HTTP server used to serve test cases
        with Sapphire(auto_close=1, timeout=timeout, certs=certs) as server:
            if certs is not None:
                LOG.debug("starting additional web services")
                ext_services = WebServices.start_services(certs.host, certs.key)

            target.reverse(server.port, server.port)
            with ReplayManager(
                frozenset(args.ignore),
                server,
                target,
                any_crash=args.any_crash,
                relaunch=relaunch,
                signature=signature,
                use_harness=not args.no_harness,
            ) as replay:
                results = replay.run(
                    testcases,
                    time_limit,
                    expect_hang=expect_hang,
                    idle_delay=args.idle_delay,
                    idle_threshold=args.idle_threshold,
                    launch_attempts=args.launch_attempts,
                    min_results=args.min_crashes,
                    post_launch_delay=args.post_launch_delay,
                    repeat=repeat,
                    services=ext_services,
                )
        # handle results
        success = any(x.expected for x in results)
        if success:
            LOG.info("Results successfully reproduced")
        elif any(results):
            LOG.info("Results detected, signature does not match")
        else:
            LOG.info("No results detected")
        if results and (args.output or args.fuzzmanager):
            # add target assets to test cases
            if not target.asset_mgr.is_empty():
                for test in testcases:
                    test.assets = dict(target.asset_mgr.assets)
                    test.assets_path = target.asset_mgr.path
            # add target environment variables
            if target.filtered_environ():
                for test in testcases:
                    test.env_vars = target.filtered_environ()
            # report results
            if args.fuzzmanager:
                ReplayManager.report_to_fuzzmanager(results, testcases, args.tool)
            else:
                ReplayManager.report_to_filesystem(args.output, results, testcases)
        return Exit.SUCCESS if success else Exit.FAILURE

    except ConfigError as exc:
        LOG.error(str(exc))
        return exc.exit_code

    except KeyboardInterrupt:
        return Exit.ABORT

    except (TargetLaunchError, TargetLaunchTimeout) as exc:
        if isinstance(exc, TargetLaunchError) and exc.report:
            FailedLaunchReporter(args.display_launch_failures).submit([], exc.report)
        return Exit.LAUNCH_FAILURE

    finally:
        LOG.info("Shutting down...")
        if results:
            # cleanup unreported results
            for result in results:
                result.report.cleanup()
        if target is not None:
            target.cleanup()
        if asset_mgr:
            asset_mgr.cleanup()
        if certs is not None:
            certs.cleanup()
        if ext_services is not None:
            ext_services.cleanup()
        clear_cached()
        LOG.info("Done.")
