# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import annotations

import json
from locale import LC_ALL, setlocale
from logging import getLogger
from typing import TYPE_CHECKING

from FTB.Signatures.CrashInfo import CrashSignature

from sapphire import Sapphire

from ..common.cache import clear_cached
from ..common.frontend import (
    ConfigError,
    Exit,
    configure_logging,
    get_certs,
    time_limits,
)
from ..common.plugins import load_plugin
from ..common.reporter import FailedLaunchReporter
from ..common.storage import TestCase, TestCaseLoadFailure, load_testcases
from ..common.utils import package_version
from ..replay import ReplayManager
from ..services import WebServices
from ..target import AssetManager, Target, TargetLaunchError, TargetLaunchTimeout
from .args import ReduceArgs
from .core import ReduceManager
from .exceptions import GrizzlyReduceBaseException

if TYPE_CHECKING:
    from argparse import Namespace


LOG = getLogger(__name__)


def main(args: Namespace | None = None) -> int:
    """CLI for `grizzly.reduce`.

    Arguments:
        args: Result from `ReduceArgs.parse_args`.

    Returns:
        Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
    """
    # pylint: disable=too-many-return-statements
    args = args or ReduceArgs().parse_args()
    configure_logging(args.log_level)
    setlocale(LC_ALL, "")

    LOG.info("Starting Grizzly Reduce")
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

    asset_mgr: AssetManager | None = None
    certs = None
    ext_services = None
    signature = None
    signature_desc = None
    target: Target | None = None
    testcases: list[TestCase] = []

    try:
        testcases, asset_mgr, env_vars = load_testcases(args.input, catalog=True)

        if args.sig:
            signature = CrashSignature.fromFile(args.sig)
            meta = args.sig.with_suffix(".metadata")
            if meta.is_file():
                meta = json.loads(meta.read_text())
                signature_desc = meta["shortDescription"]

        if not args.tool:
            args.tool = ReplayManager.lookup_tool(testcases) or "grizzly-reduce"
            LOG.info("Setting default --tool=%s", args.tool)

        expect_hang = ReplayManager.expect_hang(args.ignore, signature, testcases)

        # check test time limit and timeout
        # TODO: add support for test time limit, use timeout in both cases for now
        _, timeout = time_limits(args.timeout, args.timeout, tests=testcases)
        args.repeat = max(args.min_crashes, args.repeat)
        relaunch = min(args.relaunch, args.repeat)

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
        # prioritize specified assets over included
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
            with ReduceManager(
                frozenset(args.ignore),
                server,
                target,
                testcases,
                args.strategies,
                args.output,
                any_crash=args.any_crash,
                expect_hang=expect_hang,
                idle_delay=args.idle_delay,
                idle_threshold=args.idle_threshold,
                reducer_crash_id=args.original_crash_id,
                relaunch=relaunch,
                report_period=args.report_period,
                report_to_fuzzmanager=args.fuzzmanager,
                signature=signature,
                signature_desc=signature_desc,
                static_timeout=args.static_timeout,
                tool=args.tool,
                use_analysis=not args.no_analysis,
                use_harness=not args.no_harness,
                services=ext_services,
            ) as mgr:
                return_code = mgr.run(
                    repeat=args.repeat,
                    launch_attempts=args.launch_attempts,
                    min_results=args.min_crashes,
                    post_launch_delay=args.post_launch_delay,
                )
        return return_code

    except ConfigError as exc:
        LOG.error(str(exc))
        return exc.exit_code

    except KeyboardInterrupt:
        LOG.error("Aborted.")
        return Exit.ABORT

    except (TargetLaunchError, TargetLaunchTimeout) as exc:
        if isinstance(exc, TargetLaunchError) and exc.report:
            FailedLaunchReporter(args.display_launch_failures).submit([], exc.report)
        return Exit.LAUNCH_FAILURE

    except TestCaseLoadFailure as exc:
        LOG.error("Error: %s", str(exc))
        return Exit.ERROR

    except GrizzlyReduceBaseException as exc:
        LOG.error(exc.msg)
        return exc.code

    except Exception:  # pylint: disable=broad-except
        LOG.exception("Exception during reduction!")
        return Exit.ERROR

    finally:
        LOG.info("Shutting down...")
        if target is not None:
            target.cleanup()
        for testcase in testcases:
            testcase.cleanup()
        if asset_mgr:
            asset_mgr.cleanup()
        if certs is not None:
            certs.cleanup()
        if ext_services is not None:
            ext_services.cleanup()
        clear_cached()
        LOG.info("Done.")
