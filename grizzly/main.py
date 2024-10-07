# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import annotations

from logging import DEBUG, getLogger
from os import getpid
from typing import TYPE_CHECKING, cast

from sapphire import CertificateBundle, Sapphire

from .adapter import Adapter
from .common.plugins import load_plugin
from .common.reporter import (
    FailedLaunchReporter,
    FilesystemReporter,
    FuzzManagerReporter,
    Reporter,
)
from .common.utils import (
    Exit,
    configure_logging,
    display_time_limits,
    package_version,
    time_limits,
)
from .session import LogRate, Session
from .target import Target, TargetLaunchError, TargetLaunchTimeout

if TYPE_CHECKING:
    from argparse import Namespace

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


LOG = getLogger(__name__)


def main(args: Namespace) -> int:
    """CLI for `grizzly`.

    Arguments:
        args: Result from `GrizzlyArgs.parse_args`.

    Returns:
        Exit.SUCCESS (0) for success otherwise a different Exit code is returned.
    """
    configure_logging(args.log_level)

    LOG.info("Starting Grizzly (%d)", getpid())
    LOG.debug("grizzly-framework version: %s", package_version("grizzly-framework"))

    if args.headless:
        LOG.info("Running browser headless (%s)", args.headless)
    if args.ignore:
        LOG.info("Ignoring: %s", ", ".join(args.ignore))
    if args.pernosco:
        LOG.info("Running with RR (Pernosco mode)")
    elif args.rr:
        LOG.info("Running with RR")
    elif args.valgrind:
        LOG.info("Running with Valgrind. This will be SLOW!")

    adapter: Adapter | None = None
    certs: CertificateBundle | None = None
    complete_with_results = False
    target: Target | None = None
    try:
        LOG.debug("initializing Adapter %r", args.adapter)
        adapter = cast(
            Adapter,
            load_plugin(args.adapter, "grizzly_adapters", Adapter)(args.adapter),
        )

        # calculate time limit and timeout
        time_limit, timeout = time_limits(
            args.time_limit, args.timeout, default_limit=adapter.TIME_LIMIT
        )
        display_time_limits(time_limit, timeout, args.no_harness)

        if adapter.RELAUNCH > 0:
            LOG.info("Relaunch (%d) set in Adapter", adapter.RELAUNCH)
            relaunch: int = adapter.RELAUNCH
        else:
            relaunch = args.relaunch

        if not args.use_http:
            certs = CertificateBundle.create()

        LOG.debug("initializing the Target %r", args.platform)
        target = cast(
            Target,
            load_plugin(args.platform, "grizzly_targets", Target)(
                args.binary,
                args.launch_timeout,
                args.log_limit,
                args.memory,
                certs=certs,
                headless=args.headless,
                pernosco=args.pernosco,
                rr=args.rr,
                valgrind=args.valgrind,
            ),
        )
        # add specified assets
        target.asset_mgr.add_batch(args.asset)
        target.process_assets()
        adapter.monitor = target.monitor

        if certs and not target.https():
            LOG.warning("Target does not support HTTPS, using HTTP")
            certs.cleanup()
            certs = None

        LOG.debug("initializing the Reporter")
        if args.fuzzmanager:
            tool = args.tool or f"grizzly-{adapter.name}"
            reporter: Reporter = FuzzManagerReporter(tool)
            LOG.info("Results will be reported via FuzzManager (%s)", tool)
        else:
            report_path = args.output / "results"
            reporter = FilesystemReporter(report_path)
            LOG.info("Results will be stored in '%s'", report_path.resolve())
        reporter.display_logs = args.smoke_test or reporter.display_logs

        if args.limit:
            LOG.info("%r iteration(s) will be attempted", args.limit)
        if args.runtime:
            LOG.info("Runtime is limited to %rs", args.runtime)

        # set 'auto_close=1' so the client error pages (code 4XX) will
        # call 'window.close()' after a second.
        # launch http server used to serve test cases
        LOG.debug("starting Sapphire server")
        with Sapphire(auto_close=1, timeout=timeout, certs=certs) as server:
            target.reverse(server.port, server.port)
            LOG.debug("initializing the Session")
            with Session(
                adapter,
                reporter,
                server,
                target,
                coverage=args.coverage,
                enable_profiling=args.enable_profiling,
                relaunch=relaunch,
                report_limit=args.limit_reports,
                report_size=args.collect,
            ) as session:
                if args.log_level == DEBUG or args.verbose:
                    log_rate = LogRate.VERBOSE
                else:
                    log_rate = LogRate.NORMAL
                session.run(
                    set(args.ignore),
                    time_limit,
                    input_path=str(args.input.resolve()) if args.input else None,
                    iteration_limit=args.limit,
                    no_harness=args.no_harness,
                    result_limit=1 if args.smoke_test else 0,
                    runtime_limit=args.runtime,
                    log_rate=log_rate,
                    launch_attempts=args.launch_attempts,
                    post_launch_delay=args.post_launch_delay,
                )
                complete_with_results = session.status.results.total > 0

    except KeyboardInterrupt:
        LOG.info("Ctrl+C detected.")
        return Exit.ABORT

    except (TargetLaunchError, TargetLaunchTimeout) as exc:
        if isinstance(exc, TargetLaunchError) and exc.report:
            FailedLaunchReporter(args.display_launch_failures).submit([], exc.report)
        return Exit.LAUNCH_FAILURE

    finally:
        LOG.info("Shutting down...")
        if target is not None:
            LOG.debug("calling target.cleanup()")
            target.cleanup()
        if adapter is not None:
            LOG.debug("calling adapter.cleanup()")
            adapter.cleanup()
        if certs is not None:
            certs.cleanup()
        LOG.info("Done.")

    if complete_with_results:
        return Exit.ERROR
    return Exit.SUCCESS
