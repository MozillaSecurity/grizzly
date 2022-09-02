# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import DEBUG, getLogger
from os import getpid

from sapphire import Sapphire

from .adapter import Adapter
from .common.plugins import load as load_plugin
from .common.reporter import (
    FilesystemReporter,
    FuzzManagerReporter,
    S3FuzzManagerReporter,
)
from .common.utils import TIMEOUT_DELAY, Exit, configure_logging
from .session import Session
from .target import Target, TargetLaunchError, TargetLaunchTimeout

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


LOG = getLogger(__name__)


def main(args):
    configure_logging(args.log_level)
    LOG.info("Starting Grizzly (%d)", getpid())
    if args.fuzzmanager:
        FuzzManagerReporter.sanity_check(args.binary)
    elif args.s3_fuzzmanager:
        S3FuzzManagerReporter.sanity_check(args.binary)

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

    adapter = None
    session = None
    target = None
    try:
        LOG.debug("initializing Adapter %r", args.adapter)
        adapter = load_plugin(args.adapter, "grizzly_adapters", Adapter)(args.adapter)

        # test case time limit and timeout sanity checking
        if args.time_limit:
            time_limit = args.time_limit
        else:
            assert adapter.TIME_LIMIT >= 1
            time_limit = adapter.TIME_LIMIT
        if args.timeout:
            timeout = args.timeout
        else:
            timeout = time_limit + TIMEOUT_DELAY
        LOG.info("Using test time limit: %ds, timeout: %ds", time_limit, timeout)
        if timeout < time_limit:
            LOG.error("Timeout must be at least test time limit if not greater")
            return Exit.ARGS
        if adapter.HARNESS_FILE and time_limit == timeout:
            LOG.warning(
                "To avoid relaunches due to tests failing to close"
                " themselves use a timeout greater than time limit"
            )

        if adapter.RELAUNCH > 0:
            LOG.info("Relaunch (%d) set in Adapter", adapter.RELAUNCH)
            relaunch = adapter.RELAUNCH
        else:
            relaunch = args.relaunch

        LOG.debug("initializing the Target %r", args.platform)
        target = load_plugin(args.platform, "grizzly_targets", Target)(
            args.binary,
            args.launch_timeout,
            args.log_limit,
            args.memory,
            headless=args.headless,
            pernosco=args.pernosco,
            rr=args.rr,
            valgrind=args.valgrind,
        )
        # add specified assets
        target.assets.add_batch(args.asset)
        target.process_assets()
        adapter.monitor = target.monitor

        LOG.debug("initializing the Reporter")
        if args.fuzzmanager:
            LOG.info("Results will be reported via FuzzManager")
            reporter = FuzzManagerReporter(tool=args.tool)
        elif args.s3_fuzzmanager:
            LOG.info(
                "Results will be reported via FuzzManager w/ large attachments in S3"
            )
            reporter = S3FuzzManagerReporter(tool=args.tool)
        else:
            reporter = FilesystemReporter(args.logs / "results")
            LOG.info("Results will be stored in %r", str(reporter.report_path))
        reporter.display_logs = args.smoke_test or reporter.display_logs

        # make sure an iteration limit is set if smoke_test is True
        iteration_limit = (args.limit or 10) if args.smoke_test else args.limit
        if iteration_limit:
            LOG.info("%r iteration(s) will be attempted", iteration_limit)
        if args.runtime:
            LOG.info("Runtime is limited to %rs", args.runtime)

        # set 'auto_close=1' so the client error pages (code 4XX) will
        # call 'window.close()' after a second.
        # launch http server used to serve test cases
        LOG.debug("starting Sapphire server")
        with Sapphire(auto_close=1, timeout=timeout) as server:
            target.reverse(server.port, server.port)
            LOG.debug("initializing the Session")
            session = Session(
                adapter,
                reporter,
                server,
                target,
                coverage=args.coverage,
                enable_profiling=args.enable_profiling,
                relaunch=relaunch,
                report_limit=args.limit_reports,
                report_size=args.collect,
            )
            if args.log_level == DEBUG or args.verbose:
                display_mode = Session.DISPLAY_VERBOSE
            else:
                display_mode = Session.DISPLAY_NORMAL
            session.run(
                args.ignore,
                time_limit,
                input_path=str(args.input),
                iteration_limit=iteration_limit,
                result_limit=1 if args.smoke_test else 0,
                runtime_limit=args.runtime,
                display_mode=display_mode,
                launch_attempts=args.launch_attempts,
            )

    except KeyboardInterrupt:
        LOG.info("Ctrl+C detected.")
        return Exit.ABORT

    except (TargetLaunchError, TargetLaunchTimeout) as exc:
        LOG.error(str(exc))
        return Exit.LAUNCH_FAILURE

    finally:
        LOG.info("Shutting down...")
        if session is not None:
            LOG.debug("calling session.close()")
            session.close()
        if target is not None:
            LOG.debug("calling target.cleanup()")
            target.cleanup()
        if adapter is not None:
            LOG.debug("calling adapter.cleanup()")
            adapter.cleanup()
        LOG.info("Done.")

    if session and session.status.results.total > 0:
        return Exit.ERROR
    return Exit.SUCCESS
