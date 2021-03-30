# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import DEBUG, getLogger
from os import getcwd, getpid
from os.path import join as pathjoin

from sapphire import Sapphire

from .adapter import Adapter
from .common.plugins import load as load_plugin
from .common.reporter import (
    FilesystemReporter,
    FuzzManagerReporter,
    S3FuzzManagerReporter,
)
from .common.utils import TIMEOUT_DELAY, configure_logging
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

    if args.ignore:
        LOG.info("Ignoring: %s", ", ".join(args.ignore))
    if args.xvfb:
        LOG.info("Running with Xvfb")
    if args.rr:
        LOG.info("Running with RR")
    if args.valgrind:
        LOG.info("Running with Valgrind. This will be SLOW!")

    adapter = None
    session = None
    target = None
    try:
        LOG.debug("initializing Adapter %r", args.adapter)
        adapter = load_plugin(args.adapter, "grizzly_adapters", Adapter)(args.adapter)

        # test time limit and timeout sanity checking
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
            return Session.EXIT_ARGS
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
            args.extension,
            args.launch_timeout,
            args.log_limit,
            args.memory,
            rr=args.rr,
            valgrind=args.valgrind,
            xvfb=args.xvfb,
        )
        if args.prefs:
            target.prefs = args.prefs
            LOG.info("Using prefs %r", args.prefs)
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
            reporter = FilesystemReporter(pathjoin(getcwd(), "results"))
            LOG.info("Results will be stored in %r", reporter.report_path)

        if args.limit > 0:
            LOG.info("%r iteration(s) will be attempted", args.limit)

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
                report_size=args.collect,
            )
            if args.log_level == DEBUG or args.verbose:
                display_mode = Session.DISPLAY_VERBOSE
            else:
                display_mode = Session.DISPLAY_NORMAL
            session.run(
                args.ignore,
                time_limit,
                input_path=args.input,
                iteration_limit=args.limit,
                display_mode=display_mode,
            )

    except KeyboardInterrupt:
        LOG.info("Ctrl+C detected.")
        return Session.EXIT_ABORT

    except (TargetLaunchError, TargetLaunchTimeout) as exc:
        LOG.error(str(exc))
        return Session.EXIT_LAUNCH_FAILURE

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

    return Session.EXIT_SUCCESS
