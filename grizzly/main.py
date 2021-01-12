# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import basicConfig, DEBUG, getLogger
from os.path import join as pathjoin
from os import getcwd

from sapphire import Sapphire

from .adapters import get as get_adapter
from .common.iomanager import IOManager
from .common.reporter import FilesystemReporter, FuzzManagerReporter, S3FuzzManagerReporter
from .common.utils import grz_tmp
from .session import Session
from .target import load as load_target, TargetLaunchError, TargetLaunchTimeout


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


LOG = getLogger(__name__)

def configure_logging(log_level):
    if log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=log_level)

def main(args):
    configure_logging(args.log_level)
    LOG.info("Starting Grizzly")
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
    elif args.valgrind:
        LOG.info("Running with Valgrind. This will be SLOW!")

    adapter = None
    iomanager = None
    session = None
    target = None
    try:
        LOG.debug("initializing the IOManager")
        # TODO: move this into Session
        iomanager = IOManager(report_size=(max(args.cache, 0) + 1))

        LOG.debug("initializing Adapter %r", args.adapter)
        adapter = get_adapter(args.adapter)()

        if args.timeout <= adapter.TEST_DURATION:
            LOG.info("Using minimum adapter timeout: %ds", adapter.TEST_DURATION)
            if adapter.HARNESS_FILE:
                LOG.info("To avoid Target relaunches due to tests failing to close"
                         " themselves use a timeout > 'adapter.TEST_DURATION'")
            timeout = adapter.TEST_DURATION
        else:
            timeout = args.timeout

        if adapter.RELAUNCH > 0:
            LOG.info("Relaunch (%d) set in Adapter", adapter.RELAUNCH)
            relaunch = adapter.RELAUNCH
        else:
            relaunch = args.relaunch

        LOG.debug("initializing the Target")
        target = load_target(args.platform)(
            args.binary,
            args.extension,
            args.launch_timeout,
            args.log_limit,
            args.memory,
            rr=args.rr,
            valgrind=args.valgrind,
            xvfb=args.xvfb)
        if args.prefs:
            target.prefs = args.prefs
            LOG.info("Using prefs %r", args.prefs)
        adapter.monitor = target.monitor

        LOG.debug("calling adapter setup()")
        adapter.setup(args.input, iomanager.server_map)
        LOG.debug("configuring harness")
        iomanager.harness = adapter.get_harness()

        LOG.debug("initializing the Reporter")
        if args.fuzzmanager:
            LOG.info("Results will be reported via FuzzManager")
            reporter = FuzzManagerReporter(tool=args.tool)
        elif args.s3_fuzzmanager:
            LOG.info("Results will be reported via FuzzManager w/ large attachments in S3")
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
                iomanager,
                reporter,
                server,
                target,
                coverage=args.coverage,
                relaunch=relaunch)
            if args.log_level == DEBUG or args.verbose:
                display_mode = Session.DISPLAY_VERBOSE
            else:
                display_mode = Session.DISPLAY_NORMAL
            session.run(
                args.ignore,
                iteration_limit=args.limit,
                display_mode=display_mode)

    except KeyboardInterrupt:
        LOG.info("Ctrl+C detected.")
        return Session.EXIT_ABORT

    except (TargetLaunchError, TargetLaunchTimeout) as exc:
        LOG.error(str(exc))
        if isinstance(exc, TargetLaunchError) and exc.report:
            path = grz_tmp("launch_failures")
            LOG.error("Logs can be found here %r", path)
            reporter = FilesystemReporter(path, major_bucket=False)
            reporter.submit([], exc.report)
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
        if iomanager is not None:
            LOG.debug("calling iomanager.cleanup()")
            iomanager.cleanup()
        LOG.info("Done.")

    return Session.EXIT_SUCCESS
