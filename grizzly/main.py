# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from logging import basicConfig, DEBUG, getLogger

from sapphire import Sapphire

from .adapters import get as get_adapter
from .common import FilesystemReporter, FuzzManagerReporter, IOManager, S3FuzzManagerReporter
from .session import Session
from .target import load as load_target, TargetLaunchError, TargetLaunchTimeout


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = getLogger("grizzly")  # pylint: disable=invalid-name

def configure_logging(log_level):
    if log_level == DEBUG:
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

def main(args):
    configure_logging(args.log_level)
    log.info("Starting Grizzly")
    if args.fuzzmanager:
        FuzzManagerReporter.sanity_check(args.binary)
    elif args.s3_fuzzmanager:
        S3FuzzManagerReporter.sanity_check(args.binary)

    if args.ignore:
        log.info("Ignoring: %s", ", ".join(args.ignore))
    if args.xvfb:
        log.info("Running with Xvfb")
    if args.valgrind:
        log.info("Running with Valgrind. This will be SLOW!")
    if args.rr:
        log.info("Running with RR")

    adapter = None
    iomanager = None
    session = None
    target = None
    try:
        log.debug("initializing the IOManager")
        # TODO: move this into Session
        iomanager = IOManager(report_size=(max(args.cache, 0) + 1))

        log.debug("initializing Adapter %r", args.adapter)
        adapter = get_adapter(args.adapter)()

        if adapter.TEST_DURATION >= args.timeout:
            raise RuntimeError("Test duration (%ds) should be less than browser timeout (%ds)" % (
                adapter.TEST_DURATION, args.timeout))

        if adapter.RELAUNCH > 0:
            log.debug("relaunch (%d) set in Adapter", adapter.RELAUNCH)
            relaunch = adapter.RELAUNCH
        else:
            relaunch = args.relaunch

        log.debug("initializing the Target")
        target = load_target(args.platform)(
            args.binary,
            args.extension,
            args.launch_timeout,
            args.log_limit,
            args.memory,
            args.prefs,
            relaunch,
            rr=args.rr,
            valgrind=args.valgrind,
            xvfb=args.xvfb)
        adapter.monitor = target.monitor

        if args.coverage and relaunch == 1 and target.forced_close:
            # this is a workaround to avoid not dumping coverage
            # GRZ_FORCED_CLOSE=0 is also an option but the browser MUST
            # close itself.
            raise RuntimeError("Coverage must be run with --relaunch > 1")

        log.debug("calling adapter setup()")
        adapter.setup(args.input, iomanager.server_map)
        log.debug("configuring harness")
        iomanager.harness = adapter.get_harness()

        log.debug("initializing the Reporter")
        if args.fuzzmanager:
            log.info("Results will be reported via FuzzManager")
            reporter = FuzzManagerReporter(args.binary, tool=args.tool)
        elif args.s3_fuzzmanager:
            log.info("Results will be reported via FuzzManager w/ large attachments in S3")
            reporter = S3FuzzManagerReporter(args.binary, tool=args.tool)
        else:
            reporter = FilesystemReporter()
            log.info("Results will be stored in %r", reporter.report_path)

        # set 'auto_close=1' so the client error pages (code 4XX) will
        # call 'window.close()' after a second.
        # launch http server used to serve test cases
        log.debug("starting Sapphire server")
        with Sapphire(auto_close=1, timeout=args.timeout) as server:
            target.reverse(server.port, server.port)
            log.debug("initializing the Session")
            session = Session(
                adapter,
                iomanager,
                reporter,
                server,
                target,
                coverage=args.coverage)
            if args.log_level == DEBUG or args.verbose:
                display_mode = Session.DISPLAY_VERBOSE
            else:
                display_mode = Session.DISPLAY_NORMAL
            session.run(args.ignore, display_mode=display_mode)

    except KeyboardInterrupt:
        log.info("Ctrl+C detected.")
        return Session.EXIT_ABORT

    except (TargetLaunchError, TargetLaunchTimeout):
        return Session.EXIT_LAUNCH_FAILURE

    finally:
        log.warning("Shutting down...")
        if session is not None:
            log.debug("calling session.close()")
            session.close()
        if target is not None:
            log.debug("calling target.cleanup()")
            target.cleanup()
        if adapter is not None:
            log.debug("calling adapter.cleanup()")
            adapter.cleanup()
        if iomanager is not None:
            log.debug("calling iomanager.cleanup()")
            iomanager.cleanup()
        log.info("Done.")

    return Session.EXIT_SUCCESS
