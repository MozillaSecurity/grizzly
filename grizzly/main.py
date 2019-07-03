# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Grizzly is a general purpose browser fuzzer made of up of multiple modules. The
intention is to create a platform that can be extended by the creation of corpus
managers to fuzz different components of the browsers.

Grizzly is not meant to be much more than the automation glue code between
the modules.

A corpus manager is used to wrap an existing fuzzer to allow it to be run with
grizzly. Corpus managers take the content output by fuzzers and transform it
into a format that can be served to and processed by a browser.

Support for different browser can be added by the creation of a browser "puppet"
module (see ffpuppet). TODO: Implement generic "puppet" support.
"""

import logging
import os

import grizzly.adapters
from .args import GrizzlyArgs
from .common import FilesystemReporter, FuzzManagerReporter, IOManager, S3FuzzManagerReporter
from .session import Session
from .target import load as load_target, TargetLaunchError, TargetLaunchTimeout


__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


def console_init_logging():
    log_level = logging.INFO
    log_fmt = "[%(asctime)s] %(message)s"
    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)


def console_main():
    console_init_logging()
    grizzly.adapters.load()
    return main(GrizzlyArgs().parse_args())


def main(args):
    # NOTE: grizzly.reduce.reduce.main mirrors this pretty closely
    #       please check if updates here should go there too
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
        iomanager = IOManager(
            report_size=(max(args.cache, 0) + 1),
            mime_type=args.mime,
            working_path=args.working_path)

        log.debug("initializing Adapter %r", args.adapter)
        adapter = grizzly.adapters.get(args.adapter)()

        if adapter.TEST_DURATION >= args.timeout:
            raise RuntimeError("Test duration (%ds) should be less than browser timeout (%ds)" % (
                adapter.TEST_DURATION, args.timeout))

        if args.input:
            iomanager.scan_input(
                args.input,
                accepted_extensions=args.accepted_extensions,
                sort=adapter.ROTATION_PERIOD == 0)
        log.info("Found %d input files(s)", len(iomanager.input_files))

        if adapter.ROTATION_PERIOD == 0:
            log.info("Running in SINGLE PASS mode")
        elif args.coverage:
            log.info("Running in COVERAGE mode")
            # cover as many test cases as possible
            adapter.ROTATION_PERIOD = 1
        else:
            log.info("Running in FUZZING mode")

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
        if args.soft_asserts:
            target.add_abort_token("###!!! ASSERTION:")

        log.debug("calling adapter setup()")
        adapter.setup(iomanager.server_map)
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

        log.debug("initializing the Session")
        if bool(os.getenv("DEBUG")):
            display_mode = Session.DISPLAY_VERBOSE
        else:
            display_mode = Session.DISPLAY_NORMAL
        session = Session(
            adapter,
            args.coverage,
            args.ignore,
            iomanager,
            reporter,
            target,
            display_mode=display_mode)

        session.config_server(args.timeout)
        target.reverse(session.server.get_port(), session.server.get_port())

        session.run()

    except KeyboardInterrupt:
        return Session.EXIT_ABORT

    except (TargetLaunchError, TargetLaunchTimeout):
        return Session.EXIT_LAUNCH_FAILURE

    finally:
        log.warning("Shutting down...")
        if session is not None:
            session.close()
        if target is not None:
            target.cleanup()
        if adapter is not None:
            adapter.cleanup()
        if iomanager is not None:
            iomanager.cleanup()

    return Session.EXIT_SUCCESS
