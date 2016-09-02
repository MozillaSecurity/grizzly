#!/usr/bin/env python
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

import argparse
import logging
import os
import time

import corpman
import ffpuppet
import reporter
import sapphire

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly") # pylint: disable=invalid-name


if __name__ == "__main__":

    if len(logging.getLogger().handlers) == 0:
        logging.basicConfig()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        help="Firefox binary to run")
    parser.add_argument(
        "input",
        help="Test case or directory containing test cases")
    parser.add_argument(
        "corpus_manager",
        help="Available corpus managers: %s" % ", ".join(sorted(corpman.managers)))
    parser.add_argument(
        "-a", "--aggression", default=0.001, type=float,
        help="0.001 == 1/1000 (default: %(default)s)")
    parser.add_argument(
        "-c", "--cache", type=int, default=1,
        help="Maximum number of previous test cases to dump after crash (default: %(default)s)")
    parser.add_argument(
        "--fuzzmanager", action="store_true",
        help="Report results to FuzzManager")
    parser.add_argument(
        "--ignore-timeouts", action="store_true",
        help="Don't save the logs/results from a timeout")
    parser.add_argument(
        "--launch-timeout", type=int, default=300,
        help="Number of seconds to wait before LaunchError is raised (default: %(default)s)")
    parser.add_argument(
        '-m', '--memory', type=int,
        help='Browser process memory limit in MBs (default: No limit)')
    parser.add_argument(
        "--mime",
        help="Specify a mime type")
    parser.add_argument(
        "-p", "--prefs",
        help="prefs.js file to use")
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Output is minimal")
    parser.add_argument(
        "--replay", action="store_true",
        help="Replay do not fuzz the test cases")
    parser.add_argument(
        "--relaunch", type=int, default=1000,
        help="Number of iterations performed before relaunching the browser (default: %(default)s)")
    parser.add_argument(
        "--rotate", type=int, default=10,
        help="Number of iterations per test case before rotating (default: %(default)s)")
    parser.add_argument(
        "-s", "--asserts", action="store_true",
        help="Detect soft assertions")
    parser.add_argument(
        "-t", "--timeout", type=int, default=60,
        help="Iteration timeout in seconds (default: %(default)s)")
    parser.add_argument(
        "--valgrind", action="store_true",
        help="Use valgrind")
    parser.add_argument(
        "--windbg", action="store_true",
        help="Collect crash log with WinDBG (Windows only)")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use xvfb (Linux only)")
    args = parser.parse_args()

    if not args.quiet:
        logging.getLogger().setLevel(logging.INFO)

    args.cache = max(args.cache, 1) # test case cache must be at least one

    if args.fuzzmanager:
        reporter.FuzzManagerReporter.sanity_check(args.binary)

    log.info("%s Starting Grizzly", time.strftime("[%Y-%m-%d %H:%M:%S]"))

    current_iter = 0
    ffp = None

    # init corpus manager
    try:
        corp_man = corpman.managers[args.corpus_manager.lower()]
    except KeyError:
        raise RuntimeError("Invalid corpus manager type: %s" % args.corpus_manager)
    corp_man = corp_man(
        args.input,
        aggression=args.aggression,
        is_replay=args.replay,
        rotate=args.rotate
    )

    log.info("Found %d test cases", corp_man.size())
    if args.replay:
        log.info("Running in REPLAY mode")
    else:
        log.info("Running in FUZZING mode")

    # launch http server used to serve test cases
    serv = sapphire.Sapphire(timeout=args.timeout)

    try:
        current_test = None # template/test case currently being fuzzed
        test_cases = [] # test cases (this should only be > 1 when cache is > 1)
        total_results = 0 # to count number of results found

        # main fuzzing iteration loop
        while True:
            # create firefox puppet instance if needed
            if ffp is None or not ffp.is_running():
                test_cases = [] # reset test case cache
                log_offset = 0 # location in the log used for log scanning
                iters_before_relaunch = args.relaunch # iterations to perform before relaunch

                if args.xvfb:
                    log.info("Running with Xvfb")

                if args.valgrind:
                    log.info("Running with Valgrind. This will be SLOW!")

                if args.windbg:
                    log.info("Collecting debug information with WinDBG")

                args.memory = max(args.memory, 0)
                if args.memory:
                    log.info("Memory limit is %dMBs", args.memory)
                    if args.memory < 2048:
                        log.warning("A memory limit less than 2048MBs is not recommended")

                if args.prefs:
                    log.info("Using prefs from %s", os.path.abspath(args.prefs))
                else:
                    log.warning("Default prefs used, prefs.js file not specified")

                log.info("%s Launching FFPuppet", time.strftime("[%Y-%m-%d %H:%M:%S]"))

                # create FFPuppet object
                ffp = ffpuppet.FFPuppet(
                    use_valgrind=args.valgrind,
                    use_windbg=args.windbg,
                    use_xvfb=args.xvfb)

                if args.asserts:
                    ffp.add_abort_token("###!!! ASSERTION:")

                # launch FFPuppet
                ffp.launch(
                    args.binary,
                    launch_timeout=args.launch_timeout,
                    location="http://127.0.0.1:%d/%s" % (serv.get_port(), serv.landing_page),
                    memory_limit=args.memory * 1024 * 1024 if args.memory else None,
                    prefs_js=args.prefs)

            current_iter += 1

            # generate test case
            test_cases.append(corp_man.generate(serv.done_page, mime_type=args.mime))

            # manage test case cache size
            if len(test_cases) > args.cache:
                test_cases.pop(0)

            # print iteration status
            if args.replay:
                log.info("[I%04d-L%02d-R%03d] %s",
                         current_iter,
                         corp_man.size(),
                         total_results,
                         os.path.basename(corp_man.get_active_file_name()))
            else:
                if current_test != corp_man.get_active_file_name():
                    current_test = corp_man.get_active_file_name()
                    log.info("Now fuzzing: %s", os.path.basename(current_test))
                log.info("%s I%04d-R%03d ",
                         time.strftime("[%Y-%m-%d %H:%M:%S]"),
                         current_iter,
                         total_results)

            # use Sapphire to serve the test case and
            # if both the test case and the verification (done)
            # pages are served serve_testcase() returns true
            failure_detected = not serv.serve_testcase(
                test_cases[-1].data,
                is_alive_cb=ffp.is_running)

            # handle ignored timeouts
            if failure_detected and ffp.is_running() and args.ignore_timeouts:
                ffp.close()
                ffp.clean_up()
                failure_detected = False
                log.info("Timeout ignored")

            # handle issues if detected
            elif failure_detected:
                total_results += 1
                log.info("Potential issue detected")
                log.info("Current input: %s", corp_man.get_active_file_name())
                log.info("Collecting logs...")

                # close ffp and report results
                ffp.close()
                if args.fuzzmanager:
                    result_reporter = reporter.FuzzManagerReporter()
                    ffp.save_log(result_reporter.log_file)
                    result_reporter.report(reversed(test_cases), args.binary)
                else:
                    result_reporter = reporter.FilesystemReporter()
                    ffp.save_log(result_reporter.log_file)
                    result_reporter.report(reversed(test_cases))
                ffp.clean_up()

            # trigger relaunch by closing the browser
            iters_before_relaunch -= 1
            if iters_before_relaunch <= 0 and ffp.is_running():
                log.info("Triggering FFP relaunch")

                ffp.close()
                result_reporter = reporter.FilesystemReporter(ignore_stackless=True)
                ffp.save_log(result_reporter.log_file)
                result_reporter.report(reversed(test_cases))
                ffp.clean_up()

            # all test cases have been replayed
            if args.replay and corp_man.size() == 0:
                log.info("Replay Complete")
                break

    except KeyboardInterrupt:
        log.warning("Completed %d iterations", current_iter)

    finally:
        log.warning("Shutting down...")
        if serv is not None:
            serv.close()

        if ffp is not None:
            # close ffp and save log
            ffp.close()
            result_reporter = reporter.FilesystemReporter(ignore_stackless=True)
            ffp.save_log(result_reporter.log_file)
            result_reporter.report(reversed(test_cases))
            ffp.clean_up()
