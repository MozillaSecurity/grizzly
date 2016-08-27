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
import os
import random
import re
import socket
import time

import corpman
import ffpuppet
import reporter
import sapphire

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        help="Firefox binary to run")
    parser.add_argument(
        "input",
        help="Test case or directory containing test cases")
    parser.add_argument(
        "corpus_manager",
        help="Supported corpus managers: %s" % ", ".join(corpman.managers))
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
        "--timeout", type=int, default=60,
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

    args.cache = max(args.cache, 1) # test case cache must be at least one

    if args.fuzzmanager:
        reporter.FuzzManagerReporter.sanity_check(args.binary)

    if not args.quiet:
        print("%s Starting Grizzly" % time.strftime("[%Y-%m-%d %H:%M:%S]"))

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

    if not args.quiet:
        print("Found %d test cases" % (corp_man.size()))
        if args.replay:
            print("Running in REPLAY mode")
        else:
            print("Running in FUZZING mode")

    # launch http server used to serve test cases
    serv = None
    while serv is None:
        # find an unused port and avoid blocked ports
        # see: dxr.mozilla.org/mozilla-central/source/netwerk/base/nsIOService.cpp
        listening_port = random.randint(0x2000, 0xFFFF)
        try:
            serv = sapphire.Sapphire(port=listening_port, timeout=args.timeout)
        except socket.error as e:
            if e.errno == 98: # Address already in use
                serv = None
                continue
            raise e

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

                if not args.quiet:
                    if args.xvfb:
                        print("Running with Xvfb")

                    if args.valgrind:
                        print("Running with Valgrind. This will be SLOW!")

                    if args.windbg:
                        print("Collecting debug information with WinDBG")

                    args.memory = max(args.memory, 0)
                    if args.memory:
                        print("Memory limit is %dMBs" % args.memory)
                        if args.memory < 2048:
                            print("WARNING: A memory limit less than 2048MBs is not recommended")

                    if args.prefs:
                        print("Using prefs from %s" % os.path.abspath(args.prefs))
                    else:
                        print("WARNING: Default prefs used, prefs.js file not specified")

                    print("%s Launching FFPuppet" % time.strftime("[%Y-%m-%d %H:%M:%S]"))

                # create and launch ffpuppet
                ffp = ffpuppet.FFPuppet(
                    use_valgrind=args.valgrind,
                    use_windbg=args.windbg,
                    use_xvfb=args.xvfb)
                ffp.launch(
                    args.binary,
                    launch_timeout=args.launch_timeout,
                    location="http://127.0.0.1:%d/%s" % (listening_port, serv.landing_page),
                    memory_limit=args.memory * 1024 * 1024 if args.memory else None,
                    prefs_js=args.prefs)

            current_iter += 1

            # generate test case
            test_cases.append(corp_man.generate(serv.done_page, mime_type=args.mime))

            # manage test case cache size
            if len(test_cases) > args.cache:
                test_cases.pop(0)

            # print iteration status
            if not args.quiet:
                if args.replay:
                    print("[I%04d-L%02d-R%03d] %s" % (
                        current_iter,
                        corp_man.size(),
                        total_results,
                        os.path.basename(corp_man.get_active_file_name())
                    ))
                else:
                    if current_test != corp_man.get_active_file_name():
                        current_test = corp_man.get_active_file_name()
                        print("Now fuzzing: %s" % os.path.basename(current_test))
                    print("%s I%04d-R%03d " % (
                        time.strftime("[%Y-%m-%d %H:%M:%S]"),
                        current_iter,
                        total_results
                    ))

            # use Sapphire to serve the test case and
            # if both the test case and the verification (done)
            # pages are served serve_testcase() returns true
            failure_detected = not serv.serve_testcase(
                test_cases[-1].data,
                is_alive_cb=ffp.is_running
            )

            # detect error/failure messages in logs
            if not failure_detected and (args.asserts or args.valgrind) and ffp.is_running():
                log_contents = ffp.read_log(log_offset)
                if args.asserts and log_contents.find("###!!! ASSERTION:") != -1:
                    # detected non-crashing assertions
                    failure_detected = True
                    if not args.quiet:
                        print("Soft assertion detected")
                elif args.valgrind and re.search(r"==\d+==\s", log_contents):
                    # detected valgrind output in log
                    failure_detected = True
                    if not args.quiet:
                        print("Valgrind detected issues")
                else:
                    log_offset += len(log_contents)
            elif not ffp.is_running():
                failure_detected = True
                if not args.quiet:
                    print("Potential crash detected")
            elif failure_detected and not args.quiet and ffp.is_running():
                if not args.quiet:
                    print("Timeout detected")
                if args.ignore_timeouts:
                    if not args.quiet:
                        print("Timeout ignored")
                    ffp.close()
                    failure_detected = False

            # handle crashes or failures if detected
            if failure_detected:
                total_results += 1
                if not args.quiet:
                    print("Current input: %s" % corp_man.get_active_file_name())
                    print("Collecting logs...")

                # wait for process to dump logs
                if not args.quiet and ffp.is_running():
                    print("Process is still running! Terminating.")

                # close ffp and report results
                if args.fuzzmanager:
                    result_reporter = reporter.FuzzManagerReporter()
                    ffp.close(result_reporter.log_file)
                    result_reporter.report(reversed(test_cases), args.binary)
                else:
                    result_reporter = reporter.FilesystemReporter()
                    ffp.close(result_reporter.log_file)
                    result_reporter.report(reversed(test_cases))

            # trigger relaunch by closing the browser
            iters_before_relaunch -= 1
            if iters_before_relaunch <= 0 and ffp is not None:
                if not args.quiet:
                    print("Triggering FFP relaunch")

                result_reporter = reporter.FilesystemReporter(ignore_stackless=True)
                ffp.close(result_reporter.log_file)
                result_reporter.report(reversed(test_cases))

            # all test cases have been replayed
            if args.replay and corp_man.size() == 0:
                if not args.quiet:
                    print("Replay Complete")
                break

    except KeyboardInterrupt:
        print("Completed %d iterations" % current_iter)

    finally:
        print("Shutting down...")
        if serv is not None:
            serv.close()

        if ffp is not None:
            # close ffp and save log
            result_reporter = reporter.FilesystemReporter(ignore_stackless=True)
            ffp.close(result_reporter.log_file)
            result_reporter.report(reversed(test_cases))
