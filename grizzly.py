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

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

import argparse
import hashlib
import os
import random
import re
import shutil
import socket
import struct
import tempfile
import time

import corpman
import ffpuppet
import sapphire
import stack_hasher


def capture_logs(log_file, ignore_stackless=False, results_path="results"):
    """
    capture_logs(log_file[, ignore_stackless, results_path])
    Read log from browsers and bucket results on the file system. This is meant for local use.
    If ignore_stackless is True logs with stacks that cannot be parsed are ignored.
    results_path specifies where to store the results on the file system.
    """

    # parse log file
    with open(log_file) as fp:
        stack = stack_hasher.stack_from_text(fp.read())

    # calculate bucket data
    minor = stack_hasher.stack_to_hash(stack)
    if minor is None:
        if ignore_stackless:
            return None
        minor = "0"
        major = "NO_STACK"

        # !!!
        # hack for stagefright asserts for now...
        with open(log_file) as fp:
            # only scan the last bit of the log
            fp.seek(0, os.SEEK_END)
            seek_back = min(2048, fp.tell()) * -1
            fp.seek(seek_back, os.SEEK_END)
            try:
                # grab last line
                line = fp.read().splitlines()[-1]
            except IndexError:
                line = None
        if line and line.startswith("A/"):
            line = line.split("):")[-1].strip().split()[0] # get the file name and line number
            major = "NO_STACK_%s" % (hashlib.sha1(line).hexdigest())
        # end hack for stagefright

    else:
        major = stack_hasher.stack_to_hash(stack, major=True)

    # create results directory
    results_dir = os.path.join(os.getcwd(), results_path)
    if not os.path.isdir(results_dir):
        os.mkdir(results_dir)

    # create major bucket
    major_dir = os.path.join(results_dir, major)
    if not os.path.isdir(major_dir):
        os.mkdir(major_dir)

    # create file name without the extension
    file_name = "%s_%s" % (minor[:8], time.strftime("%Y-%m-%d_%H-%M-%S"))
    output_name = os.path.join(major_dir, file_name)

    # save log file
    shutil.move(log_file, ".".join([output_name, "log.txt"]))

    return (major_dir, file_name)


def create_tmp_log():
    fd, temp_log = tempfile.mkstemp(
        dir=".",
        prefix="grizzly_",
        suffix="_log.txt"
    )
    os.close(fd)

    return temp_log


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
        help="0.001 == 1/1000")
    parser.add_argument(
        "-c", "--cache", type=int, default=0,
        help="Maximum number of previous test cases to dump after crash")
    parser.add_argument(
        "--ignore-timeouts", action="store_true",
        help="Don't save the logs/results from a timeout")
    parser.add_argument(
        "--launch-timeout", type=int, default=300,
        help="Amount of time to wait to launch the browser before LaunchException is raised")
    parser.add_argument(
        '-l', '--log',
        help="log file name")
    parser.add_argument(
        '-m', '--memory', type=int,
        help='Firefox process memory limit in MBs')
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
        help="Number of iterations to perform before closing and relaunching the browser")
    parser.add_argument(
        "--rotate", type=int, default=10,
        help="Number of iterations per test case before switching")
    parser.add_argument(
        "-s", "--asserts", action="store_true",
        help="Detect soft assertions")
    parser.add_argument(
        "--timeout", type=int, default=60,
        help="Iteration timeout")
    parser.add_argument(
        "--valgrind", action="store_true",
        help="Use valgrind")
    parser.add_argument(
        "--windbg", default=False, action="store_true",
        help="Collect crash log with WinDBG (Windows only)")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use xvfb (Linux only)")
    args = parser.parse_args()

    if not args.quiet:
        print("%s Starting Grizzly" % time.strftime("[%Y-%m-%d %H:%M:%S]"))

    ffp = None
    current_iter = 0

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
        random.seed(struct.unpack("q", os.urandom(8))[0])

        current_test = None # template/test case currently being fuzzed
        total_results = 0 # to count number of results found

        # main fuzzing iteration loop
        while True:
            # create firefox puppet instance if needed
            if ffp is None:
                cache = [] # previously run tests
                log_offset = 0 # location in the log used for log scanning
                iters_before_relaunch = args.relaunch # iterations to perform before relaunch

                if not args.quiet:
                    if args.xvfb:
                        print("Running with Xvfb")

                    if args.valgrind:
                        print("Running with Valgrind. This will be SLOW!")

                    if args.windbg:
                        print("Collecting debug information with WinDBG")

                    if args.memory:
                        print("Memory limit is %dMBs" % args.memory)

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
            corp_man.generate(media_type=args.mime, redirect_page=serv.done_page)

            # print iteration status
            if not args.quiet:
                if args.replay:
                    print("[I%04d-L%02d-R%03d] %s" % (
                        current_iter,
                        corp_man.size(),
                        total_results,
                        os.path.basename(corp_man.get_test_case_fname())
                    ))
                else:
                    if current_test != corp_man.get_test_case_fname():
                        current_test = corp_man.get_test_case_fname()
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
                corp_man.get_test_case_data(),
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
                    ffp = None
                    failure_detected = False

            # handle crashes or failures if detected
            if failure_detected:
                total_results += 1
                if not args.quiet:
                    print("Current input: %s" % corp_man.get_test_case_fname())
                    print("Collecting logs...")

                # wait for process to dump logs
                if not args.quiet and ffp.is_running():
                    print("Process is still running! Terminating.")

                # close ffp and save log
                browser_log = create_tmp_log()
                ffp.close(browser_log)
                ffp = None

                # collect log
                log_dir, file_prefix = capture_logs(browser_log)
                corp_man.dump(log_dir, file_prefix)

                if args.cache:
                    output_name = os.path.join(log_dir, file_prefix)
                    for prev_test in range(len(cache)):
                        # save html test page
                        with open(".".join(["%s_%d" % (output_name, prev_test), "html"]), "w") as fp:
                            fp.write(cache[prev_test])

            # trigger relaunch by closing the browser
            iters_before_relaunch -= 1
            if iters_before_relaunch <= 0 and ffp is not None:
                if not args.quiet:
                    print("Triggering FFP relaunch")

                browser_log = create_tmp_log()
                ffp.close(browser_log)
                ffp = None

                # check for shutdown crash
                if capture_logs(browser_log, ignore_stackless=True) is not None:
                    total_results += 1
                    if not args.quiet:
                        print("Crash detected during close before relaunch!")

                # remove log if we don't find anything interesting
                if os.path.isfile(browser_log):
                    os.remove(browser_log)

            # all test cases have been replayed
            if args.replay and corp_man.size() == 0:
                if not args.quiet:
                    print("Replay Complete")
                break

            # store test case if no crash was detected
            if args.cache > 0:
                cache.append(corp_man.get_test_case_data())
                if len(cache) > args.cache:
                    cache.pop(0)


    except KeyboardInterrupt:
        print("Completed %d iterations" % current_iter)

    finally:
        print("Shutting down...")
        if serv is not None:
            serv.close()

        if ffp is not None:
            browser_log = args.log
            if browser_log is None:
                browser_log = create_tmp_log()
            ffp.close(browser_log)

            # check for shutdown crash
            if capture_logs(browser_log, ignore_stackless=True) is not None:
                print("Log saved: %s" % browser_log)

            # remove log if we don't want it saved
            if args.log is None and os.path.isfile(browser_log):
                os.remove(browser_log)
