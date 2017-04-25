#!/usr/bin/env python2
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
import json
import logging
import os
import shutil
import tempfile
import time

import corpman
import ffpuppet
import reporter
import sapphire

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly") # pylint: disable=invalid-name


class GrizzlyStatus(object):
    """
    GrizzlyStatus holds status information about the grizzly fuzzing process.
    """
    def __init__(self):
        self.iteration = 0
        self.results = 0
        self.test_name = None
        self._last_report = 0
        self._report_file = "grz_status_%d.json" % os.getpid()
        self._start_time = time.time()


    def clean_up(self):
        if os.path.isfile(self._report_file):
            os.remove(self._report_file)


    def report(self, report_freq=60):
        now = time.time()
        if now < (self._last_report + report_freq):
            return

        self._last_report = now
        duration = now - self._start_time
        with open(self._report_file, "w") as log_fp:
            json.dump({
                "Duration": duration,
                "Iteration": self.iteration,
                "Rate": (self.iteration/duration) if duration > 0 else 0,
                "Results": self.results}, log_fp)


def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        help="Firefox binary to run")
    parser.add_argument(
        "input",
        help="Test case or directory containing test cases")
    parser.add_argument(
        "corpus_manager",
        help="Available corpus managers: %s" % ", ".join(sorted(corpman.loader.list())))
    parser.add_argument(
        "--accepted_extensions", nargs='+',
        help="Specify a space separated list of supported file extensions... " \
             "ie: html svg (default: all)")
    parser.add_argument(
        "-c", "--cache", type=int, default=1,
        help="Maximum number of previous test cases to dump after crash (default: %(default)s)")
    parser.add_argument(
        "-e", "--extension",
        help="Install the fuzzPriv extension (specify path to funfuzz/dom/extension)")
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
        "--relaunch", type=int, default=1000,
        help="Number of iterations performed before relaunching the browser (default: %(default)s)")
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
    return parser.parse_args(args)


def main(args):
    if args.quiet and not bool(os.getenv("DEBUG")):
        logging.getLogger().setLevel(logging.WARNING)

    args.cache = max(args.cache, 1) # test case cache must be at least one
    args.memory = max(args.memory, 0)

    if args.fuzzmanager:
        reporter.FuzzManagerReporter.sanity_check(args.binary)

    log.info("Starting Grizzly")
    status = GrizzlyStatus()

    # init corpus manager
    log.debug("Initializing the corpus manager")
    corp_man = corpman.loader.get(args.corpus_manager.lower())
    if corp_man is None:
        raise RuntimeError("Invalid corpus manager type: %s" % args.corpus_manager)
    corp_man = corp_man(
        args.input,
        accepted_extensions=args.accepted_extensions)
    log.info("Found %d test cases", corp_man.size())
    if corp_man.single_pass:
        log.info("Running in REPLAY mode")
    else:
        log.info("Running in FUZZING mode")

    if (corp_man.test_duration/1000.0) >= args.timeout:
        raise RuntimeError("Test duration (%0.02fs) should be less than browser timeout (%ds)" % (
            (corp_man.test_duration/1000.0), args.timeout))

    # launch http server used to serve test cases
    log.debug("Starting sapphire server")
    serv = sapphire.Sapphire(timeout=args.timeout)

    # add include paths to server
    for url_path, target_path in corp_man.get_includes():
        serv.add_include(url_path, target_path)

    # add dynamic responses to the server
    for dr in corp_man.get_dynamic_responses():
        serv.add_dynamic_response(dr["url"], dr["callback"], dr["mime"])

    try:
        ffp = None # define ffp in case exceptions are raised on init
        wwwdir = None # directory containing test files to be served

        # create FFPuppet object
        ffp = ffpuppet.FFPuppet(
            use_valgrind=args.valgrind,
            use_windbg=args.windbg,
            use_xvfb=args.xvfb,
            detect_soft_assertions=args.asserts)

        # main fuzzing iteration loop
        while True:
            status.report()
            status.iteration += 1

            # launch FFPuppet
            if ffp.closed:
                relaunch_countdown = args.relaunch # iterations to perform before relaunch
                test_cases = [] # should contain len(cache) + 1 maximum

                if args.xvfb:
                    log.info("Running with Xvfb")

                if args.valgrind:
                    log.info("Running with Valgrind. This will be SLOW!")

                if args.windbg:
                    log.info("Collecting debug information with WinDBG")

                if args.memory:
                    log.info("Memory limit is %dMBs", args.memory)
                    if args.memory < 2048:
                        log.warning("A memory limit less than 2048MBs is not recommended")

                if args.prefs:
                    log.info("Using prefs from %s", os.path.abspath(args.prefs))
                else:
                    log.warning("Default prefs used, prefs.js file not specified")

                log.info("Launching FFPuppet")
                ffp.launch(
                    args.binary,
                    launch_timeout=args.launch_timeout,
                    location="http://127.0.0.1:%d/%s#%d" % (
                        serv.get_port(),
                        corp_man.landing_page(harness=True),
                        corp_man.test_duration),
                    memory_limit=args.memory * 1024 * 1024 if args.memory else None,
                    prefs_js=args.prefs,
                    extension=args.extension)

            # generate test case
            log.debug("calling corp_man.generate()")
            current_test = corp_man.generate(mime_type=args.mime)

            # update sapphire redirects from the corpman
            for redirect in corp_man.get_redirects():
                serv.set_redirect(redirect["url"], redirect["file_name"], redirect["required"])

            # print iteration status
            if corp_man.single_pass:
                log.info("[I%04d-L%02d-R%02d] %s",
                         status.iteration,
                         corp_man.size(),
                         status.results,
                         os.path.basename(corp_man.get_active_file_name()))
            else:
                if status.test_name != corp_man.get_active_file_name():
                    status.test_name = corp_man.get_active_file_name()
                    log.info("Now fuzzing: %s", os.path.basename(status.test_name))
                log.info("I%04d-R%02d ", status.iteration, status.results)

            # create working directory for current test case
            wwwdir = tempfile.mkdtemp(prefix="grz_test_")
            # dump test case files to filesystem to be served
            current_test.dump(wwwdir)

            # use Sapphire to serve the most recent test case
            server_status, files_served = serv.serve_path(
                wwwdir,
                continue_cb=ffp.is_running,
                optional_files=current_test.get_optional())

            # remove test case working directory
            if wwwdir and os.path.isdir(wwwdir):
                shutil.rmtree(wwwdir)

            log.debug("calling corp_man.finish_test()")
            corp_man.finish_test(ffp.clone_log, current_test, files_served)

            # only add test case to list if something was served
            # to help maintain browser/fuzzer sync
            if server_status != sapphire.SERVED_NONE:
                test_cases.append(current_test)

                # manage test case cache size
                if len(test_cases) > args.cache:
                    test_cases.pop(0)

            failure_detected = (server_status != sapphire.SERVED_ALL) or not ffp.is_running()
            log.debug("failure_detected: %r", failure_detected)

            # handle ignored timeouts
            if failure_detected and args.ignore_timeouts and ffp.is_running():
                log.info("Timeout ignored")
                ffp.close()

            # handle issues if detected
            elif failure_detected:
                status.results += 1
                log.info("Potential issue detected")
                ffp.close()

                log.debug("Current input: %s", corp_man.get_active_file_name())
                log.info("Collecting logs...")
                if args.fuzzmanager:
                    result_reporter = reporter.FuzzManagerReporter()
                    ffp.save_log(result_reporter.log_file)
                    # report with a log size limit of 128KB
                    result_reporter.report(reversed(test_cases), args.binary, log_limit=0x20000)
                else:
                    result_reporter = reporter.FilesystemReporter()
                    ffp.save_log(result_reporter.log_file)
                    result_reporter.report(reversed(test_cases))

            # trigger relaunch by closing the browser
            relaunch_countdown -= 1
            if relaunch_countdown <= 0 and ffp.is_running():
                log.info("Triggering FFP relaunch")
                ffp.close()

                # check for browser shutdown crashes
                result_reporter = reporter.FilesystemReporter(ignore_stackless=True)
                ffp.save_log(result_reporter.log_file)
                result_reporter.report(reversed(test_cases))

            # all test cases have been replayed
            if corp_man.single_pass and corp_man.size() == 0:
                log.info("Replay Complete")
                break

    except KeyboardInterrupt:
        log.warning("Iterations attempted: %d", status.iteration)

    finally:
        log.warning("Shutting down...")
        status.clean_up()

        if serv is not None:
            serv.close()

        if wwwdir and os.path.isdir(wwwdir):
            shutil.rmtree(wwwdir)

        if ffp is not None:
            # close ffp and save log
            ffp.close()
            result_reporter = reporter.FilesystemReporter(ignore_stackless=True)
            ffp.save_log(result_reporter.log_file)
            result_reporter.report(reversed(test_cases))
            ffp.clean_up()

        corp_man.close()


if __name__ == "__main__":
    log_level = logging.INFO
    log_fmt = "[%(asctime)s] %(message)s"
    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    main(parse_args())
