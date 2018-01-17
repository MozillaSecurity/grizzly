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
import logging
import os
import shutil
import signal
import tempfile

import corpman
from ffpuppet import FFPuppet
import reporter
import sapphire
from status import Status

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly") # pylint: disable=invalid-name


def parse_args(argv=None):
    aval_corpmans = sorted(corpman.loader.list())
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        help="Firefox binary to run")
    parser.add_argument(
        "input",
        help="Test case or directory containing test cases")
    parser.add_argument(
        "corpus_manager",
        help="Available corpus managers: %s" % ", ".join(aval_corpmans))
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
        "--gcov-iterations", type=int, default=None,
        help="Run only the specified amount of iterations and dump GCOV data every iteration.")
    parser.add_argument(
        "--ignore-timeouts", action="store_true",
        help="Don't save the logs/results from a timeout")
    parser.add_argument(
        "--launch-timeout", type=int, default=300,
        help="Number of seconds to wait before LaunchError is raised (default: %(default)s)")
    parser.add_argument(
        "--log-limit", type=int,
        help="Log file size limit in MBs (default: 'no limit')")
    parser.add_argument(
        "-m", "--memory", type=int,
        help="Browser process memory limit in MBs (default: 'no limit') -- requires psutil")
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
        help="Use Valgrind (Linux only)")
    parser.add_argument(
        "-w", "--working-path",
        help="Working directory. Intended to be used with ram-drives." \
             " (default: %r)" % tempfile.gettempdir())
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use Xvfb (Linux only)")

    args = parser.parse_args(argv)

    if not os.path.isfile(args.binary):
        parser.error("%r does not exist" % args.binary)

    if not os.path.exists(args.input):
        parser.error("%r does not exist" % args.input)
    elif os.path.isdir(args.input) and not os.listdir(args.input):
        parser.error("%r is empty" % args.input)

    if args.corpus_manager.lower() not in aval_corpmans:
        parser.error("%r corpus manager does not exist" % args.corpus_manager.lower())

    if args.extension is not None and not os.path.exists(args.extension):
        parser.error("%r does not exist" % args.extension)

    if args.prefs is not None and not os.path.isfile(args.prefs):
        parser.error("%r does not exist" % args.prefs)

    if args.working_path is not None and not os.path.isdir(args.working_path):
        parser.error("%r is not a directory" % args.working_path)

    return args


class Session(object):
    FM_LOG_SIZE_LIMIT = 0x40000  # max log size for log sent to FuzzManager (256KB)
    TARGET_LOG_SIZE_WARN = 0x1900000  # display warning when target log files exceed limit (25MB)

    def __init__(self, cache_size, gcov_iters, ignore_timeouts, log_limit, memory_limit, relaunch, working_path=None):
        self.adapter = None
        self.binary = None
        self.cache_size = max(cache_size, 1)  # testcase cache must be at least one
        self.extension = None  # TODO: this should become part of the target
        self.gcov_iterations = gcov_iters  # TODO: this should become part of the adapter
        self.ignore_timeouts = ignore_timeouts
        self.launch_timeout = None  # TODO: this should become part of the target
        self.log_limit = max(log_limit * 1024 * 1024, 0) if log_limit else 0  # maximum log size limit
        self.memory_limit = max(memory_limit * 1024 * 1024, 0) if memory_limit else 0 # target's memory limit
        self.mime = None  # TODO: this should become part of adapter
        self.prefs = None  # TODO: this should become part of the target
        self.reporter = None
        self.rl_countdown = 0  # TODO: this should become part of the target
        self.rl_reset = max(relaunch, 1)  # iterations to perform before relaunch... TODO: this should become part of the target
        self.server = None
        self.status = Status()
        self.target = None
        self.test_cache = list()  # should contain len(cache) + 1 maximum
        self.wwwdir = None  # directory containing test files to be served
        self.working_path = working_path  # where test files will be stored


    def config_adapter(self, name, input_path, iteration_timeout, accepted_extensions=None, mime_type=None):
        log.debug("initializing the adapter")
        assert self.adapter is None
        self.mime = mime_type

        adpt_const = corpman.loader.get(name.lower())
        if adpt_const is None:
            raise RuntimeError("Invalid corpus manager %r" % name)

        self.adapter = adpt_const(
            input_path,
            accepted_extensions=accepted_extensions)

        log.info("Found %d test cases", self.adapter.size())
        if self.adapter.single_pass:
            log.info("Running in REPLAY mode")
        elif self.gcov_iterations is not None:
            log.info("Running in GCOV mode")
            self.adapter.rotation_period = 1 # cover as many test cases as possible
        else:
            log.info("Running in FUZZING mode")

        if (self.adapter.test_duration/1000.0) >= iteration_timeout:
            raise RuntimeError("Test duration (%0.02fs) should be less than browser timeout (%ds)" % (
                (self.adapter.test_duration/1000.0), iteration_timeout))


    def config_target(self, binary, prefs, extension, launch_timeout, use_valgrind, use_xvfb):
        log.debug("initializing the target")
        assert self.target is None
        # TODO: target will be an abstraction in the future
        # do not allow network connections to non local endpoints
        os.environ["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1"

        self.binary = binary
        self.extension = extension
        self.launch_timeout = launch_timeout
        assert self.binary is not None and os.path.isfile(self.binary)

        if prefs is not None:
            self.prefs = os.path.abspath(prefs)
            assert os.path.isfile(self.prefs)
            log.info("Using prefs from %r", self.prefs)

        if use_xvfb:
            log.info("Running with Xvfb")
        if use_valgrind:
            log.info("Running with Valgrind. This will be SLOW!")

        # create FFPuppet object
        self.target = FFPuppet(
            use_valgrind=use_valgrind,
            use_xvfb=use_xvfb)


    def config_server(self, iteration_timeout):
        log.debug("initializing the server")
        assert self.server is None
        assert self.adapter is not None, "adapter must be configured first"
        log.debug("starting sapphire server")
        # launch http server used to serve test cases
        self.server = sapphire.Sapphire(timeout=iteration_timeout)
        # add include paths to server
        for url_path, target_path in self.adapter.includes:
            self.server.add_include(url_path, target_path)
        # add dynamic responses to the server
        for dyn_rsp in self.adapter.dynamic_responses:
            self.server.add_dynamic_response(dyn_rsp["url"], dyn_rsp["callback"], dyn_rsp["mime"])


    def close(self):
        self.status.cleanup()
        if self.server is not None:
            self.server.close()
        if self.wwwdir and os.path.isdir(self.wwwdir):
            shutil.rmtree(self.wwwdir)
        if self.target is not None:
            self.target.clean_up()
        if self.adapter is not None:
            self.adapter.cleanup()


    def launch_target(self):
        self.rl_countdown = self.rl_reset
        self.test_cache = list()

        log.info("Launching target")
        self.target.launch(
            self.binary,
            launch_timeout=self.launch_timeout,
            location="http://127.0.0.1:%d/%s#timeout=%d,close_after=%d" % (
                self.server.get_port(),
                self.adapter.landing_page(harness=True),
                self.adapter.test_duration,
                self.rl_reset),
            log_limit=self.log_limit,
            memory_limit=self.memory_limit,
            prefs_js=self.prefs,
            extension=self.extension)


    def run(self):
        assert self.adapter is not None, "adapter is not configured"
        assert self.reporter is not None, "reporter is not configured"
        assert self.server is not None, "server is not configured"
        assert self.target is not None, "target is not configured"

        while True:  # main fuzzing iteration loop
            self.status.report()
            self.status.iteration += 1

            if self.gcov_iterations is not None:
                # If at this point, the browser is running, i.e. we did neither
                # relaunch nor crash/timeout, then we need to signal the browser
                # to dump coverage before attempting a new test that potentially
                # crashes.
                # Note: This is not required if we closed or are going to close
                # the browser (relaunch or done with all iterations) because the
                # SIGTERM will also trigger coverage to be synced out.

                # TODO: maybe this should use relaunch=1 and self close every iteration
                if self.target.is_running():
                    log.info("GCOV: Dumping coverage data...")
                    os.kill(self.target._proc.pid, signal.SIGUSR1)

                if self.status.iteration > self.gcov_iterations:
                    log.info("GCOV: Finished with iterations, terminating...")
                    break

            # launch FFPuppet
            if self.target.closed:
                self.launch_target()

            # generate testcase
            log.debug("calling self.adapter.generate()")
            current_test = self.adapter.generate(mime_type=self.mime)
            if self.prefs is not None:
                current_test.add_environ_file(self.prefs, fname="prefs.js")

            # update sapphire redirects from the corpman
            for redirect in self.adapter.redirects:
                self.server.set_redirect(redirect["url"], redirect["file_name"], redirect["required"])

            # print iteration status
            if self.adapter.single_pass:
                log.info("[I%04d-L%02d-R%02d] %s",
                         self.status.iteration,
                         self.adapter.size(),
                         self.status.results,
                         os.path.basename(self.adapter.active_file))
            else:
                if self.status.test_name != self.adapter.active_file:
                    self.status.test_name = self.adapter.active_file
                    log.info("Now fuzzing: %s", os.path.basename(self.status.test_name))
                log.info("I%04d-R%02d ", self.status.iteration, self.status.results)

            # create working directory for current test case
            self.wwwdir = tempfile.mkdtemp(prefix="grz_test_", dir=self.working_path)
            # dump test case files to filesystem to be served
            current_test.dump(self.wwwdir)

            # decrement relaunch countdown
            self.rl_countdown -= 1
            # use Sapphire to serve the most recent test case
            server_status, files_served = self.server.serve_path(
                self.wwwdir,
                continue_cb=self.target.is_running,
                optional_files=current_test.get_optional())

            # remove test case working directory
            if self.wwwdir and os.path.isdir(self.wwwdir):
                shutil.rmtree(self.wwwdir)

            log.debug("calling self.adapter.finish_test()")
            self.adapter.finish_test(current_test, files_served)

            # only add test case to list if something was served
            # to help maintain browser/fuzzer sync
            if files_served:
                self.test_cache.append(current_test)
                # manage test case cache size
                if len(self.test_cache) > self.cache_size:
                    self.test_cache.pop(0)

            if self.rl_countdown < 1 and server_status != sapphire.SERVED_TIMEOUT:
                # if the corpus manager does not use the default harness
                # chances are it will hang here for 60 seconds
                log.debug("relaunch will be triggered... waiting 60 seconds")
                self.target.wait(60)
                if self.target.is_running():
                    log.warning("Target should have closed itself")

            # attempt to detect a failure
            failure_detected = False
            if not self.target.is_running():
                self.target.close()
                if self.target.reason == FFPuppet.RC_EXITED and self.target.returncode == 0:
                    log.info("Target closed itself")
                else:
                    log.debug("failure detected")
                    failure_detected = True
            elif server_status == sapphire.SERVED_TIMEOUT:
                log.debug("timeout detected")
                self.target.close()
                # handle ignored timeouts
                if self.ignore_timeouts:
                    self.status.ignored += 1
                    log.info("Timeout ignored (%d)", self.status.ignored)
                else:
                    failure_detected = True

            # handle failure if detected
            if failure_detected:
                self.status.results += 1
                log.info("Potential issue detected")
                log.debug("Current input: %s", self.adapter.active_file)
                log.info("Reporting results...")
                # create working directory for current testcase
                result_logs = tempfile.mkdtemp(prefix="grz_logs_", dir=self.working_path)
                self.target.save_logs(result_logs)
                self.reporter.report(result_logs, reversed(self.test_cache))
                if os.path.isdir(result_logs):
                    shutil.rmtree(result_logs)

            # warn about large browser logs
            self.status.log_size = self.target.log_length("stderr") + self.target.log_length("stdout")
            if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                log.warning("Large browser logs: %dMBs", (self.status.log_size/1048576))

            # trigger relaunch by closing the browser
            if self.rl_countdown < 1 and self.target.is_running():
                log.info("Forcing target relaunch")
                self.target.close()

            # all test cases have been replayed
            if self.adapter.single_pass and self.adapter.size() == 0:
                log.info("Replay Complete")
                break


def main(args):
    if args.quiet and not bool(os.getenv("DEBUG")):
        logging.getLogger().setLevel(logging.WARNING)

    log.info("Starting Grizzly")
    if args.fuzzmanager:
        reporter.FuzzManagerReporter.sanity_check(args.binary)

    session = Session(
        args.cache,
        args.gcov_iterations,
        args.ignore_timeouts,
        args.log_limit,
        args.memory,
        args.relaunch,
        working_path=args.working_path)

    try:
        session.config_adapter(
            args.corpus_manager,
            args.input,
            args.timeout,
            accepted_extensions=args.accepted_extensions)
        session.config_server(args.timeout)
        session.config_target(
            args.binary,
            args.prefs,
            args.extension,
            args.launch_timeout,
            args.valgrind,
            args.xvfb)

        if args.fuzzmanager:
            log.info("Reporting issues via FuzzManager")
            session.reporter = reporter.FuzzManagerReporter(
                args.binary,
                log_limit=Session.FM_LOG_SIZE_LIMIT)
        else:
            session.reporter = reporter.FilesystemReporter()

        session.adapter.br_mon.monitor_instance(session.target)

        # detect soft assertions
        if args.asserts:
            session.target.add_abort_token("###!!! ASSERTION:")

        # add tokens from corpus manager
        for token in session.adapter.abort_tokens:
            session.target.add_abort_token(token)

        session.run()

    except KeyboardInterrupt:
        log.warning("Iterations attempted: %d", session.status.iteration)

    finally:
        log.warning("Shutting down...")
        session.close()


if __name__ == "__main__":
    log_level = logging.INFO
    log_fmt = "[%(asctime)s] %(message)s"
    if bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    main(parse_args())
