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
import shutil
import tempfile

from ffpuppet import BrowserTerminatedError
import sapphire

from . import corpman, reporter
from .status import Status
from .target import Target

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]


log = logging.getLogger("grizzly")  # pylint: disable=invalid-name


class Session(object):
    FM_LOG_SIZE_LIMIT = 0x40000  # max log size for log sent to FuzzManager (256KB)
    TARGET_LOG_SIZE_WARN = 0x1900000  # display warning when target log files exceed limit (25MB)

    def __init__(self, cache_size, coverage, ignore, target, working_path=None):
        self.adapter = None
        self.binary = None
        self.cache_size = max(cache_size, 1)  # testcase cache must be at least one
        self.coverage = coverage  # TODO: this should become part of the adapter???
        self.ignore = ignore
        self.mime = None  # TODO: this should become part of adapter
        self.reporter = None
        self.server = None
        self.status = Status()
        self.target = target
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
        elif self.coverage:
            log.info("Running in GCOV mode")
            self.adapter.rotation_period = 1 # cover as many test cases as possible
        else:
            log.info("Running in FUZZING mode")

        if (self.adapter.test_duration/1000.0) >= iteration_timeout:
            raise RuntimeError("Test duration (%0.02fs) should be less than browser timeout (%ds)" % (
                (self.adapter.test_duration/1000.0), iteration_timeout))


    def config_server(self, iteration_timeout):
        log.debug("initializing the server")
        assert self.server is None
        assert self.adapter is not None, "adapter must be configured first"
        log.debug("starting sapphire server")
        # have client error pages (code 4XX) call window.close() after a few seconds
        sapphire.Sapphire.CLOSE_CLIENT_ERROR = 2
        # launch http server used to serve test cases
        self.server = sapphire.Sapphire(timeout=iteration_timeout)
        # add include paths to server
        for url_path, target_path in self.adapter.srv_map.includes:
            self.server.add_include(url_path, target_path)
        # add dynamic responses to the server
        for dyn_rsp in self.adapter.srv_map.dynamic_responses:
            self.server.add_dynamic_response(dyn_rsp["url"], dyn_rsp["callback"], dyn_rsp["mime"])


    def close(self):
        self.status.cleanup()
        if self.server is not None:
            self.server.close()
        if self.wwwdir and os.path.isdir(self.wwwdir):
            shutil.rmtree(self.wwwdir)
        if self.target is not None:
            self.target.cleanup()
        if self.adapter is not None:
            self.adapter.cleanup()
        if self.target.use_rr:
            if self.target.rr_path is not None and os.path.isdir(self.target.rr_path):
                shutil.rmtree(self.target.rr_path)


    def process_result(self):
        self.status.results += 1
        log.info("Potential issue detected")
        log.debug("Current input: %s", self.adapter.active_file)
        log.info("Reporting results...")
        # create working directory for current testcase
        result_logs = tempfile.mkdtemp(prefix="grz_logs_", dir=self.working_path)
        if self.target.use_rr:
            # symlink the RR trace into the log path so the Reporter can detect it
            # and process if needed.
            rrtrace = None
            if self.target.rr_path is not None:
                rrtrace = os.path.realpath(os.path.join(self.target.rr_path, "latest-trace"))
                if not os.path.isdir(rrtrace):
                    rrtrace = None
            if rrtrace is not None:
                os.symlink(rrtrace, os.path.join(result_logs, "rr-trace"))
            else:
                log.warning("RR specified but no trace detected.")
        self.target.save_logs(result_logs, meta=True)
        self.reporter.submit(result_logs, reversed(self.test_cache))
        if os.path.isdir(result_logs):
            shutil.rmtree(result_logs)


    def run(self):
        assert self.adapter is not None, "adapter is not configured"
        assert self.reporter is not None, "reporter is not configured"
        assert self.server is not None, "server is not configured"

        while True:  # main fuzzing iteration loop
            self.status.report()
            self.status.iteration += 1

            # launch FFPuppet
            if self.target.closed:
                try:
                    self.test_cache = list()
                    location = "http://127.0.0.1:%d/%s#timeout=%d,close_after=%d" % (
                        self.server.get_port(),
                        self.adapter.landing_page(harness=True),
                        self.adapter.test_duration,
                        self.target.rl_reset)
                    log.info("Launching target")
                    self.target.launch(location)
                    # TODO: handle BrowserTimeoutError?
                except BrowserTerminatedError:
                    # this result likely has nothing to do with grizzly
                    self.process_result()
                    raise

            # generate testcase
            log.debug("calling self.adapter.generate()")
            current_test = self.adapter.generate(mime_type=self.mime)
            if self.target.prefs is not None:
                current_test.add_environ_file(self.target.prefs, fname="prefs.js")

            # update sapphire redirects from the corpman
            for redirect in self.adapter.srv_map.redirects:
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

            # use Sapphire to serve the most recent test case
            server_status, files_served = self.server.serve_path(
                self.wwwdir,
                continue_cb=self.target._puppet.is_healthy,
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

            # attempt to detect a failure
            failure_detected = self.target.detect_failure(
                self.ignore,
                server_status == sapphire.SERVED_TIMEOUT)

            # handle failure if detected
            if failure_detected == Target.RESULT_FAILURE:
                self.process_result()
            elif failure_detected == Target.RESULT_IGNORED:
                self.status.ignored += 1
                log.info("Ignored (%d)", self.status.ignored)


            # warn about large browser logs
            self.status.log_size = self.target.log_size()
            if self.status.log_size > self.TARGET_LOG_SIZE_WARN:
                log.warning("Large browser logs: %dMBs", (self.status.log_size/0x100000))

            if self.coverage:
                self.target.dump_coverage()

            # trigger relaunch by closing the browser if needed
            self.target.check_relaunch()

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
    elif args.s3_fuzzmanager:
        reporter.S3FuzzManagerReporter.sanity_check(args.binary)

    if args.ignore:
        log.info("Ignoring: %s", ", ".join(args.ignore))

    # TODO: should these prints move?
    if args.xvfb:
        log.info("Running with Xvfb")
    if args.valgrind:
        log.info("Running with Valgrind. This will be SLOW!")
    if args.rr:
        log.info("Running with RR")

    target = Target(
        args.binary,
        args.extension,
        args.launch_timeout,
        args.log_limit,
        args.memory,
        args.prefs,
        args.relaunch,
        args.rr,
        args.valgrind,
        args.xvfb)

    session = Session(
        args.cache,
        args.coverage,
        args.ignore,
        target,
        working_path=args.working_path)

    try:
        session.config_adapter(
            args.corpus_manager,
            args.input,
            args.timeout,
            accepted_extensions=args.accepted_extensions)
        session.config_server(args.timeout)

        if args.fuzzmanager:
            log.info("Reporting issues via FuzzManager")
            session.reporter = reporter.FuzzManagerReporter(
                args.binary,
                log_limit=Session.FM_LOG_SIZE_LIMIT)
        elif args.s3_fuzzmanager:
            log.info("Reporting issues via FuzzManager w/ large attachments in S3")
            session.reporter = reporter.S3FuzzManagerReporter(
                args.binary,
                log_limit=Session.FM_LOG_SIZE_LIMIT)
        else:
            session.reporter = reporter.FilesystemReporter()

        session.adapter.br_mon.monitor_instance(session.target._puppet)

        # detect soft assertions
        if args.asserts:
            session.target._puppet.add_abort_token("###!!! ASSERTION:")

        # add tokens from corpus manager
        for token in session.adapter.abort_tokens:
            session.target._puppet.add_abort_token(token)

        session.run()

    except KeyboardInterrupt:
        log.warning("Iterations attempted: %d", session.status.iteration)

    finally:
        log.warning("Shutting down...")
        session.close()
