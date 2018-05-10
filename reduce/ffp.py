#!/usr/bin/env python2
# coding=utf-8
"""
Interesting script to use FFPuppet/Sapphire for fast reduction using lithium.
"""
import argparse
import glob
import hashlib
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import threading
import psutil

from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo, CrashSignature
import ffpuppet
import sapphire


log = logging.getLogger("ffp_interesting")  # pylint: disable=invalid-name


HARNESS = r"""<!DOCTYPE html>
<html>
<head>
<meta charset=UTF-8>
<title>&#x1f43b; &sdot; Grizzly &sdot; &#x1f98a;</title>
<script>
let limit_tmr, closed_tmr, sub, time_limit = Number(location.hash.substr(1));
let req_url = '/first_test';
let prev_url = null;
if (time_limit <= 0) {
  dump('No time limit given, using default of 5s\n');
  time_limit = 5000;
} else {
  dump('Using time limit of ' + time_limit + '\n');
}
let main = function(){
  let is_done = false;
  sub = open(req_url, 'Grizzly Fuzz');
  sub.addEventListener('beforeunload', function(){
    for (let i = 0; i < sub.frames.length; ++i) {
      if (sub.frames[i] !== sub) {
        sub.frames[i].close();
      }
    }
    closed_tmr = setInterval(function(){
      if (!is_done && sub.closed) {
        clearTimeout(limit_tmr);
        clearInterval(closed_tmr);
        is_done = true;
        dump('Test case closed itself\n');
        setTimeout(main, 0);
      }
    }, 10);
  });
  limit_tmr = setTimeout(function(){
    if (!is_done) {
      clearInterval(closed_tmr);
      is_done = true;
      dump('Time limit exceeded\n');
      let cur_loc = null;
      if (!sub.closed && sub.location != null){
        cur_loc = sub.location.toString();
      }
      if (cur_loc != null && cur_loc == prev_url){
        // TODO: figure out why this happens
        dump('Potential browser/fuzzer sync issue detected\n');
        dump('Continued to request: ' + cur_loc + '\n');
        prev_url = null;
        req_url = '/first_test';
      }
      else {
        prev_url = cur_loc;
      }
      if (!sub.closed){
        dump('Closing test case\n');
        sub.close();
      }
      setTimeout(main, 0);
    }
  }, time_limit);
  req_url = '/next_test';
};
window.onload = main;
window.addEventListener('beforeunload', function(){
  clearInterval(closed_tmr);
  clearTimeout(limit_tmr);
  dump('Cleaning up\n');
  if (!sub.closed) {
    sub.close();
  }
});
</script>
</head>
</html>
"""


class FFPInteresting(object):

    def __init__(self, interesting_script=False):
        if interesting_script:
            global init, interesting, cleanup  # pylint: disable=global-variable-undefined,invalid-name
            init = self.init
            interesting = self.interesting
            cleanup = self.cleanup

        self.args = None
        self.ffp = None
        self.serv = None
        self.relaunch_countdown = None
        self.stderr_pos = None
        self.stdout_pos = None
        self.program_cfg = None
        self.wwwdir = None
        self.orig_sig = None
        # alt_crash_cb (if set) will be called with args=(CrashInfo obj,) for any crashes which do not
        # match the original signature (assuming --any-crash is not set)
        self.alt_crash_cb = None
        # interesting_cb (if set) will be called without args on each iteration
        self.interesting_cb = None
        self.interesting_result_cb = None
        self.timeout_event = threading.Event()
        self.reduce_file = None
        self.no_cache = None
        self.env_mod = None

        class _all(object):  # pylint: disable=too-few-public-methods
            @staticmethod
            def __contains__(item):
                """
                use this for sapphire optional_files argument.
                always return True for 'in' except for the testcase itself
                """
                return item != self.args.testcase
        self.optional_files = _all()
        self.result_cache = {}

    def init(self, _args):
        self.args = self.parse_ffp_options(_args)
        self.program_cfg = ProgramConfiguration.fromBinary(self.args.binary)

        # create ffp object
        if self.args.environ is not None:
            self.env_mod = {}
            with open(self.args.environ) as env_fp:
                for line in env_fp:
                    line = line.rstrip()
                    if not line:
                        continue
                    key, value = line.split('=', 1)
                    if not value:
                        value = None
                    self.env_mod[key] = value

        self.ffp = ffpuppet.FFPuppet(
            use_gdb=self.args.gdb,
            use_valgrind=self.args.valgrind,
            use_xvfb=self.args.xvfb)
        self.wwwdir = os.path.dirname(os.path.realpath(self.args.testcase))
        self.args.testcase = os.path.basename(self.args.testcase)
        if self.args.sig is not None:
            with open(self.args.sig) as sig_fp:
                sig = sig_fp.read()
            self.orig_sig = CrashSignature(sig)
        self.skipped = None
        self.no_cache = self.args.no_cache
        self.reduce_file = self.args.reduce_file

    def keep_waiting(self):
        return self.ffp.is_healthy() and not self.timeout_event.is_set()

    def monitor_process(self, iteration_done_event):
        # Wait until timeout is hit before polling
        log.debug('Waiting %r before polling', self.args.timeout)
        exp_time = time.time() + self.args.timeout
        while exp_time >= time.time():
            if iteration_done_event.is_set():
                return
            time.sleep(0.1)

        pid = self.ffp.get_pid()
        if pid is not None:
            try:
                process = psutil.Process(pid)
                while not iteration_done_event.is_set():
                    log.debug('Polling process...')
                    cpu = all(process.cpu_percent(interval=0.1) <= self.args.idle_threshold
                              for _ in range(self.args.idle_poll * 10))
                    if cpu:
                        log.info('Process utilized <= %d%% CPU for %ds.  Closing!',
                                 self.args.idle_threshold, self.args.idle_poll)
                        self.timeout_event.set()
                        break
                    else:
                        time.sleep(0.1)
            except psutil.NoSuchProcess:
                log.debug('Error polling process: %d no longer exists', pid)

    def update_timeout(self, run_time):
        # If run_time is less than poll-time, update it
        log.debug('Run took %r', run_time)
        new_poll_timeout = max(10, min(run_time * 1.5, self.args.timeout))
        if new_poll_timeout < self.args.timeout:
            log.info("Updating poll timeout to: %r", new_poll_timeout)
            self.args.timeout = new_poll_timeout
        # If run_time * 2 is less than max_timeout, update it
        # in other words, decrease the timeout if this ran in less than half the timeout (floored at 10s)
        new_max_timeout = max(10, min(run_time * 2, self.args.max_timeout))
        if new_max_timeout < self.args.max_timeout:
            log.info("Updating max timeout to: %r", new_max_timeout)
            self.args.max_timeout = new_max_timeout
            if self.serv is not None:
                self.serv.close()
                self.serv = None
                # trigger relaunch with new timeout

    @property
    def location(self):
        if self.args.no_harness:
            return "http://127.0.0.1:%d/%s" % (self.serv.get_port(), self.args.testcase)
        return "http://127.0.0.1:%d/harness#%d" % (self.serv.get_port(), self.args.max_timeout * 1000)

    def interesting(self, _args, temp_prefix):
        if self.args.skip:
            if self.skipped is None:
                self.skipped = 0
            elif self.skipped < self.args.skip:
                self.skipped += 1
                return False
        n_crashes = 0
        n_tries = max(self.args.repeat, self.args.min_crashes)
        if not self.no_cache:
            with open(self.reduce_file, "rb") as test_fp:
                cache_key = hashlib.sha1(test_fp.read()).hexdigest()
            if cache_key in self.result_cache:
                result = self.result_cache[cache_key]['result']
                if result:
                    log.info("Interesting (cached)")
                    cached_prefix = self.result_cache[cache_key]['prefix']
                    for filename in glob.glob(r"%s_*" % cached_prefix):
                        suffix = os.path.basename(filename).split("_", 1)
                        shutil.copy(filename, "%s_%s" % (temp_prefix, suffix[1]))
                else:
                    log.info("Uninteresting (cached)")
                return result
        for i in range(n_tries):
            if (n_tries - i) < (self.args.min_crashes - n_crashes):
                break  # no longer possible to get min_crashes, so stop
            if self._interesting(_args, temp_prefix):
                n_crashes += 1
                if n_crashes >= self.args.min_crashes:
                    if self.interesting_result_cb is not None:
                        self.interesting_result_cb()
                    if not self.no_cache:
                        self.result_cache[cache_key] = {
                            'result': True,
                            'prefix': temp_prefix
                        }
                    return True
        if not self.no_cache:
            # No need to save the temp_prefix on uninteresting testcases
            # But let's do it anyway to stay consistent
            self.result_cache[cache_key] = {
                'result': False,
                'prefix': temp_prefix
            }
        return False

    def _interesting(self, _, temp_prefix):
        # XXX: args are not re-checked. should they be?
        result = False

        if self.interesting_cb is not None:
            self.interesting_cb()

        # launch sapphire if needed
        if self.serv is None:
            if self.args.no_harness:
                saph_timeout = self.args.max_timeout
            else:
                # wait a few extra seconds to avoid races between the harness & sapphire timing out
                saph_timeout = self.args.max_timeout + 10
            # have client error pages (code 4XX) call window.close() after a few seconds
            sapphire.Sapphire.CLOSE_CLIENT_ERROR = 2
            self.serv = sapphire.Sapphire(timeout=saph_timeout)

        # (re)launch FFPuppet
        if self.ffp.reason is not None:
            self.stderr_pos = self.stdout_pos = 0
            self.relaunch_countdown = self.args.relaunch
            # Try to launch the browser at most, 4 times
            for _ in range(4):
                try:
                    self.ffp.launch(
                        self.args.binary,
                        env_mod=self.env_mod,
                        launch_timeout=self.args.launch_timeout,
                        location=self.location,
                        memory_limit=self.args.memory * 1024 * 1024 if self.args.memory else 0,
                        prefs_js=self.args.prefs,
                        extension=self.args.extension)
                except ffpuppet.LaunchError as e:
                    time.sleep(15)
                    log.warn(str(e))
                else:
                    break

            if not self.args.no_harness:
                self.serv.add_dynamic_response("/harness", lambda: HARNESS, mime_type="text/html")
                self.serv.set_redirect("/first_test", self.args.testcase, required=True)

        try:
            start_time = time.time()
            self.timeout_event.clear()
            iteration_done_event = threading.Event()
            poll = threading.Thread(target=self.monitor_process, args=(iteration_done_event,))
            poll.start()

            if self.args.no_harness:
                # create a tmp file that will never be served
                # this will keep sapphire serving until timeout or ffpuppet exits
                tempfd, tempf = tempfile.mkstemp(prefix=".lithium-garbage-", suffix=".bin", dir=self.wwwdir)
                os.close(tempfd)
                try:
                    # serve the testcase
                    server_status, served = self.serv.serve_path(self.wwwdir,
                                                                 continue_cb=self.keep_waiting)
                finally:
                    os.unlink(tempf)
                # check if testcase was served if it can't be inferred by server_status
                if server_status not in (sapphire.SERVED_NONE, sapphire.SERVED_ALL):
                    if os.path.join(self.wwwdir, self.args.testcase) in served:
                        server_status = sapphire.SERVED_ALL

                failure_detected = True  # self.ffp.is_running() or self.ffp.wait() != 0

            else:
                self.serv.set_redirect("/next_test", self.args.testcase, required=True)
                # serve the testcase
                server_status = self.serv.serve_path(self.wwwdir,
                                                     continue_cb=self.keep_waiting,
                                                     optional_files=self.optional_files)[0]

                failure_detected = (server_status != sapphire.SERVED_ALL) or not self.ffp.is_healthy()

            log.debug("failure_detected: %r (server_status = %d, is_healthy = %r)",
                      failure_detected, server_status, self.ffp.is_healthy())

            end_time = time.time()

            # handle ignored timeouts
            if failure_detected and self.args.ignore_timeouts and self.ffp.is_healthy():
                log.info("Uninteresting: timeout ignored")
                self.ffp.close()

                # clone logs
                # don't care about offsets since ffpuppet was closed and will be reopened on next iteration
                self.ffp.clone_log("stderr", target_file="%s_stderr.txt" % temp_prefix, offset=self.stderr_pos)
                self.ffp.clone_log("stdout", target_file="%s_stdout.txt" % temp_prefix, offset=self.stdout_pos)

            # handle issues if detected
            elif failure_detected:
                self.ffp.close()

                # clone the logs
                err_fn = self.ffp.clone_log("stderr", target_file="%s_stderr.txt" % temp_prefix, offset=self.stderr_pos)
                out_fn = self.ffp.clone_log("stdout", target_file="%s_stdout.txt" % temp_prefix, offset=self.stdout_pos)

                # look for aux crash data
                best_log = None
                # regex to detect e10s forced crash
                re_e10s_forced = re.compile(r"""
                    ==\d+==ERROR:.+?SEGV\son.+?0x[0]+\s\(.+?T2\).+?
                    #0\s+0x[0-9a-f]+\sin\s+mozilla::ipc::MessageChannel::OnChannelErrorFromLink
                    """, re.DOTALL | re.VERBOSE)
                for log_id in self.ffp.available_logs():
                    if log_id in {"stderr", "stdout"}:
                        continue
                    if "asan" in log_id:
                        asan_fn = self.ffp.clone_log(log_id)
                        try:
                            with open(asan_fn, "r") as log_fp:
                                if re_e10s_forced.search(log_fp.read(4096)) is not None:
                                    continue
                            best_log = log_id
                        finally:
                            os.unlink(asan_fn)
                    elif "minidump" in log_id:
                        if best_log is None or "asan" not in best_log:
                            best_log = log_id
                    elif best_log is None:
                        best_log = log_id
                if best_log is not None:
                    for log_id in self.ffp.available_logs():
                        if log_id in {"stderr", "stdout", best_log}:
                            continue

                        def sanitize_filename(filename):
                            filename = os.path.basename(filename)  # split any dirnames
                            filename = re.sub(r" ", "_", filename)  # replace spaces
                            filename = re.sub(r"(^ffp_|\.log$)", "", filename)  # some ffp tokens used in asan log ids
                            return re.sub(r"[^A-Za-z0-9_-]", "", filename)  # strip non-alphanumeric

                        log_fn = "%s_%s.txt" % (temp_prefix, sanitize_filename(log_id))
                        self.ffp.clone_log(log_id, target_file=log_fn)
                    aux_fn = self.ffp.clone_log(best_log, target_file="%s_crashdata.txt" % temp_prefix)
                    with open(aux_fn) as aux_fp:
                        crash_data = aux_fp.read().splitlines()
                else:
                    crash_data = None

                with open(err_fn) as err_fp, open(out_fn) as out_fp:
                    crash = CrashInfo.fromRawCrashData(out_fp.read().splitlines(),
                                                       err_fp.read().splitlines(),
                                                       self.program_cfg,
                                                       auxCrashData=crash_data)

                short_sig = crash.createShortSignature()
                if short_sig == "No crash detected":  # XXX: need to change this to support reducing timeouts?
                    log.info("Uninteresting: no crash detected")
                elif self.orig_sig is None or self.orig_sig.matches(crash):
                    result = True
                    log.info("Interesting: %s", short_sig)
                    if self.orig_sig is None and not self.args.any_crash:
                        self.orig_sig = crash.createCrashSignature(maxFrames=5)
                    self.update_timeout(end_time - start_time)
                else:
                    log.info("Uninteresting: different signature: %s", short_sig)
                    if self.alt_crash_cb is not None:
                        self.alt_crash_cb(crash)

            else:
                log.info("Uninteresting: no failure detected")

                # update log positions in any case
                log_fn = self.ffp.clone_log("stderr", target_file="%s_stderr.txt" % temp_prefix, offset=self.stderr_pos)
                self.stderr_pos += os.stat(log_fn).st_size
                log_fn = self.ffp.clone_log("stdout", target_file="%s_stdout.txt" % temp_prefix, offset=self.stdout_pos)
                self.stdout_pos += os.stat(log_fn).st_size

            # trigger relaunch by closing the browser
            self.relaunch_countdown -= 1
            if self.relaunch_countdown <= 0 and self.ffp.is_running():
                log.info("Triggering FFP relaunch")
                self.ffp.close()

        finally:
            iteration_done_event.set()
            poll.join()

        return result

    def cleanup(self, _):
        try:
            if self.serv is not None:
                self.serv.close()
                self.serv = None
        finally:
            if self.ffp is not None:
                self.ffp.clean_up()

    @staticmethod
    def parse_ffp_options(arguments):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "binary",
            help="Firefox binary to execute")
        parser.add_argument(
            "--no-harness", action="store_true",
            help="Don't use the harness for sapphire redirection")
        parser.add_argument(
            "--any-crash", action="store_true",
            help="Any crash is interesting, not only crashes which match the original first crash")
        parser.add_argument(
            "-e", "--extension",
            help="Install the fuzzPriv extension (specify path to funfuzz/dom/extension)")
        parser.add_argument(
            "-g", "--gdb", action="store_true",
            help="Use GDB")
        parser.add_argument(
            "-m", "--memory", type=int,
            help="Process memory limit in MBs (Requires psutil)")
        parser.add_argument(
            "-p", "--prefs",
            help="prefs.js file to use")
        parser.add_argument(
            "-P", "--profile",
            help="Profile to use. (default: a temporary profile is created)")
        parser.add_argument(
            "-s", "--skip", type=int, default=0,
            help="Return interesting = False for the first n reductions (default: %(default)s)")
        parser.add_argument(
            "-r", "--repeat", type=int, default=1,
            help="Try to run the testcase multiple times, for intermittent testcases (default: %(default)sx)")
        parser.add_argument(
            "-n", "--min-crashes", type=int, default=1,
            help="Require the testcase to crash n times before accepting the result. (default: %(default)sx)")
        parser.add_argument(
            "-t", "--timeout", type=int, default=60,
            help="Number of seconds to wait before polling testcase for idle (default: %(default)s)")
        parser.add_argument(
            "--max-timeout", type=int, default=600,
            help="Maximum number of seconds to wait before killing testcase (default: %(default)s)")
        parser.add_argument(
            "--idle-poll", type=int, default=3,
            help="Number of seconds to poll the process before evaluating threshold (default: %(default)s)")
        parser.add_argument(
            "--idle-threshold", type=int, default=25,
            help="CPU usage threshold to mark the process as idle (default: %(default)s)")
        parser.add_argument(
            "--environ",
            help="Line separated environment variables (VAR=value) to be set in the firefox process.")
        parser.add_argument(
            "--sig",
            help="Specify signature to reduce (JSON file).")
        parser.add_argument(
            "--ignore-timeouts", action="store_true",
            help="Don't detect timeouts as failure")
        parser.add_argument(
            "--launch-timeout", type=int, default=300,
            help="Number of seconds to wait for the browser to become "
                 "responsive after launching. (default: %(default)s)")
        parser.add_argument(
            "--reduce-file",
            help="Value passed to lithium's --testcase option, needed for testcase cache (default: testcase param)")
        parser.add_argument(
            "--no-cache", action="store_true",
            help="Disable testcase caching")
        parser.add_argument(
            "--relaunch", type=int, default=1000,
            help="Number of iterations performed before relaunching the browser (default: %(default)s)")
        parser.add_argument(
            "--valgrind", action="store_true",
            help="Use valgrind")
        parser.add_argument(
            "--xvfb", action="store_true",
            help="Use xvfb (Linux only)")
        parser.add_argument(
            "testcase",
            help="Testcase to reduce -- MUST BE LAST! (must be last only if not using lithium's --testcase option)")
        args = parser.parse_args(arguments)

        if args.repeat < 1:
            parser.error("'--repeat' value must be positive")

        if args.min_crashes < 1:
            parser.error("'--min-crashes' value must be positive")

        if args.environ is not None and not os.path.isfile(args.environ):
            parser.error("'--environ' value '%s' is not a file" % args.environ)

        if args.reduce_file is None:
            args.reduce_file = args.testcase

        return args

    def main(self):
        import lithium

        logging.basicConfig(format="%(message)s", level=logging.INFO)

        try:
            verbose = int(os.getenv("DEBUG", "0"))
            assert verbose in {0, 1}
        except (AssertionError, ValueError):
            log.error("expecting 0 or 1 for DEBUG")
            return 1
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        try:
            lith = lithium.Lithium()
            lith.conditionScript = self
            # XXX: lithium args should be parsed from beginning .. no api for this yet
            lith.conditionArgs = sys.argv[1:]
            lith.strategy = lithium.Minimize()
            lith.testcase = lithium.TestcaseLine()
            lith.testcase.readTestcase(sys.argv[-1])
            return lith.run()
        except lithium.LithiumError as exc:
            lithium.summaryHeader()
            log.error(exc)
            return 1


if __name__ == "__main__":
    exit(FFPInteresting().main())
else:
    FFPInteresting(True)
