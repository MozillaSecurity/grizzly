#!/usr/bin/env python2
# coding=utf-8
#
# Portions Copyright 2014 BlackBerry Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import argparse
import logging
import os
import os.path
import re
import time
import hashlib

import psutil

from ffpuppet import FFPuppet

try:
    from FTB.ProgramConfiguration import ProgramConfiguration
    from FTB.Signatures.CrashInfo import CrashInfo
    HAVE_FUZZMANAGER = True
except ImportError:
    HAVE_FUZZMANAGER = False

from stack_hasher import stack_from_text, stack_to_hash

__author__ = "Jesse Schwartzentruber"
__credits__ = ["Tyson Smith", "Jesse Schwartzentruber"]

_RE_HTML_PARTS = re.compile(r"""(?x) [<>{}&;"]|
                                     \s*[A-Za-z]+="|
                                     [\n\r]+""", re.MULTILINE)


log = logging.getLogger("reduce") # pylint: disable=invalid-name


def html_parts(mutation):
    lines = []
    last = 0
    for match in _RE_HTML_PARTS.finditer(mutation):
        this = match.start(0)
        if this > last:
            lines.append(mutation[last:this])
            lines.append(match.group(0))
            last = match.end(0)
    if last <= len(mutation):
        lines.append(mutation[last:])
    #assert len("".join(lines)) == len(mutation)
    return lines


REDUCERS = {
    "line": (str.splitlines, "\n".join),
    "html": (html_parts, "".join),
    "byte": (lambda x: [c for c in x], "".join),
}


def pretty_time_diff(seconds):
    "Format a timestamp difference"
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return "%dd%02dh%02dm%02ds" % (days, hours, minutes, seconds)
    elif hours:
        return "%dh%02dm%02ds" % (hours, minutes, seconds)
    elif minutes:
        return "%dm%02ds" % (minutes, seconds)
    else:
        return "%ds" % seconds


def wait_get_hash(puppet, timeout, cfg):
    """
    Wait on FFPuppet, figure out if it was a crash, and calculate a new timeout.
    """
    start = time.time()
    return_code = puppet.wait(timeout)
    run_time = time.time() - start
    # new_timeout will be 2x this run_time if less than the existing timeout
    # in other words, decrease the timeout if this ran in less than half the timeout (floored at 10s)
    new_timeout = max(10, min(run_time * 2, timeout))

    memory_limit_hit = False
    if puppet.is_running():
        proc = psutil.Process(pid=puppet.get_pid())
        # cpu_percent() returns 0.0 on the first call.
        # http://pythonhosted.org/psutil/#psutil.Process.cpu_percent
        proc.cpu_percent()
        is_hang = proc.cpu_percent(0.5) > 75
        exit_code = None
    else:
        is_hang = False
        exit_code = puppet.wait()

    puppet.close()

    if not is_hang and exit_code == -15:
        # check if memory limit was exceeded
        log_file = puppet.clone_log()
        try:
            with open(log_file, "r") as fp:
                memory_limit_hit = fp.read().find("MEMORY_LIMIT_EXCEEDED") != -1
        finally:
            os.unlink(log_file)

    if is_hang:
        result = "TIMEOUT" # return a string since we won't calculate a hash
    elif memory_limit_hit:
        result = "MEMORY_LIMIT_EXCEEDED" # return a string since we won't calculate a hash
    elif return_code is not None:
        log_fn = puppet.clone_log()
        try:
            if cfg is None:
                with open(log_fn) as log_fp:
                    result = stack_to_hash(stack_from_text(log_fp.read()), major=True)
            else:
                with open(log_fn) as log_fp:
                    crash = CrashInfo.fromRawCrashData(None, log_fp.read(), cfg)
                if crash.createShortSignature() == "No crash detected":
                    result = None
                else:
                    result = hashlib.sha1("%s\n%r" % (crash.createShortSignature(), crash.backtrace[:5])).hexdigest()
        finally:
            os.unlink(log_fn)
    else: # XXX: I don't think this is possible
        result = None

    return result, new_timeout


def reduce_args(argv=None):
    parser = argparse.ArgumentParser(description="Grizzly reducer")
    parser.add_argument(
        "binary",
        help="Firefox binary to execute")
    parser.add_argument(
        "testcase",
        help="Testcase to reduce")
    parser.add_argument(
        "-e", "--extension",
        help="Install the fuzzPriv extension (specify path to funfuzz/dom/extension)")
    parser.add_argument(
        "-m", "--memory", type=int,
        help="Process memory limit in MBs (Requires psutil)")
    parser.add_argument(
        "-p", "--prefs",
        help="prefs.js file to use")
    parser.add_argument(
        "--timeout", type=int, default=60,
        help="Iteration timeout in seconds (default: %(default)s)")
    parser.add_argument(
        "--launch-timeout", type=int, default=300,
        help="Number of seconds to wait for the browser to become " \
             "responsive after launching. (default: %(default)s)")
    parser.add_argument(
        "-s", "--asserts", action="store_true",
        help="Detect soft assertions")
    parser.add_argument(
        "--valgrind", action="store_true",
        help="Use valgrind")
    parser.add_argument(
        "--gdb", action="store_true",
        help="Use GDB")
    parser.add_argument(
        "--windbg", action="store_true",
        help="Collect crash log with WinDBG (Windows only)")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use xvfb (Linux only)")
    parser.add_argument(
        "--n-tries", type=int, default=1,
        help="Number of times to try each reduction (can help with intermittent testcases) (default: %(default)d)")
    parser.add_argument(
        "--skip", type=int, default=0,
        help="Skip initial number of tries.")
    parser.add_argument(
        "-r", "--reducer", default="line",
        help="Reducer(s) to use, available options are: %r (can be comma separated list for multiple) "
             "(default: %%(default)s)" % REDUCERS.keys())
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show verbose debugging output")
    args = parser.parse_args(args=argv)
    if "," in args.reducer:
        args.reducer = args.reducer.split(",")
    else:
        args.reducer = [args.reducer]
    if not args.reducer or not set(args.reducer).issubset(set(REDUCERS.keys())):
        parser.error("Invalid reducer")
    if args.n_tries <= 0:
        parser.error("n_tries must be at least 1")
    if args.memory is not None:
        args.memory = args.memory * 1024 * 1024
    return args


def reduce_main(args):

    if len(logging.getLogger().handlers) == 0:
        logging.basicConfig()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if HAVE_FUZZMANAGER:
        program_cfg = ProgramConfiguration.fromBinary(args.binary)
    else:
        program_cfg = None
    timeout = args.timeout
    ffp = FFPuppet(
        use_gdb=args.gdb,
        use_valgrind=args.valgrind,
        use_windbg=args.windbg,
        use_xvfb=args.xvfb,
        detect_soft_assertions=args.asserts)
    try:
        iters = 0
        start_time = time.time()
        # get initial stack
        log.info("Running %s for initial crash", args.testcase)
        ffp.launch(
            args.binary,
            location=os.path.abspath(args.testcase),
            launch_timeout=args.launch_timeout,
            memory_limit=args.memory,
            prefs_js=args.prefs,
            extension=args.extension)
        orig_stack, timeout = wait_get_hash(ffp, timeout, program_cfg)
        if orig_stack is None:
            raise RuntimeError("%s didn't crash" % args.testcase)
        log.info("got crash: %s", orig_stack)
        prefix, testcase, suffix = split_reduce_area(args.testcase)
        orig = best = len(testcase)
        log.info("original size is %d", orig)
        best_fn = "_BEST".join(os.path.splitext(args.testcase))
        try_fn = "_TRY".join(os.path.splitext(os.path.abspath(args.testcase)))
        try_url = try_fn
        for reducer in args.reducer:
            log.info("using reducer: %s", reducer)
            splitter, joiner = REDUCERS[reducer]
            gen = FeedbackIter(splitter(testcase), formatter=joiner)
            # skip initial few
            for _ in range(args.skip):
                gen.next()
                gen.keep(True)
            for attempt in gen:
                iters += 1
                with open(try_fn, "wb") as try_fp:
                    try_fp.writelines([prefix, attempt, suffix])
                for _ in range(args.n_tries):
                    ffp.launch(
                        args.binary,
                        location=try_url,
                        launch_timeout=args.launch_timeout,
                        memory_limit=args.memory,
                        prefs_js=args.prefs)
                    result_try, new_timeout = wait_get_hash(ffp, timeout, program_cfg)
                    same_crash = (orig_stack == result_try)
                    if not same_crash:
                        break
                if same_crash:
                    assert len(attempt) < best
                    best = len(attempt)
                    with open(best_fn, "wb") as best_fp:
                        best_fp.writelines([prefix, attempt, suffix])
                    log.info("I%03d - reduced ok to %d", iters, best)
                    timeout = new_timeout
                elif result_try is not None:
                    log.info("I%03d - crashed but got %s (saved)", iters, result_try)
                    alt_fn = ("_%s" % result_try[:8]).join(os.path.splitext(args.testcase))
                    with open(alt_fn, "wb") as alt_fp:
                        alt_fp.writelines([prefix, attempt, suffix])
                    ffp.save_log("%s.log" % os.path.splitext(alt_fn)[0])
                else:
                    log.info("I%03d - no crash", iters)
                gen.keep(not same_crash)
            testcase = gen.getvalue()
        os.unlink(try_fn)
    finally:
        ffp.close()
        ffp.clean_up()
    if orig != best:
        reduced_fn = "_REDUCED".join(os.path.splitext(args.testcase))
        reduce_clobber = 0
        while os.path.isfile(reduced_fn):
            reduce_clobber += 1
            reduced_fn = ("_REDUCED(%d)" % reduce_clobber).join(os.path.splitext(args.testcase))
        with open(reduced_fn, "wb") as reduced_fp:
            reduced_fp.writelines([prefix, testcase, suffix])
        os.unlink(best_fn)
        log.info("%s was %d bytes", args.testcase, orig)
        log.info("%s is %d bytes", reduced_fn, best)
    else:
        log.warning("%s was not reduced", args.testcase)
    log.info("ran for %d iterations in %s", iters, pretty_time_diff(time.time() - start_time))


def split_reduce_area(filename, splitlines=False, begin="DDBEGIN", end="DDEND"):
    """
    Read in the filename and split on lithium reduction tokens (DDBEGIN/DDEND)
    Return the pre-DDBEGIN (inclusive), middle, and post-DDEND (inclusive) sections
    splitlines=True will change the return type from a 3-tuple of strings to a 3-tuple of lists (lines)
    """
    before, reduce_area, after = [], [], []
    with open(filename, "rb") as tc_fp:
        for line in tc_fp:
            before.append(line)
            if begin in line:
                break
        for line in tc_fp:
            if end in line:
                after.append(line)
                break
            reduce_area.append(line)
        for line in tc_fp:
            after.append(line)
        if not after:
            if reduce_area:
                raise RuntimeError("begin token '%s' found without matching end token '%s'" % (begin, end))
            log.debug("No begin token '%s' found, reducing entire file", begin)
            reduce_area = before
            before = []
        else:
            log.debug("Found begin token '%s' on line %d and end token '%s' on line %d",
                      begin, len(before), end, len(before) + len(reduce_area) + 1)
            # move trailing newline in `reduce_area` to `after` so it is not reduced out
            if reduce_area[-1]:
                newline_match = re.search(r'(\r?\n)$', reduce_area[-1])
                if newline_match is not None:
                    newline = newline_match.group(1)
                    reduce_area[-1] = reduce_area[-1][:-len(newline)]
                    after.insert(0, newline)
        if splitlines:
            return before, reduce_area, after
        else:
            return "".join(before), "".join(reduce_area), "".join(after)


class FeedbackIter(object):
    """
    This iterable operates on a sequence, deciding whether or not
    chunks of it can be removed.

    For each iteration, the keep() method should be called with a
    boolean indicating whether or not the chunk just removed should be
    kept (ie, "that broke something, put it back").

    The size of the chunk that is removed starts at len(sequence)/2,
    and decreases to 1.  The iteration is terminated once the sequence
    is iterated over with chunk size of 1 and no chunks are removed.
    """
    def __init__(self, sequence, formatter=lambda x: x):
        self.data = [sequence]
        self.tried = None
        self._reset()
        self.formatter = formatter

    def __iter__(self):
        return self

    def _reset(self):
        # pylint: disable=attribute-defined-outside-init
        self.i = 0
        self.found_something = False
        self.size = 0
        data = []
        lens = 0
        explode = None
        for i in self.data:
            self.size += len(i)
            lens += 1
            if explode is None:
                explode = bool(len(i)//2 <= 1)
            if explode:
                lens -= 1
                for j in range(len(i)):
                    data.append(i[j:j+1])
                    lens += 1
            else:
                spl = max(1, len(i)//2)
                data.append(i[:spl])
                data.append(i[spl:])
                if not data[-1]:
                    data.pop()
                else:
                    lens += 1
        self.data = data
        log.debug("chunk size: ~%d (len==%d)", self.size//lens, self.size)

    def keep(self, yes):
        if self.tried is None:
            raise Exception("feedback before any value was generated")
        if yes:
            self.i += 1
            log.debug("keeping chunk %d/%d (len==%d)", self.i, len(self.data), self.size)
        else:
            self.size -= len(self.data[self.i])
            self.data = self.tried
            #self.found_something = True # setting this to True causes the reduce loop to keep
                                         # going at chunk=1 until nothing more can be eliminated
            log.debug("eliminated chunk %d/%d (len==%d)", self.i + 1, len(self.data) + 1, self.size)
            if len(self.data) == 1:
                log.debug("only one chunk left, assuming it is needed")
                self._reset()
        self.tried = None

    def __next__(self):
        return self.next()

    def next(self):
        if self.tried is not None:
            raise Exception("no feedback received on last value generated")
        while True:
            self.tried = self.data[:] # make a copy
            try:
                rmd = self.tried.pop(self.i)
                if len(rmd) == 1 and rmd[0] == "\n":
                    self.keep(True)
                    continue # skip newlines
                return self.formatter(sum(self.tried, []))
            except IndexError:
                self.tried = None
                if not self.data or (len(self.data[0]) == 1 and not self.found_something):
                    raise StopIteration
                else:
                    self._reset()

    def getvalue(self):
        if self.tried is not None:
            raise Exception("no feedback received on last value generated")
        return self.formatter(sum(self.data, []))


if __name__ == "__main__":
    reduce_main(reduce_args())
