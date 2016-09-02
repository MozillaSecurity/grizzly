#!/usr/bin/env python
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

from ffpuppet import FFPuppet
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


class PuppetWrapper(FFPuppet):

    def __init__(self, run_timeout=None, **kwds):
        FFPuppet.__init__(self, **kwds)
        assert not hasattr(self, '_run_timeout')
        self._run_timeout = run_timeout

    def wait_get_hash(self, adjust_timeout=False, detect_soft_asserts=False):
        start = time.time()
        return_code = self.wait(self._run_timeout)
        run_time = time.time() - start
        if adjust_timeout:
            self._run_timeout = max(10, min(run_time * 2, self._run_timeout))

        self.close()
        with open(self._log.name) as log_fp:
            log_contents = log_fp.read()
        self.clean_up()

        failure_detected = False
        if (detect_soft_asserts or self._use_valgrind) and return_code is None:
            if detect_soft_asserts and log_contents.find("###!!! ASSERTION:") != -1:
                # detected non-crashing assertions
                failure_detected = True
            elif self._use_valgrind and re.search(r"==\d+==\s", log_contents):
                # detected valgrind output in log
                failure_detected = True
        elif return_code is not None:
            failure_detected = True

        if failure_detected:
            stack = stack_to_hash(stack_from_text(log_contents), major=True)
            return stack

        return None


def reduce_args():
    parser = argparse.ArgumentParser(description="Grizzly reducer")
    parser.add_argument(
        "binary",
        help="Firefox binary to execute")
    parser.add_argument(
        "testcase",
        help="Testcase to reduce")
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
        "--windbg", action="store_true",
        help="Collect crash log with WinDBG (Windows only)")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use xvfb (Linux only)")
    parser.add_argument(
        "--n-tries", type=int, default=1,
        help="Number of times to try each reduction (can help with intermittent testcases) (default: %(default)d)")
    parser.add_argument(
        "-r", "--reducer", default="line",
        help="Reducer(s) to use, available options are: %r (can be comma separated list for multiple) "
             "(default: %%(default)s)" % REDUCERS.keys())
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show verbose debugging output")
    args = parser.parse_args()
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

    ffp = PuppetWrapper(
        use_valgrind=args.valgrind,
        use_windbg=args.windbg,
        use_xvfb=args.xvfb,
        run_timeout=args.timeout)
    try:
        iters = 0
        # get initial stack
        log.info("Running %s for initial crash", args.testcase)
        ffp.launch(
            args.binary,
            location="file://%s" % os.path.abspath(args.testcase),
            launch_timeout=args.launch_timeout,
            memory_limit=args.memory,
            prefs_js=args.prefs)
        orig_stack = ffp.wait_get_hash(adjust_timeout=True, detect_soft_asserts=args.asserts)
        if orig_stack is None:
            raise RuntimeError("%s didn't crash" % args.testcase)
        log.info("got crash: %s", orig_stack)
        with open(args.testcase, "rb") as tc_fp:
            testcase = tc_fp.read()
        if "DDBEGIN" in testcase:
            testcase = testcase.splitlines()
            begin = end = None
            for line_no, line in enumerate(testcase):
                if begin is None and "DDBEGIN" in line:
                    begin = line_no
                elif begin is not None and end is None and "DDEND" in line:
                    end = line_no
                    break
            else:
                raise RuntimeError("DDBEGIN found without matching DDEND")
            log.debug("Found DDBEGIN on line %d and DDEND on line %d", begin + 1, end + 1)
            prefix, testcase, suffix = ["\n".join(x) for x in (testcase[:begin+1] + [""],
                                                               testcase[begin+1:end],
                                                               [""] + testcase[end:])]
        else:
            log.debug("No DDBEGIN found, reducing entire file")
            prefix = suffix = ""
        orig = best = len(testcase)
        log.info("original size is %d", orig)
        best_fn = "_BEST".join(os.path.splitext(args.testcase))
        try_fn = "_TRY".join(os.path.splitext(os.path.abspath(args.testcase)))
        try_url = "file://%s" % try_fn
        for reducer in args.reducer:
            log.info("using reducer: %s", reducer)
            splitter, joiner = REDUCERS[reducer]
            gen = FeedbackIter(splitter(testcase), formatter=joiner)
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
                    result_try = ffp.wait_get_hash(detect_soft_asserts=args.asserts)
                    same_crash = (orig_stack == result_try)
                    if not same_crash:
                        break
                if same_crash:
                    assert len(attempt) < best
                    best = len(attempt)
                    with open(best_fn, "wb") as best_fp:
                        best_fp.writelines([prefix, attempt, suffix])
                    log.info("I%03d - reduced ok to %d", iters, best)
                elif result_try is not None:
                    log.info("I%03d - crashed but got %s", iters, result_try)
                else:
                    log.info("I%03d - no crash", iters)
                gen.keep(not same_crash)
            testcase = gen.getvalue()
        os.unlink(try_fn)
    finally:
        ffp.close()
        ffp.clean_up()
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
    log.info("reduction took %d iterations", iters)


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


if __name__ == '__main__':
    reduce_main(reduce_args())
