################################################################################
# Name   : ALF Testcase Reducer
# Author : Jesse Schwartzentruber & Tyson Smith
#
# Copyright 2014 BlackBerry Limited
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
################################################################################
import logging
import os.path
import re


_RE_HTML_PARTS = re.compile(r"""(?x) [<>{}&;"]|
                                     \s*[A-Za-z]+="|
                                     [\n\r]+""", re.MULTILINE)


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


reducers = {
    "line": (str.splitlines, "\n".join),
    "html": (html_parts, "".join),
    "byte": (lambda x: [c for c in x], "".join),
}


def add_reducer(name, splitter, joiner):
    """
    Add a new reducer.
    - splitter takes a string and yields a list of parts
    - joiner takes a list of parts and yields a string
    - joiner(splitter(x)) == x should always be True
    - projects wishing to register a custom reducer must do so when
      imported
    """
    reducers[name] = (splitter, joiner)


def _reduce(fuzzer, reducer, n_tries, mutation, mutation_path, result):
    """
    fuzzer is an alf.Fuzzer object with a run_subject method
    reducer is a key into the reducers dict
    n_tries is the number of times a testcase must crash before it is
        considered ok. this is used to improve semi-reproducible
        testcases.
    mutation is the testcase data to be reduced (as a string)
    mutation_path is the path the testcase should be written out to.
    result is the alf.debug.FuzzResult object for comparison. crashes
        must match this to be accepted. (fuzzers can override
        'def resultmatch(self, orig, other)' method to tweak this.)
    """
    splitter, joiner = reducers[reducer]
    if n_tries <= 0:
        raise Exception("n_tries must be at least 1")
    best = len(mutation)
    bestfn = "_BEST".join(os.path.splitext(mutation_path))
    gen = FeedbackIter(splitter(mutation), formatter=joiner)
    for attempt in gen:
        with open(mutation_path, "wb") as f:
            f.write(attempt)
        for _ in range(n_tries):
            result_try = fuzzer.run_subject(mutation_path)
            same_crash = fuzzer.resultmatch(result, result_try)
            if not same_crash:
                break
        if same_crash and len(attempt) < best:
            best = len(attempt)
            with open(bestfn, "wb") as f:
                f.write(attempt)
        gen.keep(not same_crash)
    return gen.getvalue()


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
        # pylint: disable=W0201
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
        logging.debug("chunk size: ~%d (len==%d)", self.size//lens, self.size)

    def keep(self, yes):
        if self.tried is None:
            raise Exception("feedback before any value was generated")
        if yes:
            self.i += 1
            logging.debug("keeping chunk %d/%d (len==%d)", self.i, len(self.data), self.size)
        else:
            self.size -= len(self.data[self.i])
            self.data = self.tried
            #self.found_something = True # setting this to True causes the reduce loop to keep
                                         # going at chunk=1 until nothing more can be eliminated
            logging.debug("eliminated chunk %d/%d (len==%d)",
                          self.i + 1, len(self.data) + 1, self.size)
            if len(self.data) == 1:
                logging.debug("only one chunk left, assuming it is needed")
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

