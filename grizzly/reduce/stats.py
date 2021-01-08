# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Keep statistics about reduction."""
from collections import namedtuple
from copy import deepcopy
from functools import partial
from itertools import zip_longest
import json
import re
from time import time


ReductionStat = namedtuple(
    "ReductionStat", "name, duration, successes, attempts, size, iterations")


class _FormatTable:
    """Format tabular data in a table.
    """
    def __init__(self, columns, formatters, vsep=" | ", hsep="-"):
        """Initialize a FormatTable instance.

        Arguments:
            columns (iterable(str)): List of column names for the table header.
            formatters (iterable(callable)): List of format functions for each column.
                                             None will result in hiding that column.
            vsep (str): Vertical separation between columns.
            hsep (str): Horizontal separation between header and data.
        """
        assert len(columns) == len(formatters)
        self._columns = tuple(column for (column, fmt) in zip(columns, formatters)
                              if fmt is not None)
        self._formatters = formatters
        self._vsep = vsep
        self._hsep = hsep

    def format_rows(self, rows):
        """Format rows as a table and return a line generator.

        Arguments:
            rows (list(list(str))): Tabular data. Each row must be the same length as
                                    `columns` passed to `__init__`.

        Yields:
            str: Each line of formatted tabular data.
        """
        max_width = [len(col) for col in self._columns]
        formatted = []
        for row in rows:
            assert len(row) == len(self._formatters)
            formatted.append([])
            offset = 0
            for idx, (data, formatter) in enumerate(zip(row, self._formatters)):
                if formatter is None:
                    offset += 1
                    continue
                data = formatter(data)
                max_width[idx - offset] = max(max_width[idx - offset], len(data))
                formatted[-1].append(data)

        # build a format_str to space out the columns with separators using `max_width`
        # the first column is left-aligned, and other fields are right-aligned.
        format_str = self._vsep.join(
            field % (width,)
            for field, width in zip_longest(["%%-%ds"], max_width, fillvalue="%%%ds")
        )
        yield format_str % self._columns
        yield self._hsep * (len(self._vsep) * (len(self._columns) - 1) + sum(max_width))
        for row in formatted:
            yield format_str % tuple(row)


def format_seconds(duration):
    # format H:M:S, and then remove all leading zeros with regex
    minutes, seconds = divmod(int(duration), 60)
    hours, minutes = divmod(minutes, 60)
    result = re.sub("^[0:]*", "", "%d:%02d:%02d" % (hours, minutes, seconds))
    # if the result is all zeroes, ensure one zero is output
    if not result:
        result = "0"
    return result


def _format_duration(duration, total=0):
    result = ""
    if duration is not None:
        if total == 0:
            percent = 0  # pragma: no cover
        else:
            percent = int(100 * duration / total)
        result = format_seconds(duration)
        result += " (%3d%%)" % (percent,)
    return result


def _format_number(number, total=0):
    result = ""
    if number is not None:
        if total == 0:
            percent = 0
        else:
            percent = int(100 * number / total)
        result = "{:n} ({:3d}%)".format(number, percent)
    return result


class ReductionStats:
    """Statistics about reduction"""

    def __init__(self):
        """Initialize a ReductionStats instance."""
        self._data = {"stats": []}

    def __deepcopy__(self, memo):
        """Return a deep copy of this instance."""
        result = type(self)()
        result._data = deepcopy(self._data, memo)  # pylint: disable=protected-access
        return result

    def add(self, name, testcase_size, elapsed=None, iterations=None, attempts=None,
            successes=None):
        """Record reduction stats for a given point in time:

        - name of the milestone (eg. init, strategy name completed)
        - current testcase size (bytes)
        - elapsed time (seconds)
        - # of iterations
        - # of total attempts
        - # of successful attempts

        Arguments:
            name (str): name of milestone
            testcase_size (int): size of testcase
            elapsed (float or None): seconds elapsed for period recorded
            iterations (int or None): # of iterations performed
            attempts (int or None): # of attempts performed
            successes (int or None): # of attempts successful

        Returns:
            None
        """
        self._data["stats"].append(
            ReductionStat(
                name=name,
                size=testcase_size,
                duration=elapsed,
                iterations=iterations,
                attempts=attempts,
                successes=successes,
            )
        )

    def add_info(self, name, value):
        """Add extra information to be added to the stats report.

        Arguments:
            name (str): key to identify the information
            value (object): Any JSON serializable value.

        Returns:
            None
        """
        assert not self.has_info(name)
        self._data[name] = value

    def has_info(self, name):
        """Check whether the extra information specified by "name"
        already exists in this instance.

        Arguments:
            name (str): key to identify the information

        Returns:
            bool: Whether the named info already exists.
        """
        assert isinstance(name, str)
        return name in self._data

    def add_timed(self, name, testcase_size_cb):
        """Time and record the period leading up to a reduction milestone.
        eg. a strategy being run.

        Arguments:
            name (str): name of milestone
            testcase_size_cb (callable): callback to get testcase size when
                                         context is exited.

        Returns:
            context: Timer context for the period being recorded up to the milestone.

                     Attributes:
                        attempts (int): # of attempts performed during period
                        iterations (int): # of iterations performed during period.
                        successes (int): # of successful attempts during period
        """
        # pylint: disable=no-self-argument
        class _MilestoneTimer:
            def __init__(sub, sub_name, parent=None):
                sub._name = sub_name
                sub._start = None
                sub._attempts = 0
                sub._iterations = 0
                sub._successes = 0
                sub._parent = parent

            def add_attempts(sub, attempts):
                sub._attempts += attempts
                if sub._parent is not None:
                    sub._parent.add_attempts(attempts)

            def add_iterations(sub, iterations):
                sub._iterations += iterations
                if sub._parent is not None:
                    sub._parent.add_iterations(iterations)

            def add_successes(sub, successes):
                sub._successes += successes
                if sub._parent is not None:
                    sub._parent.add_successes(successes)

            def __enter__(sub):
                sub._start = time()
                return sub

            def add_timed(sub, sub_name):
                """Create a new timed period linked to this one."""
                return type(sub)(sub_name, parent=sub)

            def _stop_early(sub, other):
                """Clone and stop the timer. Add as a new stat to `other`.

                Arguments:
                    other (ReductionStats): The stats to add the clone to.

                Returns:
                    None
                """
                elapsed = time() - sub._start
                other.add(
                    name, testcase_size_cb(), elapsed=elapsed, attempts=sub._attempts,
                    successes=sub._successes, iterations=sub._iterations)
                if sub._parent is not None:
                    sub._parent._stop_early(other)  # pylint: disable=protected-access

            def __exit__(sub, exc_type, exc_value, traceback):
                elapsed = time() - sub._start
                self.add(sub._name, testcase_size_cb(), elapsed=elapsed,
                         attempts=sub._attempts, successes=sub._successes,
                         iterations=sub._iterations)
        return _MilestoneTimer(name)

    def copy(self, stop_timer=None):
        """Create a deep copy of this instance.

        Arguments:
            stop_timer (`add_timed` context):
                In-progress `add_timed` call that should be stopped and added to the
                result.

        Returns:
            ReductionStats: Clone of self
        """
        result = deepcopy(self)
        if stop_timer is not None:
            stop_timer._stop_early(result)  # pylint: disable=protected-access
        return result

    def format_lines(self):
        """Format the current stats in a table.

        Yields:
            str: Formatted lines to be output.
        """
        for key, value in self._data.items():
            if key == "stats":
                continue
            yield "%s: %r" % (key, value)
        stats = self._data["stats"]
        tabulator = _FormatTable(
            ReductionStat._fields,
            ReductionStat(
                name=str,
                # duration and attempts are % of total (last), size % of init (first)
                duration=partial(_format_duration, total=stats[-1].duration),
                attempts=partial(_format_number, total=stats[-1].attempts),
                successes=partial(_format_number, total=stats[-1].successes),
                iterations=None,  # hide
                size=partial(_format_number, total=stats[0].size),
            )
        )
        yield from tabulator.format_rows(stats)

    def add_to_reporter(self, reporter):
        """Add the reducer stats to reported metadata for the given reporter.

        Arguments:
            reporter (FuzzManagerReporter): Reporter to update.

        Returns:
            None
        """
        reporter.add_extra_metadata("reducer-stats", self._data)

    def json(self):
        """Serialize the stats using JSON.

        Returns:
            str: Stats as JSON.
        """
        return json.dumps(self._data, indent=2)
