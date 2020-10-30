# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Keep statistics about reduction."""
from collections import namedtuple
from functools import partial
from itertools import zip_longest
import json
import re
from time import gmtime, strftime, time


ReductionStat = namedtuple("ReductionStat", "name, duration, iterations, size")


class _FormatTable(object):
    """Format tabular data in a table.
    """
    def __init__(self, columns, formatters, vsep=" | ", hsep="-"):
        """Initialize a FormatTable instance.

        Arguments:
            columns (iterable(str)): List of column names for the table header.
            formatters (iterable(callable)): List of format functions for each column.
            vsep (str): Vertical separation between columns.
            hsep (str): Horizontal separation between header and data.
        """
        assert len(columns) == len(formatters)
        self._columns = columns
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
            assert len(row) == len(self._columns)
            formatted.append([])
            for idx, (data, formatter) in enumerate(zip(row, self._formatters)):
                data = formatter(data)
                max_width[idx] = max(max_width[idx], len(data))
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


def _format_duration(duration, total=0):
    result = ""
    if duration is not None:
        if total == 0:
            percent = 0
        else:
            percent = int(100 * duration / total)
        # format H:M:S, and then remove all leading zeros with regex
        result = re.sub("^[0:]*", "", strftime("%H:%M:%S", gmtime(duration)))
        # if the result is all zeroes, ensure one zero is output
        if not result:
            result = "0"
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


class ReductionStats(object):
    """Statistics about reduction"""

    def __init__(self):
        """Initialize a ReductionStats instance."""
        self._stats = []

    def add(self, name, testcase_size, elapsed=None, iters=None):
        """Record reduction stats for a given point in time:

        - name of the milestone (eg. init, strategy name completed)
        - current testcase size (bytes)
        - elapsed time (seconds)
        - # of iterations

        Arguments:
            name (str): name of milestone
            testcase_size (int): size of testcase
            elapsed (float or None): seconds elapsed for period recorded
            iters (int or None): # of iterations performed

        Returns:
            None
        """
        self._stats.append(
            ReductionStat(
                name=name,
                size=testcase_size,
                duration=elapsed,
                iterations=iters,
            )
        )

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
                        iters (int): # of iterations performed during period
        """
        # pylint: disable=no-self-argument
        class _MilestoneTimer(object):
            def __init__(sub):
                sub._start = None
                sub.iters = 0

            def __enter__(sub):
                sub._start = time()
                return sub

            def _stop_early(sub, other):
                """Clone and stop the timer. Add as a new stat to `other`.

                Arguments:
                    other (ReductionStats): The stats to add the clone to.

                Returns:
                    None
                """
                elapsed = time() - sub._start
                other.add(
                    name, testcase_size_cb(), elapsed=elapsed, iters=sub.iters
                )

            def __exit__(sub, exc_type, exc_value, traceback):
                elapsed = time() - sub._start
                self.add(name, testcase_size_cb(), elapsed=elapsed, iters=sub.iters)
        return _MilestoneTimer()

    def copy(self, stop_timers=None):
        """Create a shallow copy of this instance.

        Arguments:
            stop_timers (list(`add_timed` context)):
                In-progress `add_timed` calls that should be stopped and added to the
                result.

        Returns:
            ReductionStats: Clone of self
        """
        result = type(self)()
        result._stats = self._stats.copy()  # pylint: disable=protected-access
        if stop_timers is not None:
            for timer in stop_timers:
                timer._stop_early(result)  # pylint: disable=protected-access
        return result

    def format_lines(self):
        """Format the current stats in a table.

        Yields:
            str: Formatted lines to be output.
        """
        tabulator = _FormatTable(
            ReductionStat._fields,
            ReductionStat(
                name=str,
                # duration and iterations are % of total (last), size % of init (first)
                duration=partial(_format_duration, total=self._stats[-1].duration),
                iterations=partial(_format_number, total=self._stats[-1].iterations),
                size=partial(_format_number, total=self._stats[0].size),
            )
        )
        yield from tabulator.format_rows(self._stats)

    def json(self):
        """Serialize the stats using JSON.

        Returns:
            str: Stats as JSON.
        """
        return json.dumps(self._stats, indent=2)
