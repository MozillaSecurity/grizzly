# coding=utf-8
import curses
from difflib import SequenceMatcher
from pathlib import Path
import signal
from subprocess import Popen, PIPE, STDOUT
from time import sleep
import sys

from ..common.utils import grz_tmp


def curses_main(scr, cmd):

    attempt_path = Path(grz_tmp("reduce")) / "attempt.html"
    reduce_path = Path(grz_tmp("reduce")) / "reduced.html"

    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, -1, 0xED)
    curses.init_pair(2, curses.COLOR_RED, 0xED)
    curses.init_pair(3, -1, -1)
    curses.init_pair(4, -1, 0xED)
    curses.curs_set(0)

    c_tc = curses.color_pair(1)
    c_del = curses.color_pair(2)
    c_grz = curses.color_pair(3)
    c_tc_bg = curses.color_pair(4)

    scr.clear()

    scr_w = curses.COLS
    scr_h = curses.LINES

    rhs_w = 60  # scr_w // 2
    rhs_h = scr_h

    lhs_w = scr_w - rhs_w
    lhs_h = scr_h

    rhs = curses.newwin(rhs_h, rhs_w, 0, 0)
    rhs_line = 0
    rhs.scrollok(True)

    lhs = curses.newwin(lhs_h, lhs_w, 0, rhs_w)
    lhs.bkgd(" ", c_tc_bg)

    proc = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    try:
        while True:

            line = proc.stdout.readline()
            if not line and proc.poll is not None:
                break
            if rhs_line == rhs_h:
                rhs.scroll(1)
                rhs_line -= 1
            rhs.addnstr(rhs_line, 0, line.rstrip(), rhs_w - 1, c_grz)
            rhs_line += 1
            rhs.refresh()

            if not (attempt_path.is_file() and reduce_path.is_file()):
                sleep(0.1)
                continue

            append = attempt_path.read_text()
            reduce = reduce_path.read_text()

            class writer:
                def __init__(self):
                    self.r = 0
                    self.c = 0

                def addstr(self, data, attr):
                    while data:
                        if self.r == lhs_h:
                            break
                        if "\n" in data:
                            data, next_data = data.split("\n", 1)
                        else:
                            next_data = None
                        n = min(lhs_w - self.c, len(data))
                        if n:
                            lhs.addnstr(self.r, self.c, data, n, attr)
                        if next_data is not None:
                            data = next_data
                            self.r += 1
                            self.c = 0
                        else:
                            self.c += n
                            break

            lhs.clear()
            wr = writer()
            if append == reduce:
                wr.addstr(reduce, c_tc)
            else:
                li = 0

                def is_junk(c):
                    return c in " \n<"

                parts = []
                for i, _, n in SequenceMatcher(
                    isjunk=is_junk, a=reduce, b=append, autojunk=False
                ).get_matching_blocks():
                    if i > li:
                        parts.append((reduce[li:i], c_del))
                    if not n:
                        break
                    parts.append((reduce[i : i + n], c_tc))
                    li = i + n
                idx = 0
                while idx < len(parts) - 1:
                    if parts[idx + 1][0] == "\n":
                        parts[idx][0] += "\n"
                        del parts[idx + 1]
                    elif parts[idx][1] == parts[idx + 1][1]:
                        parts[idx] = (parts[idx][0] + parts[idx + 1][0], parts[idx][1])
                        del parts[idx + 1]
                    else:
                        idx += 1
                idx = 0
                while idx < len(parts) - 2:
                    o1, a1 = parts[idx]
                    o2, a2 = parts[idx + 1]
                    o3, a3 = parts[idx + 2]
                    if a1 == a3 and o1.endswith("<") and o2.endswith("<"):
                        assert a1 != a2
                        parts[idx] = (o1[:-1], a1)
                        parts[idx + 1] = ("<" + o2[:-1], a2)
                        parts[idx + 2] = ("<" + o3, a3)
                    else:
                        idx += 1
                for part, attr in parts:
                    wr.addstr(part, attr)
            lhs.refresh()

    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        proc.wait()


def main():
    curses.wrapper(curses_main, sys.argv[1:])


if __name__ == "__main__":
    main()
