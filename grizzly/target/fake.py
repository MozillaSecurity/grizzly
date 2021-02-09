# coding=utf-8
from logging import getLogger
from pathlib import Path
from queue import Queue
from tempfile import mkdtemp
from threading import Thread, RLock
from time import sleep
import re

from requests import get

from .target import Target
from ..common.reporter import Report
from ..common.utils import grz_tmp


# TODO: this is very specific to grizzly/reduce/anim_testcase.html
# should be more generic
a = """<script>
function setup() {
  document.getElementById("a").crash()
}
</script>
<body onload="setup()">"""
b = """<div """
c = """ id=a"""
d = """></div>"""
e = """</body>"""

LOG = getLogger(__name__)

Q = Queue()


class reqr(Thread):
    def __init__(self, loc):
        super().__init__()
        self.loc = loc
        self._state_l = RLock()
        self._state = "dead"

    @property
    def state(self):
        with self._state_l:
            return self._state

    @state.setter
    def state(self, value):
        with self._state_l:
            self._state = value

    def run(self):
        self.state = "alive"
        first = True
        try:
            resp = get(self.loc)
            LOG.debug("location: %r", self.loc)
            if "/grz_harness" in self.loc:
                relaunch = int(re.search(r"close_after=(\d+)", self.loc).group(1))
            else:
                relaunch = 1
            for _ in range(relaunch):
                if "/grz_harness" in self.loc:
                    if first:
                        resp = get(self.loc.rsplit("/", 1)[0] + "/grz_current_test")
                        first = False
                    else:
                        resp = get(self.loc.rsplit("/", 1)[0] + "/grz_next_test")
                LOG.debug("resp")
                contents = resp.text
                LOG.debug("got %r", contents)
                A = a in contents
                B = b in contents
                C = c in contents
                D = d in contents
                E = e in contents
                LOG.debug("%r %r %r %r %r", A, B, C, D, E)
                if A and B and C and D and E:
                    self.state = "crash"
                    break
                sleep(0.1)
        finally:
            with self._state_l:
                if self._state == "alive":
                    self._state = "dead"


class FakeTarget(Target):
    launch_timeout = 10
    binary = "/dev/null"

    def __init__(self, *_args, **_kwds):
        self.thing = None

    def is_healthy(self):  # Monitor interface
        return self.thing.state == "alive"

    def add_abort_token(self, token):
        pass

    def cleanup(self):
        self.close()

    def close(self):
        pass

    @property
    def closed(self):
        return self.thing is None or self.thing.state != "alive"

    def detect_failure(self, ignored, was_timeout):
        if self.thing.state == "crash":
            return self.RESULT_FAILURE
        return self.RESULT_IGNORED

    def is_idle(self, threshold):
        return True

    def launch(self, location, **_kwds):
        self.thing = reqr(location)
        self.thing.start()

    def log_size(self):
        return 10

    @property
    def monitor(self):
        return self

    @property
    def prefs(self):
        return None

    def create_report(self):
        logs = mkdtemp(prefix="logs_", dir=grz_tmp("logs"))
        self.save_logs(logs)
        return Report(logs, self.binary)

    def save_logs(self, dest, *args, **kwargs):
        dest = Path(dest)
        dest.mkdir(exist_ok=True)
        (dest / "log_stderr.txt").write_text("Assertion failure: crash\n")
        (dest / "log_stdout.txt").touch()
