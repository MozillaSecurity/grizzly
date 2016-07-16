# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
VideoCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
and embed it in a document suitable for processing by a web browser.
"""

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

import base64
import random

import corpman
import loki

class VideoCorpusManager(corpman.CorpusManager):
    key = "video"

    def _init_fuzzer(self, aggression):
        self._fuzzer = loki.Loki(aggression)


    def generate(self, media_type=None, redirect_page="done", timeout=5000):
        self._rotate_template()

        # prepare data for playback
        if self._is_replay:
            self._test.fuzzed_data = self._test.template_data
        else:
            self._test.fuzzed_data = self._fuzzer.fuzz_data(self._test.template_data)

        if media_type is None:
            if self._test.extension in ("mp4", "ogg", "webm"):
                media_type = "video/%s" % self._test.extension
            else:
                media_type = "application/octet-stream"

        # add playbackRate
        if not self._is_replay and random.randint(0, 9): # 9 out of 10 times
            playback_rate = "  v.playbackRate=%0.2f;" % (random.choice([2, 10, 100]))
        else:
            playback_rate = ""

        # add seek
        if not self._is_replay and not random.randint(0, 20):
            media_seek = []
            media_seek.append("  var dur=v.duration;"),
            for _ in range(random.randint(1, 10)):
                seek = random.random()
                if random.randint(0, 1):
                    seek *= 10
                media_seek.append("  try{v.fastSeek=Math.min(%0.2f, dur)}catch(e){};" % seek)
            media_seek.append("  v.fastSeek=0;")
            media_seek = "\n".join(media_seek)
        else:
            media_seek = ""

        fuzzed_data = "data:%s;base64,%s" % (
            media_type,
            base64.standard_b64encode(self._test.fuzzed_data))

        # The intended functionality is to wait for a canplay event and
        # then begin playback. This will trigger a play event which will
        # set a playback timeout (pbt) that will then call pause after the
        # specified amount of time. The pause event will then cause the done()
        # function to be called. done() then cleans up and moves on to the
        # next test. If at anytime there is an error event done() is
        # called. There is also a global timeout (tmr) that is intended
        # to catch any other unexpected hangs.
        self._test.test_data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<video id='m01' src='%s' type='%s'>" % (fuzzed_data, media_type),
            "Error!",
            "</video>",
            "<script>",
            "  var tmr;", # timeout timer
            "  var pbt;", # playback timer
            "  var v=document.getElementById('m01');",
            "  function done(){",
            "    clearTimeout(tmr);",
            "    clearTimeout(pbt);",
            "    v.removeEventListener('error', done, true);",
            "    v.removeEventListener('pause', done, true);",
            "    v.removeEventListener('canplay', done, true);",
            "    window.location='/%s';" % redirect_page,
            "  }",
            "  v.addEventListener('error', done, true);",
            media_seek,
            playback_rate,
            "  v.addEventListener('pause', done, true);",
            "  v.onplay=function(){",
            "      pbt=setTimeout(function(){try{v.pause()}catch(e){}}, 100);",
            "  }",
            "  v.addEventListener('canplay', v.play, true);",
            "  tmr=setTimeout(done, %d); // timeout" % timeout,
            "</script>",
            "</body>",
            "</html>"])

        self._gen_count += 1
