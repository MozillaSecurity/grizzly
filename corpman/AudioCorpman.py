# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
AudioCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
and embed it in a document suitable for processing by a web browser.
"""

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

import base64
import random

import corpman
import loki

class AudioCorpusManager(corpman.CorpusManager):
    key = "audio"

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
            if self._test.extension in ("m4a", "m4b", "mp4"):
                media_type = "audio/mp4"
            elif self._test.extension == "mp3":
                media_type = "audio/mpeg"
            elif self._test.extension in ("ogg", "oga", "spx", "opus"):
                media_type = "audio/ogg"
            elif self._test.extension == "wav":
                media_type = "audio/wav"
            else:
                media_type = "application/octet-stream"

        # add playbackRate
        if not self._is_replay and random.randint(0, 9): # 9 out of 10 times
            playback_rate = "  try{a.playbackRate=%0.2f}catch(e){};" % (random.choice([2, 10, 100]))
        else:
            playback_rate = ""

        # add seek
        if not self._is_replay and not random.randint(0, 20):
            media_seek = []
            media_seek.append("  var dur=a.duration;"),
            for _ in range(random.randint(1, 10)):
                seek = random.random()
                if random.randint(0, 1):
                    seek *= 10
                media_seek.append("  try{a.fastSeek=Math.min(%0.2f, dur)}catch(e){};" % seek)
            media_seek.append("  try{a.fastSeek=0}catch(e){};")
            media_seek = "\n".join(media_seek)
        else:
            media_seek = ""

        fuzzed_data = "data:%s;base64,%s" % (
            media_type,
            base64.standard_b64encode(self._test.fuzzed_data))

        self._test.test_data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<audio id='m01' src='%s' type='%s'>" % (fuzzed_data, media_type),
            "Error!",
            "</audio>",
            "<script>",
            "  var tmr;", # timeout timer
            "  var pbt;", # playback timer
            "  var a=document.getElementById('m01');",
            "  function next(){window.location='/%s';}" % redirect_page,
            "  function done(){",
            "    clearTimeout(tmr);",
            "    clearTimeout(pbt);",
            "    a.removeEventListener('error', done, true);",
            "    a.removeEventListener('pause', done, true);",
            "    a.removeEventListener('canplay', done, true);",
            "    a.addEventListener('pause', next, true);",
            "    a.src='';",
            "    a.play();",
            "  }",
            "  a.addEventListener('error', done, true);",
            media_seek,
            playback_rate,
            "  a.addEventListener('pause', done, true);",
            "  a.onplay=function(){",
            "    pbt=setTimeout(function(){try{a.pause()}catch(e){}}, 150);",
            "  }",
            "  a.addEventListener('canplay', a.play, true);",
            "  tmr=setTimeout(done, %d); // timeout" % timeout,
            "</script>",
            "</body>",
            "</html>"])

        self._gen_count += 1
