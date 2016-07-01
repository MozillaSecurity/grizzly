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


    def generate(self, media_type=None, redirect_page="done", timeout=250):
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
        if not self._is_replay and random.randint(0, 5): # 5 out of 6 times
            playback_rate = "  try{v.playbackRate=%0.1f}catch(e){}" % (random.choice([2, 10, 100]))
        else:
            playback_rate = ""

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
            "<audio id='m01' preload='auto' src='%s' type='%s'>" % (fuzzed_data, media_type),
            "Error!",
            "</audio>",
            "<script>",
            "  var tmr;",
            "  var v=document.getElementById('m01');",
            "  function set_duration(){tmr=setTimeout(reset, %d)}" % timeout,
            "  function done(){",
            "    v.removeEventListener('error', done, true);",
            "    v.removeEventListener('seeked', done, true);",
            "    window.location='/%s';" % redirect_page,
            "  }",
            "  function reset(){",
            "    clearTimeout(tmr);",
            "    v.removeEventListener('ended', reset, true);",
            "    v.removeEventListener('error', reset, true);",
            "    v.removeEventListener('pause', reset, true);",
            "    v.removeEventListener('playing', set_duration, true);",
            "    try{v.pause()}catch(e){}",
            "    v.addEventListener('error', done, true);",
            "    if(v.seekable && !isNaN(v.currentTime) && v.currentTime>0){",
            "      if(!isNaN(v.duration) && v.duration>0)",
            "        try{v.fastSeek(v.duration)}catch(e){}",
            "      v.addEventListener('seeked', done, true);",
            "      v.fastSeek(0);",
            "    }",
            "    else",
            "      done();",
            "  }",
            "  v.addEventListener('ended', reset, true);",
            "  v.addEventListener('error', reset, true);",
            "  v.addEventListener('pause', reset, true);",
            playback_rate,
            "  v.addEventListener('playing', set_duration, true);",
            "  v.addEventListener('canplay', function(){v.play()}, true);",
            "</script>",
            "</body>",
            "</html>"])

        self._gen_count += 1
