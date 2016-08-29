# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import random

import corpman
import loki

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class AudioCorpusManager(corpman.CorpusManager):
    """
    AudioCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
    and embed it in a document suitable for processing by a web browser.
    """

    key = "audio"

    def _init_fuzzer(self, aggression):
        self._fuzzer = loki.Loki(aggression)


    def _generate(self, template, redirect_page, mime_type=None):
        timeout = 5000 # test case timeout
        test = corpman.TestCase(template=template)

        if self._is_replay:
            test.raw_data = template.get_data()
        else:
            test.raw_data = self._fuzzer.fuzz_data(template.get_data())

        if mime_type is None:
            if template.extension in ("m4a", "m4b", "mp4"):
                mime_type = "audio/mp4"
            elif template.extension == "mp3":
                mime_type = "audio/mpeg"
            elif template.extension in ("ogg", "oga", "spx", "opus"):
                mime_type = "audio/ogg"
            elif template.extension == "wav":
                mime_type = "audio/wav"

        # add playbackRate
        if not self._is_replay and random.randint(0, 9): # 9 out of 10 times
            playback_rate = "  try{a.playbackRate=%0.2f}catch(e){};" % (random.choice([2, 10, 100]))
        else:
            playback_rate = ""

        # add seek
        media_seek = []
        if not self._is_replay and not random.randint(0, 20):
            media_seek.append("  var dur=a.duration;")
            for _ in range(random.randint(1, 10)):
                seek = random.random()
                if random.randint(0, 1):
                    seek *= 10
                media_seek.append("  try{a.fastSeek=Math.min(%0.2f, dur)}catch(e){};" % seek)
            media_seek.append("  try{a.fastSeek=0}catch(e){};")


        # prepare data for playback
        data_url = self.to_data_url(test.raw_data, mime_type=mime_type)
        test.data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<audio id='m01' src='%s' type='%s'>" % (data_url, mime_type),
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
            "\n".join(media_seek),
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

        return test
