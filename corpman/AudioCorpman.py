# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
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


    def _generate(self, test_case, redirect_page, mime_type=None):
        f_ext = os.path.splitext(test_case.template.file_name)[-1]
        data_file = "".join(["test_data_%d" % self._generated, f_ext])

        test_case.add_testfile(
                corpman.TestFile(data_file, self._fuzzer.fuzz_data(test_case.template.get_data())))

        if mime_type is None:
            if f_ext in (".m4a", ".m4b", ".mp4"):
                mime_type = "audio/mp4"
            elif f_ext == ".mp3":
                mime_type = "audio/mpeg"
            elif f_ext in (".ogg", ".oga", ".spx", ".opus"):
                mime_type = "audio/ogg"
            elif f_ext == ".wav":
                mime_type = "audio/wav"

        # add playbackRate
        pb_rate = ""
        if random.randint(0, 9): # 9 out of 10 times
            if random.randint(0, 1):
                rate = random.random() * random.randint(1, 20)
            else:
                rate = random.choice([2, 10, 100])
            pb_rate = "  try{a.playbackRate=%0.2f}catch(e){};" % rate

        # add seek
        media_seek = []
        if not random.randint(0, 9): # 1 out of 10 times
            media_seek.append("  var dur=a.duration;")
            for _ in range(random.randint(1, 10)):
                seek = random.random()
                if random.randint(0, 1):
                    seek *= 10
                media_seek.append("  try{a.fastSeek=Math.min(%0.2f, dur)}catch(e){};" % seek)
            media_seek.append("  try{a.fastSeek=0}catch(e){};")


        # prepare data for playback
        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<audio id='m01' src='/%s' type='%s'>" % (data_file, mime_type),
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
            pb_rate,
            "  a.addEventListener('pause', done, true);",
            "  a.onplay=function(){",
            "    pbt=setTimeout(function(){try{a.pause()}catch(e){}}, 100);",
            "  }",
            "  a.addEventListener('canplay', a.play, true);",
            "  tmr=setTimeout(done, 5000); // timeout",
            "</script>",
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
