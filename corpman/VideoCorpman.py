# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import random

import corpman
import loki

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class VideoCorpusManager(corpman.CorpusManager):
    """
    VideoCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
    and embed it in a document suitable for processing by a web browser.
    """

    key = "video"

    def _init_fuzzer(self):
        self._fuzzer = loki.Loki(0.001)


    def _generate(self, test_case, redirect_page, mime_type=None):
        f_ext = os.path.splitext(self._active_input.file_name)[-1]
        data_file = "".join(["test_data_%d" % self._generated, f_ext])

        test_case.add_testfile(
            corpman.TestFile(data_file, self._fuzzer.fuzz_data(self._active_input.get_data())))

        # TODO: mime type support needs work
        if mime_type is None and f_ext in (".mp4", ".ogg", ".webm"):
            mime_type = "video/%s" % f_ext.lstrip(".")

        if mime_type:
            type = " type='%s'" % mime_type
        else:
            type = ""

        # add playbackRate
        if random.randint(0, 9): # 9 out of 10 times
            if random.randint(0, 1):
                rate = random.random() * random.randint(1, 20)
            else:
                rate = random.choice([2, 10, 100])
            pb_rate = "  try{v.playbackRate=%0.2f}catch(e){};" % rate
        else:
            pb_rate = ""

        # add seek
        media_seek = []
        if not random.randint(0, 9):
            media_seek.append("  var dur=v.duration;")
            for _ in range(random.randint(1, 10)):
                seek = random.random()
                if random.randint(0, 1):
                    seek *= 10
                media_seek.append("  try{v.fastSeek=Math.min(%0.2f, dur)}catch(e){};" % seek)
            media_seek.append("  v.fastSeek=0;")

        # The intended functionality is to wait for a canplay event and
        # then begin playback. This will trigger a play event which will
        # set a playback timeout (pbt) that will then call pause after the
        # specified amount of time. The pause event will then cause the done()
        # function to be called. done() then cleans up and moves on to the
        # next test. If at anytime there is an error event done() is
        # called. There is also a global timeout (tmr) that is intended
        # to catch any other unexpected hangs.
        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<video id='m01'>",
            "  <source src='%s'%s>" % (data_file, type),
            "</video>",
            "<script>",
            "  var tmr;", # timeout timer
            "  var pbt;", # playback timer
            "  var v=document.getElementById('m01');",
            "  function reset(){",
            "    dump('%s complete\\n');" % test_case.landing_page,
            "    window.location='%s';" % redirect_page,
            "  }",
            "  function done(){",
            "    clearTimeout(tmr);",
            "    clearTimeout(pbt);",
            "    v.removeEventListener('error', done, true);",
            "    v.removeEventListener('pause', done, true);",
            "    v.removeEventListener('canplay', done, true);",
            "    v.src='';",
            "    v.addEventListener('pause', reset, true);",
            "    v.play();",
            "  }",
            "  v.addEventListener('error', done, true);",
            "\n".join(media_seek),
            pb_rate,
            "  v.addEventListener('pause', done, true);",
            "  v.onplay=function(){",
            "    pbt=setTimeout(function(){try{v.pause()}catch(e){}}, 100);",
            "  }",
            "  v.addEventListener('canplay', v.play, true);",
            "  tmr=setTimeout(done, %d);" % self.test_duration,
            "</script>",
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
