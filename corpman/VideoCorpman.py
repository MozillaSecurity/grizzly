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


    def generate(self, media_type=None, timeout=250):
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

        good_clip = "data:video/webm;base64," \
                    "GkXfowEAAAAAAAAfQoaBAUL3gQFC8oEEQvOBCEKChHdlYm1Ch4ECQoWBAhhTgGcBAAAAAAAB6BFN" \
                    "m3RALE27i1OrhBVJqWZTrIHfTbuMU6uEFlSua1OsggEwTbuMU6uEHFO7a1OsggHL7AEAAAAAAACk" \
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVSalmAQAA" \
                    "AAAAAEUq17GDD0JATYCNTGF2ZjU3LjI5LjEwMVdBjUxhdmY1Ny4yOS4xMDFzpJBAb17Yv2oNAF1Z" \
                    "EESuco33RImIQFCAAAAAAAAWVK5rAQAAAAAAADyuAQAAAAAAADPXgQFzxYEBnIEAIrWcg3VuZIaF" \
                    "Vl9WUDmDgQEj44OEAfygVeABAAAAAAAAB7CCAUC6gfAfQ7Z1AQAAAAAAAEfngQCjqYEAAICCSYNC" \
                    "ABPwDvYAOCQcGFQAAFBh9jAAABML7AAATEnjdRwIJ+gAo5eBACEAhgBAkpwATEAABCasAABekcXg" \
                    "ABxTu2sBAAAAAAAAEbuPs4EAt4r3gQHxggF48IED"

        fuzzed_data = "data:%s;base64,%s" % (
            media_type,
            base64.standard_b64encode(self._test.fuzzed_data))

        if self._is_replay:
            timeout = 5000

        self._test.test_data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<video id='m01' autoplay='false' src='%s' type='%s'>" % (fuzzed_data, media_type),
            "Error!",
            "</video>",
            "<script>",
            "  var tmr;",
            "  function reset(){window.location='/done';}",
            "  function try_valid(){",
            "    clearTimeout(tmr);",
            "    v.removeEventListener('pause', try_valid, true);",
            "    try{v.pause();}catch(e){};",
            "    v.addEventListener('pause', reset, true);",
            "    v.src='%s';" % good_clip,
            "    v.type='video/webm';",
            "    v.play();",
            "  }",
            "  var v=document.getElementById('m01');",
            "  v.addEventListener('error', try_valid, true);",
            media_seek,
            playback_rate,
            "  v.addEventListener('pause', try_valid, true);",
            "  v.onload=function(){v.play();}",
            "  tmr=setTimeout(try_valid, %d); // timeout" % timeout,
            "</script>",
            "</body>",
            "</html>"])

        self._gen_count += 1
