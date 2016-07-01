# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
ImageCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
and embed it in a document suitable for processing by a web browser. This is
Firefox specific and it requires "dom.send_after_paint_to_content=true;" to
function properly. The intent is to force synchronization of the image
processing threads in the browser.
"""

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Timothy Nikkel"]

import base64
import random

import corpman
import loki

class ImageCorpusManager(corpman.CorpusManager):
    key = "image"

    def _init_fuzzer(self, aggression):
        self._fuzzer = loki.Loki(aggression)


    @staticmethod
    def _random_dimention():
        choice = random.randint(0, 2)
        if choice == 0:
            return random.randint(1, 0xFF)
        elif choice == 1:
            return (2**random.randint(2, 16)) + random.randint(-2, 2)
        elif choice == 2: # favor small to stress downscaler
            return random.randint(1, 10)


    def generate(self, media_type=None, redirect_page="done", timeout=5000):
        self._rotate_template()

        # prepare data for playback
        if self._is_replay:
            self._test.fuzzed_data = self._test.template_data
        else:
            if self._can_splice and random.randint(0, 20) == 0:
                with open(random.choice(self._test_cases), "rb") as fp:
                    self._test.fuzzed_data = self._fuzzer.splice_data((
                        self._test.template_data,
                        fp.read()))
            else:
                self._test.fuzzed_data = self._fuzzer.fuzz_data(self._test.template_data)

        # valid images used to trigger animation used to force sync decoding
        valid_img1 = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="
        valid_img2 = "data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACwAAAAAAQABAAACAkQBADs="

        if media_type is None:
            if self._test.extension in ("jpeg", "jpg"):
                media_type = "image/jpeg"
            elif self._test.extension == "ico":
                media_type = "image/x-icon"
            elif self._test.extension in ("bmp", "gif", "png"):
                media_type = "image/%s" % self._test.extension
            else:
                media_type = "application/octet-stream"

        fuzzed_img = "data:%s;base64,%s" % (
            media_type,
            base64.standard_b64encode(self._test.fuzzed_data)
        )

        self._test.test_data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<img id='m1'><br/>",
            "<script>",
            "  var im1=document.getElementById('m1');",
            "  var step_state=0;",
            "  var tmr;",
            "  function reset(){",
            "    clearTimeout(tmr);",
            "    window.removeEventListener('MozAfterPaint', handle_step, false);",
            "    window.location='/%s';" % redirect_page,
            "  }",
            "  function handle_step(){",
            "    step_state+=1;",
            "    if(step_state == 1){",
            "      im1.src='%s'; // 2nd valid image" % valid_img2,
            "    }",
            "    else if(step_state==2){ // fuzzed image",
            "      im1.src='%s';" % fuzzed_img,
            "    }",
            "    else if(step_state==3){ // force downscaler",
            "      im1.removeEventListener('load', handle_step, false);",
            "      window.addEventListener('MozAfterPaint', handle_step, false);",
            "      if(im1.height==2)",
            "        im1.height=1;",
            "      else",
            "        im1.height=2;",
            "      im1.getBoundingClientRect(); // flush layout",
            "    }",
            "    else if(step_state==4){ // force downscaler",
            "      if(im1.width==2)",
            "        im1.width=1;",
            "      else",
            "        im1.width=2;",
            "      im1.getBoundingClientRect(); // flush layout",
            "    }",
            "    else if(step_state==5){ // force downscaler",
            "      var rdim=%d;" % self._random_dimention(),
            "      if(im1.height==rdim)",
            "        im1.height=rdim+1;",
            "      else",
            "        im1.height=rdim;",
            "      im1.getBoundingClientRect(); // flush layout",
            "    }",
            "    else if(step_state==6){ // force downscaler",
            "      var rdim=%d;" % self._random_dimention(),
            "      if(im1.width==rdim)",
            "        im1.width=rdim+1;",
            "      else",
            "        im1.width=rdim;",
            "      im1.getBoundingClientRect(); // flush layout",
            "    }",
            "    else{",
            "      reset(); // test complete",
            "    }",
            "  }",
            "  tmr=setTimeout(reset, %d); // timeout" % timeout,
            "  im1.addEventListener('error', reset, true);",
            "  window.onload=function(){",
            "    setTimeout(function(){",
            "      im1.addEventListener('load', handle_step, false);",
            "      im1.src='%s'; // 1st valid image" % valid_img1,
            "    }, 0); // setTimeout to avoid paint suppression",
            "  }",
            "</script>",
            "</body>",
            "</html>"
        ])

        self._gen_count += 1
