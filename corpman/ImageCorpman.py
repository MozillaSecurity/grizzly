# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import random

import corpman
import loki

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith", "Timothy Nikkel"]

class ImageCorpusManager(corpman.CorpusManager):
    """
    ImageCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
    and embed it in a document suitable for processing by a web browser. This is
    Firefox specific and it requires "dom.send_after_paint_to_content=true;" to
    function properly. The intent is to force synchronization of the image
    processing threads in the browser.
    """

    key = "image"

    def _init_fuzzer(self):
        self._fuzzer = loki.Loki(0.001)


    @staticmethod
    def _random_dimention():
        choice = random.randint(0, 2)
        if choice == 0:
            return random.randint(1, 0xFF)
        elif choice == 1:
            return (2**random.randint(2, 16)) + random.randint(-2, 2)
        elif choice == 2: # favor small to stress downscaler
            return random.randint(1, 10)


    def _generate(self, test_case, redirect_page, mime_type=None):
        f_ext = os.path.splitext(self._active_input.file_name)[-1]
        data_file = "".join(["test_data_%d" % self._generated, f_ext])

        test_case.add_testfile(
            corpman.TestFile(data_file, self._fuzzer.fuzz_data(self._active_input.get_data())))

        # valid images used to trigger animation used to force sync decoding
        valid_img1 = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="
        valid_img2 = "data:image/gif;base64,R0lGODlhAQABAIABAP///wAAACwAAAAAAQABAAACAkQBADs="

        # prepare data for playback
        data = "\n".join([
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
            "    window.location='%s';" % redirect_page,
            "  }",
            "  function handle_step(){",
            "    step_state+=1;",
            "    if(step_state == 1){",
            "      im1.src='%s'; // 2nd valid image" % valid_img2,
            "    }",
            "    else if(step_state==2){ // fuzzed image",
            "      im1.src='%s';" % data_file,
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
            "  tmr=setTimeout(reset, %d);" % self.test_duration,
            "  im1.addEventListener('error', reset, true);",
            "  document.addEventListener('DOMContentLoaded', function(){",
            "    setTimeout(function(){",
            "      im1.addEventListener('load', handle_step, false);",
            "      im1.src='%s'; // 1st valid image" % valid_img1,
            "    }, 0); // setTimeout to avoid paint suppression",
            "  });",
            "</script>",
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
