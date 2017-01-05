# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import random

import corpman
import loki

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class BasicImageCorpusManager(corpman.CorpusManager):
    """
    BasicImageCorpusManager is a CorpusManager that uses the loki fuzzer to mutate
    data and embed it in a document suitable for processing by a web browser.
    """

    key = "image_basic"

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
            return random.randint(1, 4)


    def _generate(self, test_case, redirect_page, mime_type=None):
        f_ext = os.path.splitext(test_case.template.file_name)[-1]
        data_file = "".join(["test_data_%d" % self._generated, f_ext])

        if self._is_replay:
            test_case.add_testfile(
                corpman.TestFile(data_file, test_case.template.get_data()))
        else:
            test_case.add_testfile(
                corpman.TestFile(data_file, self._fuzzer.fuzz_data(test_case.template.get_data())))

        if mime_type is None:
            if f_ext in (".jpeg", ".jpg"):
                mime_type = "image/jpeg"
            elif f_ext == ".ico":
                mime_type = "image/x-icon"
            elif f_ext in (".bmp", ".gif", ".png"):
                mime_type = "image/%s" % f_ext.lstrip(".")

        # prepare data for playback
        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<img id='m1' src='/%s'>" % data_file,
            "<img id='m2' height='2' width='2'>",
            "<canvas id='c1'></canvas>",
            "<script>",
            "  var tmr;",
            "  var im1=document.getElementById('m1');",
            "  function done(){",
            "    clearTimeout(tmr);",
            "    window.location='/%s';" % redirect_page,
            "  }",
            "  im1.addEventListener('error', done, true);",
            "  window.onload=function(){",
            "    var im2=document.getElementById('m2');",
            "    im2.src=im1.src;",
            "    var ctx=document.getElementById('c1').getContext('2d');",
            "    ctx.drawImage(im1, 0, 0); // sync docoder call",
            "    ctx.drawImage(im2, 0, 0); // sync downscaler call",
            "    im2.height=%d;" % self._random_dimention(),
            "    im2.width=%d;" % self._random_dimention(),
            "    ctx.drawImage(im2, 0, 0);",
            "    done();",
            "  }",
            "  tmr=setTimeout(done, 5000); // timeout",
            "</script>",
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
