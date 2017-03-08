# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import random

import corpman
import loki

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class FontCorpusManager(corpman.CorpusManager):
    """
    FontCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
    and embed it in a document suitable for processing by a web browser.
    """

    key = "font"

    def _init_fuzzer(self, aggression):
        self._fuzzer = loki.Loki(aggression)
        self._use_transition = False


    def _generate(self, test_case, redirect_page, mime_type=None):
        f_ext = os.path.splitext(test_case.template.file_name)[-1]
        data_file = "".join(["test_data_%d" % self._generated, f_ext])

        test_case.add_testfile(
            corpman.TestFile(data_file, self._fuzzer.fuzz_data(test_case.template.get_data())))

        # prepare data for playback
        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "<style>",
            "@font-face {",
            "  font-family: TestFont;",
            "  src: url('%s');" % data_file,
            "}",
            "body { font-family: 'TestFont' }",
            "</style>",
            "</head>",
            "<body>",
            "".join(["&#x%02x;" % i for i in range(32, 4096)]),
            "</body>",
            "<script>",
            "  var tmr;",
            "  function reset(){clearTimeout(tmr);window.location='/%s';}" % redirect_page,
            "  document.body.onload=reset;",
            "  tmr=setTimeout(reset, 5000); // timeout",
            "</script>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
