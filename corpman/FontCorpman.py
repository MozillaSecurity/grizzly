# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
FontCorpusManager is a CorpusManager that uses the loki fuzzer to mutate data
and embed it in a document suitable for processing by a web browser.
"""

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


import base64
import string

import corpman
import loki


class FontCorpusManager(corpman.CorpusManager):
    key = "font"

    def _init_fuzzer(self, aggression):
        self._fuzzer = loki.Loki(aggression)


    def generate(self, media_type=None, redirect_page="done", timeout=1000):
        self._rotate_template()

        # prepare data for playback
        if self._is_replay:
            self._test.fuzzed_data = self._test.template_data
        else:
            self._test.fuzzed_data = self._fuzzer.fuzz_data(self._test.template_data)

        if media_type is None:
            media_type = "application/octet-stream"

        source = "data:%s;base64,%s" % (
            media_type,
            base64.standard_b64encode(self._test.fuzzed_data))

        self._test.test_data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "<style>",
            "@font-face {",
            "  font-family: TestFont;",
            "  src: url('%s');" % source,
            "}",
            "body { font-family: 'TestFont' }",
            "</style>",
            "<script>",
            "  var tmr;",
            "  function reset(){clearTimeout(tmr);window.location='/%s';}" % redirect_page,
            "  window.onload=reset;",
            "  tmr=setTimeout(reset, %d); // timeout" % timeout,
            "</script>",
            "</head>",
            "<body>",
            "".join(["&#x%02x;" % i for i in range(32, 4096)]),
            "</body>",
            "</html>"
        ])

        self._gen_count += 1
