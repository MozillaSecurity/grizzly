# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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


    def _generate(self, template, redirect_page, mime_type=None):
        timeout = 5000 # test case timeout

        test = corpman.TestCase(template_file=template.file_name)
        if self._is_replay:
            test.raw_data = template.get_data()
        else:
            test.raw_data = self._fuzzer.fuzz_data(template.get_data())

        # prepare data for playback
        test.data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "<style>",
            "@font-face {",
            "  font-family: TestFont;",
            "  src: url('%s');" % self.to_data_url(test.raw_data, mime_type=mime_type),
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
            "</html>"])

        return test
