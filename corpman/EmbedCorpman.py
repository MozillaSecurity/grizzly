# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import corpman
import loki

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class EmbedCorpusManager(corpman.CorpusManager):
    key = "embed"

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
            "</head>",
            "<body>",
            "<iframe id='test_if' src='%s'></iframe>" % self._to_data_url(test.raw_data, mime_type),
            "<script>",
            "  var tmr;",
            "  tmr=setTimeout(reset, %d); // timeout" % timeout,
            "  function reset(){clearTimeout(tmr);window.location='/%s';}" % redirect_page,
            "  document.getElementById('test_if').onload=reset;",
            "</script>",
            "</body>",
            "</html>"])

        return test
