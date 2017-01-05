# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os

import corpman
import loki

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class EmbedCorpusManager(corpman.CorpusManager):
    key = "embed"

    def _init_fuzzer(self, aggression):
        self._fuzzer = loki.Loki(aggression)


    def _generate(self, test_case, redirect_page, mime_type=None):
        f_ext = os.path.splitext(test_case.template.file_name)[-1]
        data_file = "".join(["test_data_%d" % self._generated, f_ext])

        if self._is_replay:
            test_case.add_testfile(
                corpman.TestFile(data_file, test_case.template.get_data()))
        else:
            test_case.add_testfile(
                corpman.TestFile(data_file, self._fuzzer.fuzz_data(test_case.template.get_data())))

        # prepare data for playback
        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta http-equiv='Cache-control' content='no-cache'>",
            "</head>",
            "<body>",
            "<iframe id='test_if' src='/%s'></iframe>" % data_file,
            "<script>",
            "  var tmr;",
            "  tmr=setTimeout(reset, 5000); // timeout",
            "  function reset(){clearTimeout(tmr);window.location='/%s';}" % redirect_page,
            "  document.getElementById('test_if').onload=reset;",
            "</script>",
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
