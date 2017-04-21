# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os

import avalanche
import corpman

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class AvalancheCorpusManager(corpman.CorpusManager):
    """
    AvalancheCorpusManager is a CorpusManager that uses Avalanche to generate data
    and then embeds it in a document suitable for processing by a web browser.
    """

    key = "avalanche"


    def _init_fuzzer(self):
        self.enable_harness()

        assert len(self.input_files) == 1 and os.path.isfile(self.input_files[0])
        with open(self.input_files[0], "r") as gmr_fp:
            self._fuzzer = avalanche.Grammar(gmr_fp)


    def _generate(self, test_case, redirect_page, mime_type=None):
        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<script>",
            #"dump('loading %s\\n');" % test_case.landing_page,
            "var tmr=setTimeout(done, %d);" % self.test_duration,
            "function done(){",
            "  clearTimeout(tmr);",
            "  try{fuzzPriv.forceGC()}catch(e){}",
            "  try{fuzzPriv.CC()}catch(e){}",
            "  document.body.bgColor='FEFFFE';",
            "  dump('%s complete\\n');" % test_case.landing_page,
            "  window.close();",
            "}",
            "</script>",
            "</head>",
            "<body id='test_body'>",
            self._fuzzer.generate(),
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
