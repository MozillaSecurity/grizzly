# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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


    def _init_fuzzer(self, _):
        self._fuzzer = None
        self._use_transition = False


    def _generate(self, test_case, redirect_page, mime_type=None):
        if self._is_replay:
            raise RuntimeError("AvalancheCorpusManager does not support replay mode")

        # init fuzzer if needed
        if self._fuzzer is None:
            with open(test_case.template.file_name, "r") as gmr_fp:
                self._fuzzer = avalanche.Grammar(gmr_fp)

        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<script>",
            "var tmr;",
            "function set_duration(){tmr=setTimeout(done, 5000)}",
            "function done(){",
            "  clearTimeout(tmr);",
            "  try{fuzzPriv.GC()}catch(e){}",
            "  try{fuzzPriv.CC()}catch(e){}",
            "  document.body.bgColor='FEFFFE';",
            "  window.location='/%s';" % redirect_page,
            "}",
            "window.onload=set_duration;",
            "</script>",
            "</head>",
            "<body id='test_body'>",
            self._fuzzer.generate(),
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
