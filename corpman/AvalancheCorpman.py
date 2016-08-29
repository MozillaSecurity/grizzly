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


    def _generate(self, template, redirect_page, mime_type=None):
        if self._is_replay:
            raise RuntimeError("AvalancheCorpusManager does not support replay mode")

        # init fuzzer if needed
        if self._fuzzer is None:
            with open(template.file_name, "r") as gmr_fp:
                self._fuzzer = avalanche.Grammar(gmr_fp)

        timeout = 5000 # test case timeout
        test = corpman.TestCase(template=template, file_ext="html")
        test.data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<script>",
            "  var tmr;",
            "  function set_duration(){tmr=setTimeout(done, %d)}" % timeout,
            "  function done(){",
            "    clearTimeout(tmr);",
            "    document.body.bgColor='FEFFFE';",
            "    //document.getElementById('test_body').innerHTML='<p>done</p>';",
            "    window.location='/%s';" % redirect_page,
            "  }",
            "  window.onload=set_duration;",
            "</script>",
            "</head>",
            "<body id='test_body'>",
            self._fuzzer.generate(),
            "</body>",
            "</html>"])

        return test
