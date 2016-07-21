# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
AvalancheCorpusManager is a CorpusManager that uses Avalanche to generate data
and then embeds it in a document suitable for processing by a web browser.
"""

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

import os

import avalanche
import corpman

class AvalancheCorpusManager(corpman.CorpusManager):
    key = "avalanche"

    def _init_fuzzer(self, aggression):
        self._load_template()
        if self._is_replay:
            raise RuntimeError("AvalancheCorpusManager does not support replay mode")
        with open(self._test.template_name, "r") as gmr_file:
            self._fuzzer = avalanche.Grammar(gmr_file)


    def generate(self, media_type=None, redirect_page="done", timeout=5000):
        if not self._is_replay:
            self._test.fuzzed_data = self._fuzzer.generate()
        else:
            self._test.fuzzed_data = self._test.template_data

        self._test.test_data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<script>",
            "  var tmr;",
            "  function set_duration(){tmr=setTimeout(done, %d)}" % timeout,
            "  function done(){",
            "    clearTimeout(tmr);",
            "    document.body.bgColor='FEFFFE';",
            "    window.location='/%s';" % redirect_page,
            "  }",
            "  window.onload=set_duration;",
            "</script>",
            "</head>",
            "<body>",
            self._test.fuzzed_data,
            "</body>",
            "</html>"
        ])

        self._gen_count += 1
