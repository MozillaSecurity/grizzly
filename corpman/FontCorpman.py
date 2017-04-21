# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import random
import subprocess
import tempfile

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

    def _init_fuzzer(self):
        self._use_transition = False
        self._fuzzer = {}
        self._fuzzer["loki"] = loki.Loki(0.001)
        try:
            self._fuzzer["radamsa"] = subprocess.check_output(["which", "radamsa"]).strip()
        except (OSError, subprocess.CalledProcessError):
            self._fuzzer["radamsa"] = None

        chr_ranges = (
            (0x21, 0x7E),
            (0xA1, 0x58F),
            (0x590, 0x6FF),
            (0x700, 0xFFF),
            (0xAA80, 0xAADF))

        self._fuzzer["text"] = ""
        for chr_range in chr_ranges:
            self._fuzzer["text"] += "".join(["&#x%02x;" % i for i in range(chr_range[0], chr_range[1])])

    def _generate(self, test_case, redirect_page, mime_type=None):
        f_ext = os.path.splitext(self._active_input.file_name)[-1]
        data_file = "".join(["test_data_%d" % self._generated, f_ext])

        if self._fuzzer["radamsa"] is not None and random.randint(0, 1) == 0:
            with tempfile.TemporaryFile() as fp:
                #subprocess.call([self._fuzzer["radamsa"], "-r", self._corpus_path], stdout=fp)
                subprocess.call([self._fuzzer["radamsa"], self._active_input.file_name], stdout=fp)
                fp.seek(0)
                test_case.add_testfile(
                    corpman.TestFile(data_file, fp.read()))
        else:
            test_case.add_testfile(
                corpman.TestFile(data_file, self._fuzzer["loki"].fuzz_data(self._active_input.get_data())))

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
            "body { font-family: 'TestFont'; word-wrap: break-word; }",
            "</style>",
            "</head>",
            "<body>",
            self._fuzzer["text"],
            "</body>",
            "<script>",
            "  var tmr;",
            "  function done(){clearTimeout(tmr);window.location='/%s';}" % redirect_page,
            "  tmr=setTimeout(done, %d);" % self.test_duration,
            "  document.body.onload=function(){",
            "    document.body.style.fontSize='8px';",
            "    document.body.style.fontSize='12px';",
            "    document.body.style.fontSize='24px';",
            "    document.body.style.fontSize='40px';",
            "    document.body.style.fontSize='64px';",
            "    done();"
            "  }",
            "</script>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
