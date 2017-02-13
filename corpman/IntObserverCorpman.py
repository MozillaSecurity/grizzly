import random

import avalanche
import corpman

__author__ = "Raymond Forbes"
__credits__ = "Raymond Forbes"

class AvalancheCorpusManager(corpman.CorpusManager):
    """
    AvalancheCorpusManager is a CorpusManager that uses Avalanche to generate data
    and then embeds it in a document suitable for processing by a web browser.
    """

    key = "intobs"

    def _init_fuzzer(self, _):
        self._use_transition = False
        self._element_objs = None
        self._next_id = None
        self.enable_harness()
        self.test_duration = 5000

    def reset(self):
        self._next_id = 0
        self._element_objs = {}

    def link(self, element, obj):
        """
        add objects to element array
        """
        self._element_objs.setdefault(element, []).append(obj)
        return u""

    def unlink(self, element, obj):
        if obj in self._element_objs[element]:
            self._element_objs[element].remove(obj)
        return u""

    def lookup(self, element):
        return random.choice(self._element_objs[element])

    def rndid(self):
        id_ = self._next_id
        self._next_id += 1
        return u"%d" %id_

    def _generate(self, test_case, redirect_page, mime_type=None):
        if self._is_replay:
            raise RuntimeError("replay mode not supported")

        if self._fuzzer is None:
            with open(test_case.template.file_name, "r") as gmr_fp:
                self._fuzzer = avalanche.Grammar(gmr_fp,
                                                 link=self.link,
                                                 rndid=self.rndid,
                                                 lookup=self.lookup,
                                                 unlink=self.unlink)

        self.reset()

        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<script>",
            "var tmr=setTimeout(done, %d);" % self.test_duration,
            "function done(){",
            "  clearTimeout(tmr);",
            "  try{fuzzPriv.forceGC()}catch(e){}",
            "  try{fuzzPriv.CC()}catch(e){}",
            "  document.body.bgColor='FEFFFE';",
            "  window.close();",
            "}",
            "</script>",
            "</head>",
            "<body id='test_body'>",
            self._fuzzer.generate(),
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))



