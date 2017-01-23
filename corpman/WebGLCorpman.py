# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import argparse
import json
import random
import tempfile
import time
import copy
import corpman


__author__ = "Raymond Forbes"
__credits__ = ["Raymond Forbes"]

class WebGLCorpusManager(corpman.CorpusManager):
    """
   WebGLCorpusManager is a CorpusManager that uses the WebGL fuzzer to mutate data
    and embed it in a document suitable for processing by a web browser.
    """

    key = "webgl"

    def _init_fuzzer(self, aggression):
        self._fuzzer

    def _fuzz(self, frames):

        aggression = random.randint(1, 10)

        for _ in range(aggression):
            fuzz_choice = random.randint(0, 3)

            if fuzz_choice == 0: # shuffle frames
                random.shuffle(frames)
            elif fuzz_choice == 1: # duplicate frames
                self._duplicate_frames(frames)
            elif fuzz_choice == 2: # delete frames
                removed_frame = random.randint(1, len(frames) - 1)
                del frames[removed_frame]

    def _duplicate_frames(self, frames):

        total_frames = len(frames)
        chunk = random.randint(1, total_frames)
        starting_point = random.randint(0, (total_frames) - chunk)
        insertion_point = random.randint(0, (total_frames))

        working_frames = frames[starting_point:starting_point + chunk]

        frames.insert(insertion_point, working_frames)


    def _generate(self, test_case, redirect_page, mime_type=None):
        timeout = 5000 # test case timeout
         # test = corpman.TestCase(template=template)


        with open(test_case.template.file_name) as json_data:
            data = json.load(json_data)

        temp_data = copy.deepcopy(data)
        temp_frames = temp_data["frames"][0]

        self._fuzz(temp_frames)
        temp_data["frames"][0] = temp_frames

        with open(os.path.join('..', 'grizzly-private', 'resources', 'webgl', 'rr-utilities.js'), 'r') as fp:
            utility_data = fp.read()
        utilities_data_url = self.to_data_url(utility_data, mime_type="appliation/javascript")

        with open(os.path.join('..', 'grizzly-private', 'resources', 'webgl', 'webgl-rr.js'), 'r') as fp:
            webglrr_data = fp.read()
        webglrr_data_url = self.to_data_url(webglrr_data, mime_type="appliation/javascript")

        with tempfile.NamedTemporaryFile(delete=False) as outfile:
            json.dump(temp_data, outfile, indent=4)
            fuzzed_file_data = outfile.read()
        fuzzedfile_data_url = self.to_data_url(fuzzed_file_data, mime_type="appliation/json")


        # prepare data for playback
        data = "\n".join([
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<script>",
            "  var tmr;",
            "  function set_duration(){tmr=setTimeout(done, %d)}" % timeout,
            "  function done(){",
            "    clearTimeout(tmr);",
            "    //document.getElementById('sandbox').innerHTML='<p>done</p>';",
            "    window.location='/%s';" % redirect_page,
            "  }",
            "  window.onload=set_duration;",
            "</script>",
            "</head>",
            "<body>",
            "<script>",
            "window.WEBGLRR_DISABLE_ATTACH = null;",
            "</script>",
            "<script src='%s'>" % webglrr_data_url, "</script>",
            "<script src='%s'>" % utilities_data_url, "</script>",
            "<br/>",
            "Status: <span id='status'>-</span>",
            "<hr/>",
            "<div id='sandbox'></div>",
            "<hr/>",
            "<script>",
            "    // var srcPath = args['src'];",
            "    srcPath = '%s'" % fuzzedfile_data_url,
            "    if (srcPath) {",
            "        var xhr = new XMLHttpRequest();",
            "        xhr.open('GET', srcPath, true);",
            "        xhr.responseType = 'blob';",
            "        xhr.onreadystatechange = function(e) {",
            "            if (xhr.readyState != 4)",
            "                return;",
            "            var blob = xhr.response;",
            "            if (!blob) {",
            "                console.log('Failed to load blob from: ' + srcPath);",
            "                return;",
            "             }",
            "             FileInputChanged(blob);",
            "        };",
            "         xhr.send();",
            "    }",
            "</script>",
            "</body>",
            "</html>"])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))
