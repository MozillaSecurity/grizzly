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

    def _init_fuzzer(self, _):
        self.enable_harness()
        self.webgl_frames = []

    def _fuzz(self):

        aggression = random.randint(1, 10)

        for _ in range(aggression):
            #fuzz_choice = random.randint(0, 2)
            fuzz_choice = 1
            if fuzz_choice == 0: # shuffle frames
                exit(0)
                #self._munge_setup()
            elif fuzz_choice == 1:
                self._munge_buffer_data()
            elif fuzz_choice == 2:
                exit(0)

    def _munge_buffer_data(self):
        buffer_constants_list = ['__GL_STATIC_DRAW',
                                 '__GL_STREAM_DRAW',
                                 '__GL_DYNAMIC_DRAW',
                                 '__GL_ARRAY_BUFFER',
                                 '__GL_ELEMENT_ARRAY_BUFFER',
                                 '__GL_BUFFER_SIZE',
                                 '__GL_BUFFER_USAGE']

        for frameset in self.webgl_frames["frames"]:
            temp_frames = []
            for frame in frameset:
                if frame[1] == "bufferData":
                    new_frame = copy.deepcopy(frame)
                    new_frame[-1][-1] = buffer_constants_list[random.randint(0, len(buffer_constants_list) - 1)]
                    temp_frames.append(new_frame)
            if len(temp_frames) > 0:
                for item in temp_frames:
                    frameset.append(item)

    def _munge_setup(self):
    
        aggression = random.randint(1, 10)

        for _ in range(aggression):

            fuzz_choice = random.randint(0, 3)

            if fuzz_choice == 0: # shuffle frames
                random.shuffle(self.webgl_frames)
            elif fuzz_choice == 1: # duplicate frames
                self._duplicate_frames()
            elif fuzz_choice == 2: # delete frames
                removed_frame = random.randint(1, len(self.webgl_frames) - 1)
                del self.webgl_frames[removed_frame]

    def _duplicate_frames(self):
        total_frames = len(self.webgl_frames)
        chunk = random.randint(1, total_frames)
        starting_point = random.randint(0, (total_frames) - chunk)
        insertion_point = random.randint(0, (total_frames))

            # working_frames = frames[starting_point:starting_point + chunk]


    def _generate(self, test_case, redirect_page, mime_type=None):
        with open(test_case.template.file_name) as json_data:
            self.webgl_frames = json.load(json_data)

        self._fuzz()

        with open(os.path.join('..', 'grizzly-private', 'resources', 'webgl', 'utilities.js'), 'r') as fp:
            utilities_data_url = self.to_data_url(fp.read(), mime_type="appliation/javascript")

        with open(os.path.join('..', 'grizzly-private', 'resources', 'webgl', 'webgl-rr.js'), 'r') as fp:
            webglrr_data_url = self.to_data_url(fp.read(), mime_type="appliation/javascript")

        fuzzedfile_data_url = self.to_data_url(json.dumps(self.webgl_frames, indent=4), mime_type="appliation/json")
        # prepare data for playback
        data = "\n".join([
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<meta charset='UTF-8'>",
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
            "<body>",
            "<script>",
            "    window.WEBGLRR_DISABLE_ATTACH = null;",
            "</script>",
            "<script src='%s'>" % webglrr_data_url, "</script>",
            "<script src='%s'>" % utilities_data_url, "</script>",
            "<br/>",
            "Status: <span id='status'>-</span>",
            "<hr/>",
            "<div id='sandbox'></div>",
            "<hr/>",
            "<script>",
            "   var srcPath = '%s'" % fuzzedfile_data_url,
            "   if (srcPath) {",
            "       var xhr = new XMLHttpRequest();",
            "       xhr.open('GET', srcPath, true);",
            "       xhr.responseType = 'blob';",
            "       xhr.onreadystatechange = function(e) {",
            "        if (xhr.readyState != 4)",
            "            return;",
            "        var blob = xhr.response;",
            "        if (!blob) {",
            "            console.log('Failed to load blob from: ' + srcPath);",
            "            return;",
            "           }",
            "        FileInputChanged(blob);",
            "    };",
            "    xhr.send();",
            "    NextFrame();",
            "   }",
            " </script>",
            "</body>",
            "</html>"
            ])

        test_case.add_testfile(corpman.TestFile(test_case.landing_page, data))

        