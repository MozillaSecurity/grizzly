# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import os
import random

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]

class Template(object):
    def __init__(self, file_name):
        self._data = None # file data
        self.extension = None # file extension
        self.file_name = file_name # file name of the template

        if self.file_name is None:
            raise IOError("File does not exist: %s" % self.file_name)

        if "." in self.file_name:
            self.extension = os.path.splitext(self.file_name)[1].lstrip(".")


    def get_data(self):
        # load template data the first time it is requested
        if self._data is None:
            if not os.path.isfile(self.file_name):
                raise IOError("File does not exist: %s" % self.file_name)

            with open(self.file_name, "rb") as in_fp:
                self._data = in_fp.read()

        return self._data


class TestCase(object):
    def __init__(self, file_ext=None, template_file=None):
        self._template_file = template_file # file name of the template
        self.data = None # data that will be used in test
        self.raw_data = None # raw fuzzed data

        # use manually specified file ext
        if file_ext is not None:
            self.extension = file_ext
        # use file ext from template file
        elif self._template_file is not None and "." in self._template_file:
            self.extension = os.path.splitext(self._template_file)[1].lstrip(".")
        # no available file ext to use
        else:
            self.extension = None


    def dump(self, log_dir, file_prefix):
        output_name = os.path.join(log_dir, file_prefix)

        # save html test page
        with open(".".join([output_name, "html"]), "wb") as out_fp:
            out_fp.write(self.data)

        # save raw test case
        output_name = "%s_raw" % output_name
        if self.extension is not None:
            output_name = ".".join([output_name, self.extension])
        with open(output_name, "wb") as out_fp:
            out_fp.write(self.raw_data)


    def get_template_name(self):
        if self._template_file is not None:
            return os.path.basename(self._template_file)
        return None


class CorpusManager(object):
    """
    CorpusManager is the base class that is used when creating specific corpus
    managers.
    """

    def __init__(self, path, aggression=0.001, is_replay=False, rotate=10):
        self._active_template = None
        self._corpus_path = path
        self._fuzzer = None
        self._generated = 0 # number of test cases generated
        self._is_replay = is_replay
        self._rotate_period = 0 if is_replay else rotate # how often a new template is selected
        self._templates = list() # fuzzed test cases will be based on these files

        self._init_fuzzer(aggression)
        self._scan_for_templates()


    def _init_fuzzer(self, aggression):
        raise NotImplementedError("_init_fuzzer implemented in subclass")


    def _scan_for_templates(self):
        # ignored_list is a list of ignored files (usually auto generated OS files)
        ignored_list = ["desktop.ini", "thumbs.db"]
        self._templates = list()
        if os.path.isdir(self._corpus_path):
            abs_path = os.path.abspath(self._corpus_path)
            for test_file in os.listdir(abs_path):
                # check for unwanted files
                if test_file.startswith(".") or test_file.lower() in ignored_list:
                    continue
                test_file = os.path.join(abs_path, test_file)
                if os.path.isfile(test_file) and os.path.getsize(test_file) > 0:
                    self._templates.append(test_file)
        elif os.path.isfile(self._corpus_path) and os.path.getsize(self._corpus_path) > 0:
            self._templates.append(os.path.abspath(self._corpus_path))

        # order list for replay to help manually remove items if needed
        if self._is_replay:
            # reverse since we use .pop()
            self._templates.sort(reverse=True)

        if not self._templates:
            raise IOError("Could not find test case(s) at %s" % self._corpus_path)


    @staticmethod
    def _to_data_url(data, mime_type=None):
        if mime_type is None:
            mime_type = "application/octet-stream"
        return "data:%s;base64,%s" % (mime_type, base64.standard_b64encode(data))


    def _generate(self, template, redirect_page, mime_type=None):
        raise NotImplementedError("_generate must be implemented in the subclass")


    def generate(self, redirect_page, mime_type=None):
        # check if we should choose a new active template
        if self._rotate_period > 0 and (self._generated % self._rotate_period) == 0:
            # rescan test case directory to pick up any new additions
            self._scan_for_templates()
            # only switch templates if we have more than one
            if len(self._templates) > 1:
                self._active_template = None

        # choose a template
        if self._is_replay:
            self._active_template = Template(self._templates.pop())
        elif self._active_template is None:
            self._active_template = Template(random.choice(self._templates))

        self._generated += 1
        return self._generate(self._active_template, redirect_page, mime_type=mime_type)


    def get_active_file_name(self):
        try:
            return self._active_template.file_name
        except AttributeError:
            return None


    def size(self):
        return len(self._templates)
