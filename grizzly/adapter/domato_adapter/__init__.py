import os
import random
import time

from grizzly.adapter import Adapter
from grizzly.common import storage

DOMATO_PATH = input("Enter full path to your domato directory : ")

class DomatoAdapter(Adapter):
    NAME = "domato"
    FILES = input("Enter number of files to be generated for each adaptyer testcase : ")

    def setup(self, _):
        self.enable_harness()
        # create directory to temporarily store generated content
        self.fuzz["tmp"] = "./fuzztest{}".format(random.random())

        os.mkdir(self.fuzz['tmp'])
        
        if os.environ.get("FUZZTOOL"):
            run = "python3 {}".format(os.environ["FUZZTOOL"])
        else:
            run = "python3 {}".format(DOMATO_PATH)
        # command used to call fuzzer to generate output
        self.fuzz["cmd"] = [
            run,  # binary to call
            "--no_of_files", "1",
            "--output_dir", self.fuzz["tmp"]
        ]

        
    def generate(self, testcase, *_):
        # launch fuzzer to generate a single file
        # subprocess.check_output(self.fuzz["cmd"])
        # subprocess.Popen(self.fuzz["cmd"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE )

        # lookup the name of the newly generated file on disk

        os.system("python3 {} --no_of_files {} --output_dir {}".format(DOMATO_PATH, self.fuzz["tmp"]))
        time.sleep(3)

        gen_file = os.path.join(self.fuzz["tmp"], os.listdir(self.fuzz["tmp"])[0])
        # remove generated file now that the data has been added to a test file
        test_file = storage.TestFile.from_file(gen_file, testcase.landing_page)
        # remove generated file now that the data has been added to a test file
        os.remove(gen_file)
        # add test file to the testcase
        testcase.add_file(test_file)