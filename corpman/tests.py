import logging
import os
import shutil
import tempfile
import unittest

import corpman


logging.basicConfig(level=logging.DEBUG if bool(os.getenv("DEBUG")) else logging.INFO)
log = logging.getLogger("corpman_test")


class EnvVarCorpman(corpman.CorpusManager):
    key = "envvar"
    def _init_fuzzer(self):
        self.add_required_envvar("RANDOM_ENVAR_TEST")
        self.add_required_envvar("RANDOM_ENVAR_TEST2", "test123")
        self.add_required_envvar("RANDOM_ENVAR_TEST3", "3test3")
    def _generate(self, testcase, redirect_page, mime_type=None):
        testcase.add_testfile(corpman.TestFile(testcase.landing_page, redirect_page))
        return testcase

class SimpleCorpman(corpman.CorpusManager):
    key = "simple"
    def _init_fuzzer(self):
        self.add_abort_token("ABORT_TOKEN")
    def _generate(self, testcase, redirect_page, mime_type=None):
        testcase.add_testfile(corpman.TestFile(testcase.landing_page, redirect_page))
        return testcase


class SinglePassCorpman(corpman.CorpusManager):
    key = "single_pass"
    def _init_fuzzer(self):
        self.rotation_period = 1
        self.single_pass = True
    def _generate(self, testcase, redirect_page, mime_type=None):
        testcase.add_testfile(corpman.TestFile(self._active_input.file_name, self._active_input.get_data()))
        testcase.add_testfile(corpman.TestFile(testcase.landing_page, redirect_page))
        return testcase


class CorpusManagerTests(unittest.TestCase):
    def setUp(self):
        self.tdir = tempfile.mkdtemp(prefix="cm_tests")

    def tearDown(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def test_00(self):
        "test a basic corpus manager"
        # create template
        template_file = os.path.join(self.tdir, "test_template.bin")
        with open(template_file, "wb") as fp:
            fp.write("template_data")
        # create corpman
        cm = SimpleCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.key, "simple")
        self.assertEqual(cm.size(), 1) # we only added one template
        self.assertIsNone(cm.active_file) # None since generate() has not been called
        self.assertEqual(cm.landing_page(), "test_page_0000.html")
        self.assertEqual(cm.landing_page(transition=True), "next_test")
        self.assertIsNone(cm.br_mon.clone_log("stderr"))
        self.assertEqual(cm.br_mon.launch_count(), 0) # should default to 0 and be incremented by ffpuppet.py
        self.assertFalse(cm.br_mon.is_running())
        self.assertIsNone(cm.br_mon.log_data("stderr"))
        self.assertEqual(cm.br_mon.log_length("stderr"), 0)
        self.assertIn("ABORT_TOKEN", cm.abort_tokens)

    def test_01(self):
        "test CorpusManager generate() creates TestCases and TestFiles using SimpleCorpman"
        corp_dir = tempfile.mkdtemp(prefix="crp_", dir=self.tdir)
        template_file = os.path.join(corp_dir, "test_template.bin")
        with open(template_file, "wb") as fp:
            fp.write("template_data")
        cm = SimpleCorpman(corp_dir)
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.landing_page(), "test_page_0000.html")
        tc = cm.generate()
        # check for transition redirect
        self.assertEqual("next_test", cm.redirects[0]["url"])
        # make sure we move forwarded when generate() is called
        self.assertEqual(cm.landing_page(), "test_page_0001.html")
        self.assertEqual(cm.active_file, template_file)
        self.assertIsInstance(tc, corpman.TestCase)
        self.assertEqual(tc.landing_page, "test_page_0000.html")
        tc_dir = tempfile.mkdtemp(prefix="tc_", dir=self.tdir)
        tc.dump(tc_dir, include_details=True)
        dumped_tf = os.listdir(tc_dir) # dumped test files
        self.assertIn("test_page_0000.html", dumped_tf)

    def test_02(self):
        "test CorpusManager multiple calls to generate() and template rotation"
        selected_templates = set()
        # create templates
        for i in range(10):
            with open(os.path.join(self.tdir, "test_template_%d.bin" % i), "wb") as fp:
                fp.write("template_data_%d" % i)
        cm = SimpleCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        cm.rotation_period = 1
        for i in range(50):
            self.assertEqual(cm.landing_page(), "test_page_%04d.html" % i)
            cm.generate()
            self.assertEqual(cm.landing_page(), "test_page_%04d.html" % (i+1))
            selected_templates.add(cm.active_file)
        # make sure we rotate templates
        self.assertGreater(len(selected_templates), 1)

    def test_03(self):
        "test CorpusManager single pass mode"
        selected_templates = set()
        # create templates
        template_count = 10
        for i in range(template_count):
            with open(os.path.join(self.tdir, "test_template_%d.bin" % i), "wb") as fp:
                fp.write("template_data_%d" % i)
        cm = SinglePassCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.size(), template_count)
        for _ in range(template_count):
            tc = cm.generate()
            self.assertEqual(len(tc._test_files), 2)
            selected_templates.add(cm.active_file)
        # make sure we cover all the input files
        self.assertEqual(len(selected_templates), template_count)
        self.assertEqual(cm.size(), 0)

    def test_04(self):
        "test single template file"
        # create templates
        for i in range(10):
            with open(os.path.join(self.tdir, "test_template_%d.bin" % i), "wb") as fp:
                fp.write("template_data_%d" % i)
        cm = SimpleCorpman(os.path.join(self.tdir, "test_template_0.bin"))
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.size(), 1)

    def test_05(self):
        "test multiple template files in nested directories"
        corp_dir = tempfile.mkdtemp(prefix="crp_", dir=self.tdir)
        nd_1 = tempfile.mkdtemp(prefix="test1_", dir=corp_dir)
        nd_2 = tempfile.mkdtemp(prefix="test2_", dir=corp_dir)
        # create templates
        template_count = 10
        for i in range(template_count):
            with open(os.path.join(nd_1, "test_template_%d.bin" % i), "wb") as fp:
                fp.write("template_data_%d" % i)
        for i in range(template_count):
            with open(os.path.join(nd_2, "test_template_%d.bin" % i), "wb") as fp:
                fp.write("template_data_%d" % i)
        cm = SimpleCorpman(corp_dir)
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.size(), template_count*2)

    def test_06(self):
        "test multiple template files with extension filter"
        # create templates
        for i in range(10):
            with open(os.path.join(self.tdir, "test_template_%d.bad" % i), "wb") as fp:
                fp.write("template_data_%d" % i)
        with open(os.path.join(self.tdir, "test_template.good"), "wb") as fp:
            fp.write("template_data")
        cm = SimpleCorpman(self.tdir, accepted_extensions=["good"])
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.size(), 1)

    def test_07(self):
        "test ignore empty template files and blacklisted files"
        # create templates
        with open(os.path.join(self.tdir, "test_template.good"), "wb") as fp:
            fp.write("template_data")
        with open(os.path.join(self.tdir, "test_template.empty"), "wb") as fp:
            fp.write("")
        with open(os.path.join(self.tdir, ".somefile"), "wb") as fp:
            fp.write("template_data")
        # /me crosses fingers and hopes this test doesn't break something on Windows...
        with open(os.path.join(self.tdir, "thumbs.db"), "wb") as fp:
            fp.write("template_data")
        cm = SimpleCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.size(), 1)

    def test_08(self):
        "test extension filter normalization"
        # create templates
        with open(os.path.join(self.tdir, "test_template.bad"), "wb") as fp:
            fp.write("template_data")

        with open(os.path.join(self.tdir, "test_template1.good"), "wb") as fp:
            fp.write("template_data")

        with open(os.path.join(self.tdir, "test_template2.GOOD"), "wb") as fp:
            fp.write("template_data")

        with open(os.path.join(self.tdir, "test_template2.GReat"), "wb") as fp:
            fp.write("template_data")

        cm = SimpleCorpman(self.tdir, accepted_extensions=["good", ".greaT"])
        self.addCleanup(cm.cleanup)
        self.assertEqual(cm.size(), 3)

    def test_09(self):
        "test corpus manager with default harness"
        corp_dir = tempfile.mkdtemp(prefix="crp_", dir=self.tdir)
        tc_dir = tempfile.mkdtemp(prefix="tc_", dir=self.tdir)
        # create templates
        with open(os.path.join(corp_dir, "test_template.bin"), "wb") as fp:
            fp.write("template_data")

        cm = SimpleCorpman(corp_dir)
        self.addCleanup(cm.cleanup)
        cm.enable_harness()
        self.assertEqual(cm.landing_page(harness=True), "grizzly_fuzz_harness.html")
        self.assertEqual(cm.size(), 1)

        expected_test = cm.landing_page()
        tc = cm.generate()
        tc.dump(tc_dir)

        # verify test files
        dumped_tf = os.listdir(tc_dir) # dumped test files
        self.assertEqual(len(dumped_tf), 2) # expect test and harness
        self.assertIn(expected_test, dumped_tf)
        self.assertIn(cm.landing_page(harness=True), dumped_tf)

        # verify redirects
        self.assertEqual(len(cm.redirects), 2)
        r_count = 0
        for redir in cm.redirects:
            self.assertIn(redir["url"], ["next_test", "first_test"])
            if redir["url"] == "first_test":
                self.assertEqual(redir["file_name"], expected_test)
            elif redir["url"] == "next_test":
                self.assertEqual(redir["file_name"], cm.landing_page())
            if redir["required"]:
                r_count += 1
        self.assertEqual(r_count, 1)

    def test_10(self):
        "test corpus manager landing_page() without a harness"
        # create templates
        with open(os.path.join(self.tdir, "test_template.bin"), "wb") as fp:
            fp.write("template_data")

        cm = SimpleCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        self.assertIn(cm.landing_page(harness=True), "test_page_0000.html")

    def test_11(self):
        "test get/set and reset redirects"
        # create templates
        with open(os.path.join(self.tdir, "test_template.bin"), "wb") as fp:
            fp.write("template_data")
        cm = SimpleCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        test_redirs = (
            ("url1", "file1", True),
            ("url2", "file2", False),
            ("url3", "file3", True),
            ("url3", "file4", False))
        for url, name, reqd in test_redirs:
            cm._set_redirect(url, name, reqd)
        self.assertEqual(len(cm.redirects), 3)
        self.assertEqual(len([redir for redir in cm.redirects if redir["required"]]), 1)
        cm.generate()

    def test_12(self):
        "test get/set includes"
        corp_dir = tempfile.mkdtemp(prefix="crp_", dir=self.tdir)
        inc_dir = tempfile.mkdtemp(prefix="inc_", dir=self.tdir)
        # create templates
        with open(os.path.join(corp_dir, "dummy_template.bin"), "wb") as fp:
            fp.write("template_data")
        cm = SimpleCorpman(corp_dir)
        self.addCleanup(cm.cleanup)
        cm._add_include("/", inc_dir)
        with self.assertRaises(IOError):
            cm._add_include("bad_path", "/does_not_exist/asdf")
        self.assertEqual(len(cm.includes), 1)

    def test_13(self):
        "test get/set and reset dynamic responses (callbacks)"
        def test_callback():
            return "PASS"
        # create templates
        with open(os.path.join(self.tdir, "test_template.bin"), "wb") as fp:
            fp.write("template_data")
        cm = SimpleCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        cm._add_dynamic_response("test_url", test_callback, mime_type="text/plain")
        self.assertEqual(len(cm.dynamic_responses), 1)
        self.assertEqual(cm.dynamic_responses[0]["callback"](), "PASS")

    def test_14(self):
        "test adding test files in nested directories"
        corp_dir = tempfile.mkdtemp(prefix="crp_", dir=self.tdir)
        tc_dir = tempfile.mkdtemp(prefix="tc_", dir=self.tdir)
        template_file = os.path.join(corp_dir, "test_template.bin")
        with open(template_file, "wb") as fp:
            fp.write("template_data")
        cm = SimpleCorpman(corp_dir)
        self.addCleanup(cm.cleanup)
        tc = cm.generate()
        test_file_path = "test/dir/path/file.txt"
        tc.add_testfile(corpman.TestFile(test_file_path, "somedata"))
        tc.dump(tc_dir)
        self.assertTrue(os.path.isfile(os.path.join(tc_dir, test_file_path)))

    def test_15(self):
        "test a rotation period of 0 with single_pass true"
        with open(os.path.join(self.tdir, "test_template.bin"), "wb") as fp:
            fp.write("a")
        cm = SinglePassCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        cm.rotation_period = 0
        with self.assertRaises(AssertionError):
            cm.generate()

    def test_16(self):
        "test a negative rotation period"
        with open(os.path.join(self.tdir, "test_template.bin"), "wb") as fp:
            fp.write("a")
        cm = SimpleCorpman(self.tdir)
        self.addCleanup(cm.cleanup)
        cm.rotation_period = -1
        with self.assertRaises(AssertionError):
            cm.generate()

    def test_17(self):
        "test missing an environment variable check"
        # create template
        template_file = os.path.join(self.tdir, "test_template.bin")
        with open(template_file, "wb") as fp:
            fp.write("template_data")
        with self.assertRaisesRegexp(RuntimeError, "Missing environment variable!.+"):
            EnvVarCorpman(self.tdir)

    def test_18(self):
        "test environment variable & files are dumped"
        corp_dir = tempfile.mkdtemp(prefix="crp_", dir=self.tdir)
        tc_dir = tempfile.mkdtemp(prefix="tc_", dir=self.tdir)
        prf_dir = tempfile.mkdtemp(prefix="prf_", dir=self.tdir)
        try:
            # create template
            template_file = os.path.join(corp_dir, "test_template.bin")
            with open(template_file, "wb") as fp:
                fp.write("template_data")
            os.environ["RANDOM_ENVAR_TEST"] = ""
            os.environ["RANDOM_ENVAR_TEST2"] = "test123"
            os.environ["RANDOM_ENVAR_TEST3"] = "3test3"
            cm = EnvVarCorpman(corp_dir)
            self.addCleanup(cm.cleanup)
            tc = cm.generate()
            with self.assertRaises(IOError):
                tc.add_environ_file("nofile.js")
            env_file = os.path.join(prf_dir, "simple_prefs.js")
            with open(env_file, "wb") as fp:
                fp.write("stuff.blah=1;")
            tc.add_environ_file(env_file, fname="prefs.js")
            tc.dump(tc_dir, include_details=True)
            dumped_tf = os.listdir(tc_dir)
            self.assertIn("prefs.js", dumped_tf)
            self.assertIn("env_vars.txt", dumped_tf)
            with open(os.path.join(tc_dir, "env_vars.txt"), "r") as fp:
                env_vars = fp.read()
            self.assertRegexpMatches(env_vars, "RANDOM_ENVAR_TEST=\n")
            self.assertRegexpMatches(env_vars, "RANDOM_ENVAR_TEST2=test123\n")
            self.assertRegexpMatches(env_vars, "RANDOM_ENVAR_TEST3=3test3\n")
        finally:
            os.environ.pop("RANDOM_ENVAR_TEST", None)
            os.environ.pop("RANDOM_ENVAR_TEST2", None)
            os.environ.pop("RANDOM_ENVAR_TEST3", None)


class TestCaseTests(unittest.TestCase):
    def setUp(self):
        self.tdir = tempfile.mkdtemp(prefix="cm_tests")

    def tearDown(self):
        if os.path.isdir(self.tdir):
            shutil.rmtree(self.tdir)

    def test_01(self):
        "test empty TestCase"
        tc = corpman.TestCase("dummy_page.html", "dummy_cm")
        self.assertIsNone(tc.get_optional())
        tc.dump(self.tdir)
        self.assertFalse(os.listdir(self.tdir))
        tc.dump(self.tdir, include_details=True)
        self.assertIn("test_info.txt", os.listdir(self.tdir))

    def test_02(self):
        "test TestCase with TestFiles"
        tf1 = corpman.TestFile("testfile1.bin", "test_req")
        tf2 = corpman.TestFile(os.path.join("test_dir", "testfile2.bin"), "test_nreq", required=False)
        tf3 = corpman.TestFile("/testfile3.bin", "test_blah")
        tc = corpman.TestCase("land_page.html", "corp_name", input_fname="testinput.bin")
        tc.add_testfile(tf1)
        tc.add_testfile(tf2)
        tc.add_testfile(tf3)
        opt_files = tc.get_optional()
        self.assertEqual(len(opt_files), 1)
        self.assertIn("test_dir/testfile2.bin", opt_files)
        tc.dump(self.tdir, include_details=True)
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "test_info.txt")))
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "testfile1.bin")))
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "testfile3.bin")))
        self.assertTrue(os.path.isdir(os.path.join(self.tdir, "test_dir")))
        self.assertTrue(os.path.isfile(os.path.join(self.tdir, "test_dir", "testfile2.bin")))
        with open(os.path.join(self.tdir, "testfile1.bin"), "r") as test_fp:
            self.assertEqual(test_fp.read(), "test_req")
        with open(os.path.join(self.tdir, "test_dir", "testfile2.bin"), "r") as test_fp:
            self.assertEqual(test_fp.read(), "test_nreq")
        with open(os.path.join(self.tdir, "testfile3.bin"), "r") as test_fp:
            self.assertEqual(test_fp.read(), "test_blah")

    def test_03(self):
        "test TestCase add_environ_*()"
        tc = corpman.TestCase("land_page.html", "corp_name", input_fname="testinput.bin")
        with self.assertRaisesRegexp(IOError, "Could not find environ file '.+?no_file.txt'"):
            tc.add_environ_file("no_file.txt")
        env_file = os.path.join(self.tdir, "env_file.txt")
        env_file_data = "file_data\n"
        with open(env_file, "w") as test_fp:
            test_fp.write(env_file_data)
        tc.add_environ_file(env_file)
        tc.add_environ_file(env_file, fname="use_new_name.txt")
        tc.add_environ_var("TEST_ENV_VAR", "1")
        dmp_dir = os.path.join(self.tdir, "dmp_test")
        os.mkdir(dmp_dir)
        tc.dump(dmp_dir, include_details=True)
        dmp_contents = os.listdir(dmp_dir)
        self.assertIn("env_file.txt", dmp_contents)
        self.assertIn("use_new_name.txt", dmp_contents)
        self.assertIn("env_vars.txt", dmp_contents)
        with open(os.path.join(dmp_dir, "env_file.txt"), "r") as test_fp:
            self.assertEqual(test_fp.read(), env_file_data)
        with open(os.path.join(dmp_dir, "use_new_name.txt"), "r") as test_fp:
            self.assertEqual(test_fp.read(), env_file_data)
        with open(os.path.join(dmp_dir, "env_vars.txt"), "r") as test_fp:
            self.assertIn("TEST_ENV_VAR=1\n", test_fp.read())

    def test_04(self):
        "test InputFile object"
        # non-existing file
        with self.assertRaises(IOError):
            corpman.InputFile(os.path.join("foo", "bar", "none"))
        # existing file
        t_file = os.path.join(self.tdir, "testfile.bin")
        with open(t_file, "w") as test_fp:
            test_fp.write("test")
        in_file = corpman.InputFile(t_file)
        self.addCleanup(in_file.close)
        self.assertEqual(in_file.extension, "bin")
        self.assertEqual(in_file.file_name, t_file)
        self.assertIsNone(in_file.fp)
        self.assertEqual(in_file.get_data(), "test")
        self.assertEqual(in_file.get_fp().read(), "test")
        in_file.close()
        self.assertIsNone(in_file.fp)


class LoaderTests(unittest.TestCase):
    def test_00(self):
        "test loader"
        pass # TODO
