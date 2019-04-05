import hashlib
import logging
import os
import random
import re
import socket
import shutil
import sys
import tempfile
import threading
import time
import unittest
try: # py 2-3 compatibility
    from http.client import BadStatusLine
    from urllib.request import urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    from httplib import BadStatusLine
    from urllib2 import urlopen, HTTPError, URLError

from .core import Resource, Sapphire, ServeJob, SERVED_ALL, SERVED_NONE, \
    SERVED_REQUEST, SERVED_TIMEOUT

log_level = logging.INFO
log_fmt = "[%(asctime)s] %(message)s"
if bool(os.getenv("DEBUG")):
    log_level = logging.DEBUG
    log_fmt = "%(levelname).1s [%(asctime)s] %(message)s"
logging.basicConfig(format=log_fmt, datefmt="%H:%M:%S", level=log_level)
log = logging.getLogger("sphr_test")


class _TestFile(object):
    def __init__(self, url):
        self.md5_org = None
        self.md5_srv = None
        self.code = None
        self.content_type = None
        self.len_org = 0  # original file length
        self.len_srv = 0  # served file length
        self.lock = threading.Lock()
        self.url = url


class SimpleClient(object):
    RX_SIZE = 0x10000

    def __init__(self):
        self.thread = None

    def close(self):
        if self.thread is not None:
            self.thread.join()

    def launch(self, addr, port, files_to_serve, delay=0, in_order=False, indicate_failure=False, request=None, throttle=0):
        self.thread = threading.Thread(
            target=SimpleClient._handle_request,
            args=(addr, port, files_to_serve),
            kwargs={
                "delay":delay,
                "in_order":in_order,
                "indicate_failure":indicate_failure,
                "request":request,
                "throttle":throttle})
        self.thread.start()

    @staticmethod
    def _handle_request(addr, port, files_to_request, delay=0, in_order=False, indicate_failure=False, request=None, throttle=0):
        assert isinstance(files_to_request, list), "files_to_request should be a list"
        if delay:
            time.sleep(delay)
        indexes = list(range(len(files_to_request)))
        if not in_order:
            random.shuffle(indexes)  # request files in random order
        for index in indexes:
            t_file = files_to_request[index]
            with t_file.lock:
                # check if the file has been served
                if t_file.code is not None:
                    continue
                # if t_file.md5_org is set to anything but None the test client will calculate the md5 hash
                data_hash = hashlib.md5() if t_file.md5_org is not None else None
                target_url = t_file.url
            cl = None
            try:
                if request is None:
                    cl = urlopen("http://%s:%d/%s" % (addr, port, target_url), timeout=0.5)
                    resp_code = cl.getcode()
                    content_type = cl.info().get("Content-Type")
                    if resp_code == 200:
                        data_length = 0
                        while True:
                            data = cl.read(SimpleClient.RX_SIZE)
                            data_length += len(data)
                            if data_hash is not None:
                                data_hash.update(data)
                            if len(data) < SimpleClient.RX_SIZE:
                                break
                            if throttle > 0:  # try to simulate a slow connection
                                time.sleep(throttle)
                        if data_hash is not None:
                            data_hash = data_hash.hexdigest()
                else:  # custom request
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        sock.connect((addr, port))
                        sock.settimeout(1) # safety, so test doesn't hang on failure
                        sock.sendall(request)
                        data = sock.recv(SimpleClient.RX_SIZE) if request else b""
                    finally:
                        sock.close()
                    content_type = None
                    data_length = len(data)
                    try:
                        resp_code = int(re.match(r"HTTP/1\.\d\s(?P<code>\d+)\s", data.decode("ascii")).group("code"))
                    except AttributeError:
                        resp_code = 0 if indicate_failure else None  # set code to zero to help testing

                # update test info
                with t_file.lock:
                    if t_file.code is not None:
                        continue  # test has already be updated
                    t_file.code = resp_code
                    if resp_code == 200:
                        t_file.content_type = content_type
                        t_file.len_srv = data_length
                        t_file.md5_srv = data_hash

            except HTTPError as http_err:
                with t_file.lock:
                    if t_file.code is None:
                        t_file.code = http_err.code
            except (BadStatusLine, socket.error, socket.timeout, URLError):
                exc_type, exc_obj, exc_tb = sys.exc_info()
                # set code to zero to help testing
                with t_file.lock:
                    log.debug(
                        "%s - %s - line %d (processing: %s)",
                        exc_type.__name__,
                        exc_obj,
                        exc_tb.tb_lineno,
                        t_file.url)
                    if indicate_failure and t_file.code is None:
                        t_file.code = 0
                        break
            finally:
                if cl is not None:
                    cl.close()


def _create_test(fname, path, data=b"Test!", calc_hash=False, url_prefix=None):
    test = _TestFile(fname)
    if url_prefix is not None:
        test.url = "".join([url_prefix, fname])
    with open(os.path.join(path, fname), "w+b") as out_fp:
        out_fp.write(data)
        test.len_org = out_fp.tell()
        if calc_hash:
            out_fp.seek(0)
            test.md5_org = hashlib.md5(out_fp.read()).hexdigest()
    return test


class SapphireTests(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="spr_")
        self.client = None
        self.serv = None

    def tearDown(self):
        if self.serv is not None:
            self.serv.close()
        if self.client is not None:
            self.client.close()
        if os.path.isdir(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_00(self):
        "test requesting a single test case file"
        self.client = SimpleClient()
        self.addCleanup(self.client.close)
        self.serv = Sapphire(timeout=10)
        test = _create_test("test_case.html", self.test_dir)
        self.client.launch("127.0.0.1", self.serv.get_port(), [test])
        self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
        self.client.close()
        self.assertEqual(test.code, 200)
        self.assertEqual(test.len_srv, test.len_org)

    def test_01(self):
        "test requesting multiple test case files (test cleanup code)"
        files_to_serve = list()
        self.serv = Sapphire(timeout=10)
        expect_served = 100
        for i in range(expect_served):
            test = _create_test("test_case_%03d.html" % i, self.test_dir, data=os.urandom(5), calc_hash=True)
            files_to_serve.append(test)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve)
        status, served_list = self.serv.serve_path(self.test_dir)
        self.assertEqual(status, SERVED_ALL)
        self.assertEqual(expect_served, len(served_list))
        self.client.close()
        for t_file in files_to_serve:
            self.assertEqual(t_file.code, 200)
            self.assertEqual(t_file.len_srv, t_file.len_org)
            self.assertEqual(t_file.md5_srv, t_file.md5_org)

    def test_02(self):
        "test skipping optional test case file"
        optional_to_serve = list()
        files_to_serve = list()
        self.serv = Sapphire(timeout=10)
        for i in range(3):
            files_to_serve.append(_create_test("test_case_%d.html" % i, self.test_dir))

        # add first file to optional list
        optional_to_serve.append(files_to_serve[0].url)

        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve[1:])
        status, served_list = self.serv.serve_path(self.test_dir, optional_files=optional_to_serve)
        self.assertEqual(status, SERVED_ALL)
        self.client.close()
        self.assertEqual(files_to_serve[0].code, None)
        self.assertEqual(files_to_serve[0].len_srv, 0)
        for t_file in files_to_serve[1:]:
            self.assertEqual(t_file.code, 200)
            self.assertEqual(t_file.len_srv, t_file.len_org)
        self.assertEqual(len(files_to_serve) - 1, len(served_list))

        # reset tests
        for t_file in files_to_serve:
            t_file.code = None
            t_file.len_srv = 0

        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve, in_order=True)
        status, served_list = self.serv.serve_path(self.test_dir, optional_files=optional_to_serve)
        self.assertEqual(status, SERVED_ALL)
        self.client.close()
        self.assertEqual(len(files_to_serve), len(served_list))
        for t_file in files_to_serve:
            self.assertEqual(t_file.code, 200)
            self.assertEqual(t_file.len_srv, t_file.len_org)

    def test_03(self):
        "test requesting invalid file (404)"
        files_to_serve = list()
        self.serv = Sapphire(timeout=10)
        invalid_test = _TestFile("does_not_exist.html")
        files_to_serve.append(invalid_test)
        test = _create_test("test_case.html", self.test_dir)
        files_to_serve.append(test)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve, in_order=True)
        self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
        self.client.close()
        self.assertEqual(invalid_test.code, 404)

    def test_04(self):
        "test requesting a file outside of the server root (403)"
        root_dir = tempfile.mkdtemp(prefix="root_", dir=self.test_dir)
        files_to_serve = list()
        self.serv = Sapphire(timeout=10)
        # add invalid file
        invalid_test = _TestFile(os.path.abspath(__file__))
        files_to_serve.append(invalid_test)
        # add file in parent of root_dir
        no_acc = _create_test("no_access.html", self.test_dir, data=b"no_access", url_prefix="../")
        self.assertTrue(os.path.isfile(os.path.join(self.test_dir, "no_access.html")))
        files_to_serve.append(no_acc)
        # add valid test
        test = _create_test("test_case.html", root_dir)
        files_to_serve.append(test)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve, in_order=True)
        self.assertEqual(self.serv.serve_path(root_dir)[0], SERVED_ALL)
        self.client.close()
        self.assertEqual(invalid_test.code, 403)
        self.assertEqual(no_acc.code, 403)

    def test_05(self):
        "test serving no files... this should never happen but..."
        self.client = SimpleClient()
        self.serv = Sapphire(timeout=1)
        self.client.launch("127.0.0.1", self.serv.get_port(), [])
        status, files_served = self.serv.serve_path(self.test_dir)
        self.assertEqual(status, SERVED_NONE)
        self.assertFalse(files_served)

    def test_06(self):
        "test timeout of the server"
        self.serv = Sapphire(timeout=1)  # minimum timeout is 1 second
        _create_test("test_case.html", self.test_dir)
        status, files_served = self.serv.serve_path(self.test_dir)
        self.assertEqual(status, SERVED_TIMEOUT)
        self.assertFalse(files_served)

    def test_07(self):
        "test only serving some files (SERVED_REQUEST)"
        cb_status = {"count": 0}
        def is_running():
            cb_status["count"] += 1
            return cb_status["count"] < 3  # return false after 2nd call

        files_to_serve = list()
        self.serv = Sapphire()
        for i in range(3):
            files_to_serve.append(_create_test("test_case_%d.html" % i, self.test_dir))
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve[1:])
        status, files_served = self.serv.serve_path(self.test_dir, continue_cb=is_running)
        self.assertEqual(status, SERVED_REQUEST)
        self.assertTrue(files_served)

    def test_08(self):
        "test serving interesting sized files"
        self.serv = Sapphire(timeout=10)
        tests = [
            {"size":Sapphire.DEFAULT_TX_SIZE, "name":"even.html"},
            {"size":Sapphire.DEFAULT_TX_SIZE-1, "name":"minus_one.html"},
            {"size":Sapphire.DEFAULT_TX_SIZE+1, "name":"plus_one.html"},
            {"size":Sapphire.DEFAULT_TX_SIZE*2, "name":"double.html"},
            {"size":1, "name":"one.html"},
            {"size":0, "name":"zero.html"}]
        for test in tests:
            test["file"] = _TestFile(test["name"])
            t_data = "".join(random.choice("ABCD1234") for _ in range(test["size"])).encode("ascii")
            with open(os.path.join(self.test_dir, test["file"].url), "wb") as fp:
                fp.write(t_data)
            test["file"].md5_org = hashlib.md5(t_data).hexdigest()
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), [test["file"] for test in tests])
        status, served_list = self.serv.serve_path(self.test_dir)
        self.assertEqual(status, SERVED_ALL)
        self.assertEqual(len(served_list), len(tests))
        self.client.close()
        for test in tests:
            self.assertEqual(test["file"].code, 200)
            self.assertEqual(test["file"].len_srv, test["size"])
            self.assertEqual(test["file"].md5_srv, test["file"].md5_org)

    def test_09(self):
        "test serving a large (100MB) file"
        self.serv = Sapphire(timeout=10)
        t_file = _TestFile("test_case.html")
        data_hash = hashlib.md5()
        with open(os.path.join(self.test_dir, t_file.url), "wb") as fp:
            # write 100MB of 'A'
            data = b"A" * (100 * 1024) # 100KB of 'A'
            for _ in range(1024):
                fp.write(data)
                data_hash.update(data)
        t_file.md5_org = data_hash.hexdigest()
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), [t_file])
        self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
        self.client.close()
        self.assertEqual(t_file.code, 200)
        self.assertEqual(t_file.len_srv, (100 * 1024 * 1024))
        self.assertEqual(t_file.md5_srv, t_file.md5_org)

    def test_10(self):
        "test serving a binary file"
        self.serv = Sapphire(timeout=10)
        t_file = _create_test("test_case.html", self.test_dir, data=os.urandom(512), calc_hash=True)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), [t_file])
        self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
        self.client.close()
        self.assertEqual(t_file.code, 200)
        self.assertEqual(t_file.len_srv, t_file.len_org)
        self.assertEqual(t_file.md5_srv, t_file.md5_org)

    def test_11(self):
        "test requested port is used"
        test_port = 0x1337
        self.serv = Sapphire(port=test_port, timeout=1)
        self.assertEqual(test_port, self.serv.get_port())

    def test_12(self):
        "test serving multiple content types"
        files_to_serve = list()
        self.serv = Sapphire(timeout=10)
        test_html = _create_test("test_case.html", self.test_dir)
        files_to_serve.append(test_html)
        # create binary test case with no ext
        test_bin = _create_test("test_case", self.test_dir, data=os.urandom(5))
        files_to_serve.append(test_bin)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve)
        self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
        self.client.close()
        content_types = set()
        for test in files_to_serve:
            self.assertEqual(test.code, 200)
            self.assertEqual(test.len_srv, test.len_org)
            file_ext = os.path.splitext(test.url)[-1]
            content_type = {".html": "text/html"}.get(file_ext, "application/octet-stream")
            content_types.add(content_type)
            self.assertEqual(test.content_type, content_type)
        self.assertEqual(len(content_types), 2)

    def test_13(self):
        "test callback"
        cb_status = {"count": 0}

        def test_callback():
            cb_status["count"] += 1
            # return true on first call
            return cb_status["count"] < 2

        self.serv = Sapphire(timeout=10)
        _create_test("test_case.html", self.test_dir)
        self.client = SimpleClient()
        self.assertEqual(self.serv.serve_path(self.test_dir, continue_cb=test_callback)[0], SERVED_NONE)
        self.client.close()
        self.assertEqual(cb_status["count"], 2)

    def test_14(self):
        "test calling serve_path multiple times"
        self.serv = Sapphire(timeout=10)
        for i in range(3):
            test = _create_test("test_case_%d.html" % i, self.test_dir)
            self.client = SimpleClient()
            self.client.launch("127.0.0.1", self.serv.get_port(), [test])
            self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
            self.client.close()
            self.assertEqual(test.code, 200)
            self.assertEqual(test.len_srv, test.len_org)
            os.remove(os.path.join(self.test_dir, test.url))

    def test_15(self):
        "test non required mapped redirects"
        self.serv = Sapphire(timeout=10)
        self.serv.set_redirect("test_url", "blah", required=False)
        test = _create_test("test_case.html", self.test_dir)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), [test])
        self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
        self.client.close()
        self.assertEqual(test.code, 200)
        self.assertEqual(test.len_srv, test.len_org)

    def test_16(self):
        "test required mapped redirects"
        self.serv = Sapphire(timeout=10)
        files_to_serve = list()
        # redir_target will be requested indirectly via the redirect
        redir_target = _create_test("redir_test_case.html", self.test_dir, data=b"Redirect DATA!")
        redir_test = _TestFile("redirect_test")
        self.serv.set_redirect(redir_test.url, redir_target.url, required=True)
        files_to_serve.append(redir_test)
        test = _create_test("test_case.html", self.test_dir)
        files_to_serve.append(test)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve)
        status, served_list = self.serv.serve_path(self.test_dir)
        self.assertEqual(status, SERVED_ALL)
        self.client.close()
        self.assertEqual(test.code, 200)
        self.assertEqual(test.len_srv, test.len_org)
        self.assertEqual(redir_test.code, 200)
        self.assertEqual(redir_test.len_srv, redir_target.len_org)
        self.assertEqual(len(served_list), len(files_to_serve))

    def test_17(self):
        "test include directories"
        inc1_dir = tempfile.mkdtemp(prefix="inc1_", dir=self.test_dir)
        inc2_dir = tempfile.mkdtemp(prefix="inc2_", dir=self.test_dir)
        root_dir = tempfile.mkdtemp(prefix="root_", dir=self.test_dir)
        self.serv = Sapphire(timeout=10)
        files_to_serve = list()

        # add files to inc dirs
        inc1 = _create_test("included_file1.html", inc1_dir, data=b"blah....1")
        files_to_serve.append(inc1)

        # add a nested dir
        nest_dir = os.path.join(inc1_dir, "nested")
        os.mkdir(nest_dir)
        # add file in a nested dir in inc1
        nest = _create_test("nested_file.html", nest_dir, data=b"blah... .nested", url_prefix="nested/")
        self.assertTrue(os.path.isfile(os.path.join(nest_dir, "nested_file.html")))
        files_to_serve.append(nest)

        # test 404 in nested dir in inc1
        nest_404 = _TestFile("nested/nested_file_404.html")
        files_to_serve.append(nest_404)

        # test path mounted somewhere other than /
        inc2 = _create_test("included_file2.html", inc2_dir, data=b"blah....2", url_prefix="inc_test/")
        files_to_serve.append(inc2)

        # test 404 in include dir
        inc404 = _TestFile("inc_test/included_file_404.html")
        self.assertFalse(os.path.isfile(os.path.join(nest_dir, "included_file_404.html")))
        files_to_serve.append(inc404)

        # test 403
        inc403 = _create_test("no_access.html", self.test_dir, data=b"no_access", url_prefix="inc_test/../")
        self.assertTrue(os.path.isfile(os.path.join(self.test_dir, "no_access.html")))
        files_to_serve.append(inc403)

        # test file
        test = _create_test("test_case.html", root_dir)
        files_to_serve.append(test)

        self.serv.add_include("/", inc1_dir) # mount at '/'
        self.serv.add_include("inc_test", inc2_dir) # mount at '/inc_test'

        client_incs = SimpleClient()
        self.addCleanup(client_incs.close)
        client_reqs = SimpleClient()
        self.addCleanup(client_reqs.close)
        # client that requests the include files
        # TODO: find out why test fails without in_order=True and fix or make a note
        client_incs.launch("127.0.0.1", self.serv.get_port(), files_to_serve, in_order=True)
        client_reqs.launch("127.0.0.1", self.serv.get_port(), [test], delay=0.1)
        # delayed client that requests the required files (once others are requested)
        status, files_served = self.serv.serve_path(root_dir)
        self.assertEqual(status, SERVED_ALL)
        self.assertEqual(inc1.code, 200)
        self.assertEqual(inc2.code, 200)
        self.assertEqual(nest.code, 200)
        self.assertEqual(test.code, 200)
        self.assertEqual(nest_404.code, 404)
        self.assertEqual(inc404.code, 404)
        self.assertEqual(inc403.code, 403)
        self.assertEqual(len(files_served), 4)

    def test_18(self):
        "test mapping with bad urls"
        self.serv = Sapphire(timeout=1)
        with self.assertRaises(RuntimeError):
            self.serv.set_redirect("/test/test", "a.html") # cannot map more than one '/' deep
        with self.assertRaises(RuntimeError):
            self.serv.set_redirect("asd!@#", "a.html") # only alpha-numeric is allowed

    def test_19(self):
        "test dynamic response"
        _test_string = b"dynamic response -- TEST DATA!"
        def _dyn_test_cb():
            return _test_string

        self.serv = Sapphire(timeout=10)
        test_dr = _TestFile("dynm_test")
        test_dr.len_org = len(_test_string)
        test_dr.md5_org = hashlib.md5(_test_string).hexdigest()
        self.serv.add_dynamic_response("dynm_test", _dyn_test_cb, mime_type="text/plain")
        test = _create_test("test_case.html", self.test_dir)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), [test_dr, test], in_order=True)
        self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
        self.assertEqual(test.code, 200)
        self.assertEqual(test.len_srv, test.len_org)
        self.assertEqual(test_dr.code, 200)
        self.assertEqual(test_dr.len_srv, test_dr.len_org)
        self.assertEqual(test_dr.md5_srv, test_dr.md5_org)


    def test_20(self):
        "test pending_files == 0 in worker thread"
        default_rx_size = SimpleClient.RX_SIZE
        SimpleClient.RX_SIZE = 2
        self.serv = Sapphire(timeout=10)
        client_defer = SimpleClient()
        self.addCleanup(client_defer.close)
        try:
            # server should shutdown while this file is being served
            test_defer = _create_test("defer_test.html", self.test_dir)
            optional = [test_defer.url]
            test = _create_test("test_case.html", self.test_dir, data=b"112233")
            # this test needs to wait just long enough to have the required file served
            # but not too long or the connection will be closed by the server
            client_defer.launch("127.0.0.1", self.serv.get_port(), [test_defer], delay=0.1, indicate_failure=True)
            self.client = SimpleClient()
            self.client.launch("127.0.0.1", self.serv.get_port(), [test], throttle=0.1)
            self.assertEqual(self.serv.serve_path(self.test_dir, optional_files=optional)[0], SERVED_ALL)
            self.client.close()
            client_defer.close()
            self.assertEqual(test.code, 200)
            self.assertEqual(test_defer.code, 0)
        finally:
            SimpleClient.RX_SIZE = default_rx_size


    def test_21(self):
        "test handling an invalid request"
        bad_client = SimpleClient()
        self.addCleanup(bad_client.close)
        self.serv = Sapphire(timeout=10)
        bad_test = _TestFile("bad.html")
        optional = [bad_test.url]
        test = _create_test("test_case.html", self.test_dir)
        self.client = SimpleClient()
        bad_client.launch("127.0.0.1", self.serv.get_port(), [bad_test], request=b"a bad request...0+%\xef\xb7\xba\r\n")
        self.client.launch("127.0.0.1", self.serv.get_port(), [test], delay=0.1)
        self.assertEqual(self.serv.serve_path(self.test_dir, optional_files=optional)[0], SERVED_ALL)
        self.client.close()
        bad_client.close()
        self.assertEqual(test.code, 200)
        self.assertEqual(bad_test.code, 400)


    def test_22(self):
        "test handling an empty request"
        bad_client = SimpleClient()
        self.addCleanup(bad_client.close)
        self.serv = Sapphire(timeout=10)
        bad_test = _TestFile("bad.html")
        optional = [bad_test.url]
        test = _create_test("test_case.html", self.test_dir)
        self.client = SimpleClient()
        bad_client.launch("127.0.0.1", self.serv.get_port(), [bad_test], indicate_failure=True, request=b"")
        self.client.launch("127.0.0.1", self.serv.get_port(), [test], delay=0.1)
        self.assertEqual(self.serv.serve_path(self.test_dir, optional_files=optional)[0], SERVED_ALL)
        bad_client.close()
        self.client.close()
        self.assertEqual(test.code, 200)
        self.assertEqual(bad_test.code, 0)


    def test_23(self):
        "test requesting multiple files via multiple connections"
        default_pool_limit = Sapphire.WORKER_POOL_LIMIT
        default_rx_size = SimpleClient.RX_SIZE
        self.serv = Sapphire(timeout=10)
        try:
            Sapphire.WORKER_POOL_LIMIT = 20
            SimpleClient.RX_SIZE = 1
            expect_served = 2  # number of files available to serve
            to_serve = list()
            for i in range(expect_served):
                to_serve.append(_create_test("test_%03d.html" % i, self.test_dir, data=b"AAAA"))
            clients = list()
            try:
                for _ in range(Sapphire.WORKER_POOL_LIMIT):  # number of clients to spawn
                    clients.append(SimpleClient())
                for client in clients:
                    client.launch("127.0.0.1", self.serv.get_port(), to_serve, in_order=True, throttle=0.05)
                status, served_list = self.serv.serve_path(self.test_dir)
            finally:
                for client in clients:
                    client.close()
            self.assertEqual(status, SERVED_ALL)
            self.assertEqual(expect_served, len(served_list))
            for t_file in to_serve:
                self.assertEqual(t_file.code, 200)
                self.assertEqual(t_file.len_srv, t_file.len_org)
        finally:
            Sapphire.WORKER_POOL_LIMIT = default_pool_limit
            SimpleClient.RX_SIZE = default_rx_size


    def test_24(self):
        "test all request types via multiple connections"
        def _dyn_test_cb():
            return b"A" if random.getrandbits(1) else b"AA"

        self.serv = Sapphire(timeout=10)
        default_pool_limit = Sapphire.WORKER_POOL_LIMIT
        default_rx_size = SimpleClient.RX_SIZE
        try:
            SimpleClient.RX_SIZE = 1
            Sapphire.WORKER_POOL_LIMIT = 10
            to_serve = list()
            for i in range(50):
                # add required files
                to_serve.append(_create_test("test_%03d.html" % i, self.test_dir, data=b"A" * ((i % 2) + 1)))
                # add a missing files
                to_serve.append(_TestFile("missing_%03d.html" % i))
                # add optional files
                opt = os.path.join(self.test_dir, "opt_%03d.html" % i)
                with open(opt, "w") as out_fp:
                    out_fp.write("A" * ((i % 2) + 1))
                to_serve.append(_TestFile(os.path.basename(opt)))
                # add redirects
                redir_target = _create_test("redir_%03d.html" % i, self.test_dir, data=b"AA")
                to_serve.append(_TestFile("redir_%03d" % i))
                self.serv.set_redirect(to_serve[-1].url, redir_target.url, required=random.getrandbits(1) > 0)
                # add dynamic responses
                to_serve.append(_TestFile("dynm_%03d" % i))
                self.serv.add_dynamic_response(to_serve[-1].url, _dyn_test_cb, mime_type="text/plain")

            clients = list()
            try:
                for _ in range(100):  # number of clients to spawn
                    clients.append(SimpleClient())
                    throttle = 0.05 if random.getrandbits(1) else 0
                    clients[-1].launch("127.0.0.1", self.serv.get_port(), to_serve, throttle=throttle)
                status, served_list = self.serv.serve_path(self.test_dir)
            finally:
                for client in clients:
                    client.close()
            self.assertEqual(status, SERVED_ALL)
        finally:
            SimpleClient.RX_SIZE = default_rx_size
            Sapphire.WORKER_POOL_LIMIT = default_pool_limit


    def test_25(self):
        "test dynamic response with bad callbacks"
        def _dyn_none_cb():
            return None

        self.serv = Sapphire(timeout=10)
        test_dr = _TestFile("dynm_test")
        self.serv.add_dynamic_response("dynm_test", _dyn_none_cb, mime_type="text/plain")
        test = _create_test("test_case.html", self.test_dir)
        self.client = SimpleClient()
        self.client.launch("127.0.0.1", self.serv.get_port(), [test_dr, test], in_order=True)
        with self.assertRaises(TypeError):
            self.serv.serve_path(self.test_dir)


    def test_26(self):
        "test serving to a slow client"
        default_rx_size = SimpleClient.RX_SIZE
        self.serv = Sapphire(timeout=10)
        try:
            t_data = "".join(random.choice("ABCD1234") for _ in range(0x19000)) # 100KB
            t_file = _create_test("test_case.html", self.test_dir, data=t_data.encode("ascii"), calc_hash=True)
            # rx_size 10KB and throttle to 0.25 sec, which will be ~50KB/s
            # also taking 2.5 seconds to complete will hopefully find problems
            # with any assumptions that were made
            SimpleClient.RX_SIZE = 0x2800
            self.client = SimpleClient()
            self.client.launch("127.0.0.1", self.serv.get_port(), [t_file], throttle=0.25)
            self.assertEqual(self.serv.serve_path(self.test_dir)[0], SERVED_ALL)
            self.client.close()
            self.assertEqual(t_file.code, 200)
            self.assertEqual(t_file.len_srv, t_file.len_org)
            self.assertEqual(t_file.md5_srv, t_file.md5_org)
        finally:
            SimpleClient.RX_SIZE = default_rx_size


    def test_27(self):
        "test timeout while requesting multiple test cases"
        default_rx_size = SimpleClient.RX_SIZE
        files_to_serve = list()
        self.serv = Sapphire(timeout=1) # minimum timeout is 1 second
        try:
            max_served = 50
            t_data = "".join(random.choice("ABCD1234") for _ in range(1024)).encode("ascii")
            for i in range(max_served):
                files_to_serve.append(_create_test("test_case_%03d.html" % i, self.test_dir, data=t_data))
            SimpleClient.RX_SIZE = 512
            self.client = SimpleClient()
            self.client.launch("127.0.0.1", self.serv.get_port(), files_to_serve, indicate_failure=True, throttle=0.1)
            status, served_list = self.serv.serve_path(self.test_dir)
            self.assertEqual(status, SERVED_TIMEOUT)
            self.assertLess(len(served_list), max_served)
        finally:
            SimpleClient.RX_SIZE = default_rx_size


class ServeJobTests(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="spr_")

    def tearDown(self):
        if os.path.isdir(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_01(self):
        "test creating an empty ServeJob"
        sj = ServeJob(self.test_dir, dict(), dict(), dict())
        self.assertEqual(sj.status, SERVED_ALL)
        self.assertIsNone(sj.check_request(""))
        self.assertIsNone(sj.check_request("test"))
        self.assertIsNone(sj.check_request("test/test/"))
        self.assertIsNone(sj.check_request("test/../../"))
        self.assertFalse(sj.is_forbidden(self.test_dir))
        self.assertFalse(sj.is_forbidden(os.path.join(self.test_dir, "missing_file")))
        self.assertEqual(sj.pending_files(), 0)
        self.assertFalse(sj.is_complete())
        self.assertTrue(sj.remove_pending("no_file.test"))
        sj.finish()
        self.assertTrue(sj.is_complete())

    def test_02(self):
        "test ServeJob two required files and one optional file"
        opt = os.path.join(self.test_dir, "opt_file.txt")
        with open(opt, "w") as out_fp:
            out_fp.write("a")
        req1 = os.path.join(self.test_dir, "req_file_1.txt")
        with open(req1, "w") as out_fp:
            out_fp.write("a")
        os.mkdir(os.path.join(self.test_dir, "test"))
        req2 = os.path.join(self.test_dir, "test", "req_file_2.txt?q=123")
        with open(req2, "w") as out_fp:
            out_fp.write("a")
        sj = ServeJob(self.test_dir, dict(), dict(), dict(), optional_files=[os.path.basename(opt)])
        self.assertEqual(sj.status, SERVED_NONE)
        self.assertFalse(sj.is_complete())
        resource = sj.check_request("req_file_1.txt")
        self.assertTrue(resource.required)
        self.assertTrue(resource.target, "req_file_1.txt")
        self.assertEqual(resource.type, sj.URL_FILE)
        self.assertFalse(sj.is_forbidden(req1))
        self.assertFalse(sj.remove_pending("no_file.test"))
        self.assertEqual(sj.pending_files(), 2)
        self.assertFalse(sj.remove_pending(req1))
        self.assertEqual(sj.status, SERVED_REQUEST)
        self.assertEqual(sj.pending_files(), 1)
        self.assertTrue(sj.remove_pending(req2))
        self.assertEqual(sj.status, SERVED_ALL)
        self.assertEqual(sj.pending_files(), 0)
        self.assertTrue(sj.remove_pending(req1))
        resource = sj.check_request("opt_file.txt")
        self.assertFalse(resource.required)
        self.assertTrue(resource.target, "opt_file.txt")
        self.assertEqual(resource.type, sj.URL_FILE)
        self.assertTrue(sj.remove_pending(opt))
        sj.finish()
        self.assertTrue(sj.is_complete())

    def test_03(self):
        "test ServeJob redirects"
        redirs = {
            "one": Resource(ServeJob.URL_REDIRECT, "somefile.txt"),
            "two": Resource(ServeJob.URL_REDIRECT, "reqfile.txt", required=True)}
        sj = ServeJob(self.test_dir, dict(), dict(), redirs)
        self.assertEqual(sj.status, SERVED_NONE)
        resource = sj.check_request("one")
        self.assertEqual(resource.type, sj.URL_REDIRECT)
        resource = sj.check_request("two?q=123")
        self.assertIsNotNone(resource)
        self.assertEqual(resource.type, sj.URL_REDIRECT)
        self.assertEqual(sj.pending_files(), 1)
        self.assertTrue(sj.remove_pending("two"))
        self.assertEqual(sj.pending_files(), 0)

    def test_04(self):
        "test ServeJob includes"
        srv_root = os.path.join(self.test_dir, "root")
        srv_include = os.path.join(self.test_dir, "test")
        srv_include_2 = os.path.join(self.test_dir, "test_2")
        srv_include_nested = os.path.join(srv_include, "nested")
        os.mkdir(srv_root)
        os.mkdir(srv_include)
        os.mkdir(srv_include_2)
        os.mkdir(srv_include_nested)
        test_1 = os.path.join(srv_root, "req_file.txt")
        with open(test_1, "w") as out_fp:
            out_fp.write("a")
        inc_1 = os.path.join(srv_include, "test_file.txt")
        with open(inc_1, "w") as out_fp:
            out_fp.write("b")
        nst_1 = os.path.join(srv_include_nested, "nested_file.txt")
        with open(nst_1, "w") as out_fp:
            out_fp.write("c")
        inc_2 = os.path.join(srv_include_2, "test_file_2.txt?q=123")
        with open(inc_2, "w") as out_fp:
            out_fp.write("d")
        includes = {
            "testinc": Resource(ServeJob.URL_INCLUDE, srv_include),
            "testinc/fakedir": Resource(ServeJob.URL_INCLUDE, srv_include),
            "testinc/1/2/3": Resource(ServeJob.URL_INCLUDE, srv_include),
            "": Resource(ServeJob.URL_INCLUDE, srv_include),
            "testinc/inc2": Resource(ServeJob.URL_INCLUDE, srv_include_2)}
        sj = ServeJob(srv_root, dict(), includes, dict())
        self.assertEqual(sj.status, SERVED_NONE)
        # test includes that map to 'srv_include'
        for incl, inc_path in includes.items():
            if inc_path != srv_include:  # only check 'srv_include' mappings
                continue
            resource = sj.check_request("/".join([incl, "test_file.txt"]))
            self.assertEqual(resource.type, sj.URL_INCLUDE)
            self.assertEqual(resource.target, inc_1)
        # test nested include path pointing to a different include
        resource = sj.check_request("testinc/inc2/test_file2.txt?q=123")
        self.assertEqual(resource.type, sj.URL_INCLUDE)
        self.assertEqual(resource.target, os.path.join(srv_include_2, "test_file2.txt"))
        # test redirect root without leading '/'
        resource = sj.check_request("test_file.txt")
        self.assertEqual(resource.type, sj.URL_INCLUDE)
        self.assertEqual(resource.target, os.path.join(srv_include, "test_file.txt"))
        # test redirect with file in a nested directory
        resource = sj.check_request("/".join(["testinc", "nested", "nested_file.txt"]))
        self.assertEqual(resource.type, sj.URL_INCLUDE)
        self.assertEqual(resource.target, nst_1)
        self.assertFalse(sj.is_forbidden(os.path.join(srv_root, "..", "test", "test_file.txt")))
        self.assertFalse(sj.is_forbidden(os.path.join(srv_include, "..", "root", "req_file.txt")))

    def test_05(self):
        "test ServeJob dynamic"
        srv_root = os.path.join(self.test_dir, "root")
        def _dyn_test_cb():
            pass
        dynamics = {
            "cb1": Resource(ServeJob.URL_DYNAMIC, _dyn_test_cb, mime="mime_type"),
            "cb2": Resource(ServeJob.URL_DYNAMIC, _dyn_test_cb, mime="mime_type"),}
        sj = ServeJob(srv_root, dynamics, dict(), dict())
        self.assertEqual(sj.status, SERVED_ALL)
        self.assertEqual(sj.pending_files(), 0)
        resource = sj.check_request("cb1")
        self.assertEqual(resource.type, sj.URL_DYNAMIC)
        self.assertTrue(callable(resource.target))
        self.assertTrue(isinstance(resource.mime, str))
        resource = sj.check_request("cb2?q=123")
        self.assertIsNotNone(resource)
        self.assertEqual(resource.type, sj.URL_DYNAMIC)
        self.assertTrue(callable(resource.target))
        self.assertTrue(isinstance(resource.mime, str))

    def test_06(self):
        "test accessing forbidden files"
        srv_root = os.path.join(self.test_dir, "root")
        os.mkdir(srv_root)
        test_1 = os.path.join(srv_root, "req_file.txt")
        with open(test_1, "w") as out_fp:
            out_fp.write("a")
        no_access = os.path.join(self.test_dir, "no_access.txt")
        with open(no_access, "w") as out_fp:
            out_fp.write("a")
        sj = ServeJob(srv_root, dict(), dict(), dict())
        self.assertEqual(sj.status, SERVED_NONE)
        self.assertEqual(sj.pending_files(), 1)
        resource = sj.check_request("../no_access.txt")
        self.assertTrue(resource.target, "../no_access.txt")
        self.assertEqual(resource.type, sj.URL_FILE)
        self.assertFalse(sj.is_forbidden(test_1))
        self.assertTrue(sj.is_forbidden(os.path.join(srv_root, "../no_access.txt")))


class ResponseDataTests(unittest.TestCase):
    def test_01(self):
        "test _200_header()"
        output = Sapphire._200_header("10", "text/html")  # pylint: disable=protected-access
        self.assertIn("Content-Length: 10", output)
        self.assertIn("Content-Type: text/html", output)

    def test_02(self):
        "test _307_redirect()"
        output = Sapphire._307_redirect("http://some.test.url")  # pylint: disable=protected-access
        self.assertIn("Location: http://some.test.url", output)

    def test_03(self):
        "test _4xx_page() without close timeout"
        output = Sapphire._4xx_page(400, "Bad Request")  # pylint: disable=protected-access
        self.assertIn("Content-Length: ", output)
        self.assertIn("HTTP/1.1 400 Bad Request", output)
        self.assertIn("400!", output)

    def test_04(self):
        "test _4xx_page() with close timeout"
        try:
            Sapphire.CLOSE_CLIENT_ERROR = 10
            output = Sapphire._4xx_page(404, "Not Found")  # pylint: disable=protected-access
            self.assertIn("Content-Length: ", output)
            self.assertIn("HTTP/1.1 404 Not Found", output)
            self.assertIn("<script>window.setTimeout(window.close, 10000)</script>", output)
        finally:
            Sapphire.CLOSE_CLIENT_ERROR = None
