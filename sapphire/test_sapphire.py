# coding=utf-8
"""
Sapphire unit tests
"""
# pylint: disable=protected-access

import hashlib
import logging
import os
import platform
import random
import threading

import pytest

from grizzly.common import TestCase

from .core import Sapphire, ServeJob, SERVED_ALL, SERVED_NONE, SERVED_REQUEST, SERVED_TIMEOUT
from .server_map import Resource, ServerMap


LOG = logging.getLogger("sphr_test")


class _TestFile(object):
    def __init__(self, url):
        self.md5_org = None
        self.md5_srv = None
        self.code = None
        self.content_type = None
        self.custom_request = None
        self.len_org = 0  # original file length
        self.len_srv = 0  # served file length
        self.requested = 0  # number of time file was requested
        self.lock = threading.Lock()
        self.url = url


def _create_test(fname, path, data=b"Test!", calc_hash=False, url_prefix=None):
    test = _TestFile(fname)
    if url_prefix is not None:
        test.url = "".join([url_prefix, fname])
    with (path / fname).open("w+b") as out_fp:
        out_fp.write(data)
        test.len_org = out_fp.tell()
        if calc_hash:
            out_fp.seek(0)
            test.md5_org = hashlib.md5(out_fp.read()).hexdigest()
    return test


def test_sapphire_00(client, tmp_path):
    """test requesting a single file"""
    serv = Sapphire(timeout=10)
    try:
        assert serv.timeout == 10
        test = _create_test("test_case.html", tmp_path)
        client.launch("127.0.0.1", serv.get_port(), [test])
        assert serv.serve_path(str(tmp_path))[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org


def test_sapphire_01(client, tmp_path):
    """test requesting multiple files (test cleanup code)"""
    files_to_serve = list()
    serv = Sapphire(timeout=30)
    try:
        for i in range(100):
            files_to_serve.append(
                _create_test("test_case_%03d.html" % i, tmp_path, data=os.urandom(5), calc_hash=True))
        client.launch("127.0.0.1", serv.get_port(), files_to_serve)
        status, files_served = serv.serve_path(str(tmp_path))
        assert status == SERVED_ALL
        assert len(files_to_serve) == len(files_served)
    finally:
        serv.close()
    assert client.wait(timeout=10)
    for t_file in files_to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org
        assert t_file.md5_srv == t_file.md5_org


def test_sapphire_02(client, tmp_path):
    """test serving optional file"""
    files_to_serve = list()
    serv = Sapphire(timeout=10)
    try:
        for i in range(3):
            files_to_serve.append(_create_test("test_case_%d.html" % i, tmp_path))
        optional = [files_to_serve[0].url]
        client.launch("127.0.0.1", serv.get_port(), files_to_serve, in_order=True)
        status, served_list = serv.serve_path(str(tmp_path), optional_files=optional)
        assert status == SERVED_ALL
        assert len(files_to_serve) == len(served_list)
    finally:
        serv.close()
    assert client.wait(timeout=10)
    for t_file in files_to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org


def test_sapphire_03(client, tmp_path):
    """test skipping optional file"""
    files_to_serve = list()
    serv = Sapphire(timeout=10)
    try:
        for i in range(3):
            files_to_serve.append(_create_test("test_case_%d.html" % i, tmp_path))
        optional = [files_to_serve[0].url]
        client.launch("127.0.0.1", serv.get_port(), files_to_serve[1:])
        status, served_list = serv.serve_path(str(tmp_path), optional_files=optional)
        assert status == SERVED_ALL
        assert len(served_list) == len(files_to_serve) - 1
        assert client.wait(timeout=10)
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert files_to_serve[0].code is None
    assert files_to_serve[0].len_srv == 0
    for t_file in files_to_serve[1:]:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org


def test_sapphire_04(client, tmp_path):
    """test requesting invalid file (404)"""
    files_to_serve = list()
    serv = Sapphire(timeout=10)
    try:
        files_to_serve.append(_TestFile("does_not_exist.html"))
        files_to_serve.append(_create_test("test_case.html", tmp_path))
        client.launch("127.0.0.1", serv.get_port(), files_to_serve, in_order=True)
        assert serv.serve_path(str(tmp_path))[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert "does_not_exist.html" in files_to_serve[0].url
    assert files_to_serve[0].code == 404
    assert files_to_serve[1].code == 200


def test_sapphire_05(client, tmp_path):
    """test requesting a file outside of the server root (403)"""
    files_to_serve = list()
    serv = Sapphire(timeout=10)
    try:
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        # add invalid file
        files_to_serve.append(_TestFile(os.path.abspath(__file__)))
        # add file in parent of root_dir
        files_to_serve.append(_create_test("no_access.html", tmp_path, data=b"no_access", url_prefix="../"))
        assert (tmp_path / "no_access.html").is_file()
        # add valid test
        files_to_serve.append(_create_test("test_case.html", root_dir))
        client.launch("127.0.0.1", serv.get_port(), files_to_serve, in_order=True)
        status, files_served = serv.serve_path(str(root_dir))
        assert status == SERVED_ALL
        assert len(files_served) == 1
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert os.path.basename(__file__) in files_to_serve[0].url
    assert files_to_serve[0].code == 403
    assert "no_access.html" in files_to_serve[1].url
    assert files_to_serve[1].code == 403
    assert files_to_serve[2].code == 200


def test_sapphire_06(client, tmp_path):
    """test serving no files... this should never happen but..."""
    serv = Sapphire(timeout=10)
    try:
        client.launch("127.0.0.1", serv.get_port(), [])
        status, files_served = serv.serve_path(str(tmp_path))
        assert status == SERVED_NONE
        assert not files_served
    finally:
        serv.close()


def test_sapphire_07(tmp_path):
    """test timeout of the server"""
    serv = Sapphire(timeout=60)
    try:
        assert serv.timeout == 60  # verify default
        serv.timeout = None  # disable timeout
        assert serv.timeout == 0
        serv.timeout = 0  # disable timeout
        assert serv.timeout == 0
        serv.timeout = 0.1  # set minimum time
        assert serv.timeout == 1
        _create_test("test_case.html", tmp_path)
        serv._timeout = 0.01  # force shorter timeout for faster tests
        status, files_served = serv.serve_path(str(tmp_path))
        assert status == SERVED_TIMEOUT
        assert not files_served
    finally:
        serv.close()


def test_sapphire_08(client, tmp_path):
    """test only serving some files (SERVED_REQUEST)"""
    cb_status = {"count": 0}

    def is_running():
        cb_status["count"] += 1
        return cb_status["count"] < 3  # return false after 2nd call

    serv = Sapphire()
    try:
        files_to_serve = list()
        for i in range(3):
            files_to_serve.append(_create_test("test_case_%d.html" % i, tmp_path))
        client.launch("127.0.0.1", serv.get_port(), files_to_serve[1:])
        status, files_served = serv.serve_path(str(tmp_path), continue_cb=is_running)
        assert status == SERVED_REQUEST
        assert len(files_served) < len(files_to_serve)
    finally:
        serv.close()


def test_sapphire_09(client, tmp_path):
    """test serving interesting sized files"""
    serv = Sapphire(timeout=10)
    tests = [
        {"size": Sapphire.DEFAULT_TX_SIZE, "name": "even.html"},
        {"size": Sapphire.DEFAULT_TX_SIZE - 1, "name": "minus_one.html"},
        {"size": Sapphire.DEFAULT_TX_SIZE + 1, "name": "plus_one.html"},
        {"size": Sapphire.DEFAULT_TX_SIZE * 2, "name": "double.html"},
        {"size": 1, "name": "one.html"},
        {"size": 0, "name": "zero.html"},
    ]
    try:
        for test in tests:
            test["file"] = _TestFile(test["name"])
            t_data = "".join(random.choice("ABCD1234") for _ in range(test["size"])).encode("ascii")
            (tmp_path / test["file"].url).write_bytes(t_data)
            test["file"].md5_org = hashlib.md5(t_data).hexdigest()
        client.launch("127.0.0.1", serv.get_port(), [test["file"] for test in tests])
        status, served_list = serv.serve_path(str(tmp_path))
        assert status == SERVED_ALL
        assert len(served_list) == len(tests)
    finally:
        serv.close()
    assert client.wait(timeout=10)
    for test in tests:
        assert test["file"].code == 200
        assert test["file"].len_srv == test["size"]
        assert test["file"].md5_srv == test["file"].md5_org


def test_sapphire_10(client, tmp_path):
    """test serving a large (100MB) file"""
    serv = Sapphire(timeout=10)
    try:
        t_file = _TestFile("test_case.html")
        data_hash = hashlib.md5()
        with (tmp_path / t_file.url).open("wb") as test_fp:
            # write 100MB of 'A'
            data = b"A" * (100 * 1024)  # 100KB of 'A'
            for _ in range(1024):
                test_fp.write(data)
                data_hash.update(data)
        t_file.md5_org = data_hash.hexdigest()
        client.launch("127.0.0.1", serv.get_port(), [t_file])
        assert serv.serve_path(str(tmp_path))[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == (100 * 1024 * 1024)
    assert t_file.md5_srv == t_file.md5_org


def test_sapphire_11(client, tmp_path):
    """test serving a binary file"""
    serv = Sapphire(timeout=10)
    try:
        t_file = _create_test("test_case.html", tmp_path, data=os.urandom(512), calc_hash=True)
        client.launch("127.0.0.1", serv.get_port(), [t_file])
        assert serv.serve_path(str(tmp_path))[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == t_file.len_org
    assert t_file.md5_srv == t_file.md5_org


def test_sapphire_12():
    """test requested port is used"""
    test_port = 0x1337
    serv = Sapphire(port=test_port, timeout=1)
    try:
        assert test_port == serv.get_port()
    finally:
        serv.close()


def test_sapphire_13(client, tmp_path):
    """test serving multiple content types"""
    files_to_serve = list()
    serv = Sapphire(timeout=10)
    try:
        files_to_serve.append(_create_test("test_case.html", tmp_path))
        # create binary file without an extension
        files_to_serve.append(_create_test("test_case", tmp_path, data=os.urandom(5)))
        client.launch("127.0.0.1", serv.get_port(), files_to_serve)
        assert serv.serve_path(str(tmp_path))[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    content_types = set()
    for test in files_to_serve:
        assert test.code == 200
        assert test.len_srv == test.len_org
        file_ext = os.path.splitext(test.url)[-1]
        content_type = {".html": "text/html"}.get(file_ext, "application/octet-stream")
        content_types.add(content_type)
        assert test.content_type == content_type
    assert len(content_types) == 2


def test_sapphire_14(tmp_path):
    """test callback"""
    cb_status = {"count": 0}

    def _test_callback():
        cb_status["count"] += 1
        # return true on first call
        return cb_status["count"] < 2

    serv = Sapphire(timeout=10)
    try:
        _create_test("test_case.html", tmp_path)
        assert serv.serve_path(str(tmp_path), continue_cb=_test_callback)[0] == SERVED_NONE
    finally:
        serv.close()
    assert cb_status["count"] == 2


def test_sapphire_15(client, tmp_path):
    """test calling serve_path multiple times"""
    serv = Sapphire(timeout=10)
    try:
        for i in range(3):
            test = _create_test("test_case_%d.html" % i, tmp_path)
            client.launch("127.0.0.1", serv.get_port(), [test])
            assert serv.serve_path(str(tmp_path))[0] == SERVED_ALL
            assert client.wait(timeout=10)
            client.close()
            assert test.code == 200
            assert test.len_srv == test.len_org
            (tmp_path / test.url).unlink()
    finally:
        serv.close()


def test_sapphire_16(client, tmp_path):
    """test non required mapped redirects"""
    smap = ServerMap()
    smap.set_redirect("test_url", "blah", required=False)
    serv = Sapphire(timeout=10)
    try:
        test = _create_test("test_case.html", tmp_path)
        client.launch("127.0.0.1", serv.get_port(), [test])
        assert serv.serve_path(str(tmp_path), server_map=smap)[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org


def test_sapphire_17(client, tmp_path):
    """test required mapped redirects"""
    smap = ServerMap()
    serv = Sapphire(timeout=10)
    try:
        files_to_serve = list()
        # redir_target will be requested indirectly via the redirect
        redir_target = _create_test("redir_test_case.html", tmp_path, data=b"Redirect DATA!")
        redir_test = _TestFile("redirect_test")
        smap.set_redirect(redir_test.url, redir_target.url, required=True)
        files_to_serve.append(redir_test)
        test = _create_test("test_case.html", tmp_path)
        files_to_serve.append(test)
        client.launch("127.0.0.1", serv.get_port(), files_to_serve)
        status, served_list = serv.serve_path(str(tmp_path), server_map=smap)
        assert status == SERVED_ALL
        assert len(served_list) == len(files_to_serve)
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org
    assert redir_test.code == 200
    assert redir_test.len_srv == redir_target.len_org


def test_sapphire_18(client, tmp_path):
    """test include directories and permissions"""
    inc1_path = tmp_path / "inc1"
    inc2_path = tmp_path / "inc2"
    root_path = tmp_path / "root"
    inc1_path.mkdir()
    inc2_path.mkdir()
    root_path.mkdir()
    files_to_serve = list()
    serv = Sapphire(timeout=10)
    smap = ServerMap()
    try:
        # add files to inc dirs
        inc1 = _create_test("included_file1.html", inc1_path, data=b"blah....1")
        files_to_serve.append(inc1)
        # add a nested dir
        nest_path = inc1_path / "nested"
        nest_path.mkdir()
        # add file in a nested dir in inc1
        nest = _create_test("nested_file.html", nest_path, data=b"blah... .nested", url_prefix="nested/")
        assert nest_path / "nested_file.html"
        files_to_serve.append(nest)
        # test 404 in nested dir in inc1
        nest_404 = _TestFile("nested/nested_file_404.html")
        files_to_serve.append(nest_404)
        # test path mounted somewhere other than /
        inc2 = _create_test("included_file2.html", inc2_path, data=b"blah....2", url_prefix="inc_test/")
        files_to_serve.append(inc2)
        # test 404 in include dir
        inc404 = _TestFile("inc_test/included_file_404.html")
        assert not (nest_path / "included_file_404.html").is_file()
        files_to_serve.append(inc404)
        # test 403
        inc403 = _create_test("no_access.html", tmp_path, data=b"no_access", url_prefix="inc_test/../")
        assert (tmp_path / "no_access.html").is_file()
        files_to_serve.append(inc403)
        # test file (used to keep sever job alive)
        test = _create_test("test_case.html", root_path)
        files_to_serve.append(test)
        # add include paths
        smap.set_include("/", str(inc1_path))  # mount at '/'
        smap.set_include("inc_test", str(inc2_path))  # mount at '/inc_test'
        client.launch("127.0.0.1", serv.get_port(), files_to_serve, in_order=True)
        status, files_served = serv.serve_path(str(root_path), server_map=smap)
        assert status == SERVED_ALL
        assert len(files_served) == 4
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert inc1.code == 200
    assert inc2.code == 200
    assert nest.code == 200
    assert test.code == 200
    assert nest_404.code == 404
    assert inc404.code == 404
    assert inc403.code == 403


def test_sapphire_19(client, tmp_path):
    """test dynamic response"""
    _test_string = b"dynamic response -- TEST DATA!"

    def _dyn_test_cb():
        return _test_string

    smap = ServerMap()
    serv = Sapphire(timeout=10)
    try:
        test_dr = _TestFile("dynm_test")
        test_dr.len_org = len(_test_string)
        test_dr.md5_org = hashlib.md5(_test_string).hexdigest()
        smap.set_dynamic_response("dynm_test", _dyn_test_cb, mime_type="text/plain")
        test = _create_test("test_case.html", tmp_path)
        client.launch("127.0.0.1", serv.get_port(), [test_dr, test], in_order=True)
        assert serv.serve_path(str(tmp_path), server_map=smap)[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org
    assert test_dr.code == 200
    assert test_dr.len_srv == test_dr.len_org
    assert test_dr.md5_srv == test_dr.md5_org


def test_sapphire_20(client_factory, tmp_path):
    """test pending_files == 0 in worker thread"""
    serv = Sapphire(timeout=10)
    client_defer = client_factory(rx_size=2)
    try:
        # server should shutdown while this file is being served
        test_defer = _create_test("defer_test.html", tmp_path)
        optional = [test_defer.url]
        test = _create_test("test_case.html", tmp_path, data=b"112233")
        # this test needs to wait just long enough to have the required file served
        # but not too long or the connection will be closed by the server
        client_defer.launch("127.0.0.1", serv.get_port(), [test_defer], delay=0.1, indicate_failure=True)
        client = client_factory(rx_size=2)
        client.launch("127.0.0.1", serv.get_port(), [test], throttle=0.1)
        assert serv.serve_path(str(tmp_path), optional_files=optional)[0] == SERVED_ALL
    finally:
        serv.close()
    assert client_defer.wait(timeout=10)
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test_defer.code == 0


def test_sapphire_21(client, tmp_path):
    """test handling an invalid request"""
    serv = Sapphire(timeout=10)
    try:
        bad_test = _TestFile("bad.html")
        bad_test.custom_request = b"a bad request...0+%\xef\xb7\xba\r\n"
        optional = [bad_test.url]
        test = _create_test("test_case.html", tmp_path)
        client.launch("127.0.0.1", serv.get_port(), [bad_test, test], in_order=True)
        assert serv.serve_path(str(tmp_path), optional_files=optional)[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert test.code == 200
    assert bad_test.code == 400


def test_sapphire_22(client, tmp_path):
    """test handling an empty request"""
    serv = Sapphire(timeout=10)
    try:
        bad_test = _TestFile("bad.html")
        bad_test.custom_request = b""
        optional = [bad_test.url]
        test = _create_test("test_case.html", tmp_path)
        client.launch("127.0.0.1", serv.get_port(), [bad_test, test], indicate_failure=True, in_order=True)
        assert serv.serve_path(str(tmp_path), optional_files=optional)[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert test.code == 200
    assert bad_test.code == 0


def test_sapphire_23(client_factory, tmp_path):
    """test requesting multiple files via multiple connections"""
    default_pool_limit = Sapphire.WORKER_POOL_LIMIT
    serv = Sapphire(timeout=60)
    try:
        Sapphire.WORKER_POOL_LIMIT = 20
        to_serve = list()
        for i in range(2):
            to_serve.append(_create_test("test_%03d.html" % i, tmp_path, data=b"AAAA"))
        clients = list()
        for _ in range(Sapphire.WORKER_POOL_LIMIT):  # number of clients to spawn
            clients.append(client_factory(rx_size=1))
        for client in clients:
            client.launch("127.0.0.1", serv.get_port(), to_serve, in_order=True, throttle=0.05)
        status, files_served = serv.serve_path(str(tmp_path))
        assert status == SERVED_ALL
        assert len(to_serve) == len(files_served)
    finally:
        Sapphire.WORKER_POOL_LIMIT = default_pool_limit
        serv.close()
    for client in clients:
        assert client.wait(timeout=10)
        client.close()
    for t_file in to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org


def test_sapphire_24(client_factory, tmp_path):
    """test all request types via multiple connections"""
    def _dyn_test_cb():
        return b"A" if random.getrandbits(1) else b"AA"

    smap = ServerMap()
    serv = Sapphire(timeout=60)
    default_pool_limit = Sapphire.WORKER_POOL_LIMIT
    try:
        Sapphire.WORKER_POOL_LIMIT = 10
        to_serve = list()
        for i in range(50):
            # add required files
            to_serve.append(_create_test("test_%03d.html" % i, tmp_path, data=b"A" * ((i % 2) + 1)))
            # add a missing files
            to_serve.append(_TestFile("missing_%03d.html" % i))
            # add optional files
            opt_path = tmp_path / ("opt_%03d.html" % i)
            opt_path.write_bytes(b"A" * ((i % 2) + 1))
            to_serve.append(_TestFile(opt_path.name))
            # add redirects
            redir_target = _create_test("redir_%03d.html" % i, tmp_path, data=b"AA")
            to_serve.append(_TestFile("redir_%03d" % i))
            smap.set_redirect(to_serve[-1].url, redir_target.url, required=random.getrandbits(1) > 0)
            # add dynamic responses
            to_serve.append(_TestFile("dynm_%03d" % i))
            smap.set_dynamic_response(to_serve[-1].url, _dyn_test_cb, mime_type="text/plain")
        clients = list()
        for _ in range(100):  # number of clients to spawn
            clients.append(client_factory(rx_size=1))
            throttle = 0.05 if random.getrandbits(1) else 0
            clients[-1].launch("127.0.0.1", serv.get_port(), to_serve, throttle=throttle)
        assert serv.serve_path(str(tmp_path), server_map=smap)[0] == SERVED_ALL
    finally:
        serv.close()
        Sapphire.WORKER_POOL_LIMIT = default_pool_limit


def test_sapphire_25(client, tmp_path):
    """test dynamic response with bad callbacks"""
    smap = ServerMap()
    serv = Sapphire(timeout=10)
    try:
        test_dr = _TestFile("dynm_test")
        smap.set_dynamic_response("dynm_test", lambda: None, mime_type="text/plain")
        test = _create_test("test_case.html", tmp_path)
        client.launch("127.0.0.1", serv.get_port(), [test_dr, test], in_order=True)
        with pytest.raises(TypeError):
            serv.serve_path(str(tmp_path), server_map=smap)
    finally:
        serv.close()


def test_sapphire_26(client, tmp_path):
    """test serving to a slow client"""
    serv = Sapphire(timeout=60)
    try:
        t_data = "".join(random.choice("ABCD1234") for _ in range(0x19000))  # 100KB
        t_file = _create_test("test_case.html", tmp_path, data=t_data.encode("ascii"), calc_hash=True)
        # rx_size 10KB and throttle to 0.25 sec, which will be ~50KB/s
        # also taking 2.5 seconds to complete will hopefully find problems
        # with any assumptions that were made
        client.rx_size = 0x2800
        client.launch("127.0.0.1", serv.get_port(), [t_file], throttle=0.25)
        assert serv.serve_path(str(tmp_path))[0] == SERVED_ALL
    finally:
        serv.close()
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == t_file.len_org
    assert t_file.md5_srv == t_file.md5_org


def test_sapphire_27(client, tmp_path):
    """test timeout while requesting multiple files"""
    serv = Sapphire(timeout=1)  # minimum timeout is 1 second
    try:
        files_to_serve = list()
        t_data = "".join(random.choice("ABCD1234") for _ in range(1024)).encode("ascii")
        for i in range(50):
            files_to_serve.append(_create_test("test_case_%03d.html" % i, tmp_path, data=t_data))
        client.rx_size = 512
        client.launch("127.0.0.1", serv.get_port(), files_to_serve, indicate_failure=True, throttle=0.1)
        status, files_served = serv.serve_path(str(tmp_path))
        assert status == SERVED_TIMEOUT
        assert len(files_served) < len(files_to_serve)
    finally:
        serv.close()


def test_sapphire_28(client, tmp_path):
    """test Sapphire.serve_testcase()"""
    serv = Sapphire(timeout=10)
    try:
        test = TestCase("test.html", "none.test", "foo")
        test.add_from_data(b"test", "test.html")
        t_file = _create_test(test.landing_page, tmp_path)
        client.launch("127.0.0.1", serv.get_port(), [t_file])
        assert test.duration is None
        status, files_served = serv.serve_testcase(test)
        assert status == SERVED_ALL
        assert files_served
        assert test.duration >= 0
    finally:
        serv.close()


def test_sapphire_29(client_factory, tmp_path):
    """test Sapphire.serve_path() with forever=True"""
    clients = list()
    serv = Sapphire(timeout=10)
    try:
        assert serv.timeout == 10
        test = _create_test("test_case.html", tmp_path)
        for _ in range(3):
            clients.append(client_factory())
        for client in clients:
            client.launch("127.0.0.1", serv.get_port(), [test], skip_served=False)
        def _test_callback():
            with test.lock:
                return test.requested < 3
        assert serv.serve_path(str(tmp_path), continue_cb=_test_callback, forever=True)[0] == SERVED_ALL
    finally:
        serv.close()
    for client in clients:
        assert client.wait(timeout=10)
        client.close()
    assert test.requested == 3
    assert test.code == 200
    assert test.len_srv == test.len_org


def test_serve_job_01(tmp_path):
    """test creating an empty ServeJob"""
    job = ServeJob(str(tmp_path))
    assert not job.forever
    assert job.status == SERVED_ALL
    assert job.check_request("") is None
    assert job.check_request("test") is None
    assert job.check_request("test/test/") is None
    assert job.check_request("test/../../") is None
    assert not job.is_forbidden(str(tmp_path))
    assert not job.is_forbidden(str(tmp_path / "missing_file"))
    assert job.pending_files() == 0
    assert not job.is_complete()
    assert job.remove_pending("no_file.test")
    job.finish()
    assert job.is_complete()


def test_serve_job_02(tmp_path):
    """test ServeJob two required files and one optional file"""
    opt_path = tmp_path / "opt_file.txt"
    opt_path.write_bytes(b"a")
    req1_path = tmp_path / "req_file_1.txt"
    req1_path.write_bytes(b"a")
    (tmp_path / "test").mkdir()
    req2_path = tmp_path / "test" / "req_file_2.txt"
    req2_path.write_bytes(b"a")
    job = ServeJob(str(tmp_path), optional_files=[opt_path.name])
    assert job.status == SERVED_NONE
    assert not job.is_complete()
    resource = job.check_request("req_file_1.txt")
    assert resource.required
    assert resource.target == str(tmp_path / "req_file_1.txt")
    assert resource.type == Resource.URL_FILE
    assert not job.is_forbidden(str(req1_path))
    assert not job.remove_pending("no_file.test")
    assert job.pending_files() == 2
    assert not job.remove_pending(str(req1_path))
    assert job.status == SERVED_REQUEST
    assert job.pending_files() == 1
    assert job.remove_pending(str(req2_path))
    assert job.status == SERVED_ALL
    assert job.pending_files() == 0
    assert job.remove_pending(str(req1_path))
    resource = job.check_request("opt_file.txt")
    assert not resource.required
    assert resource.target == str(tmp_path / "opt_file.txt")
    assert resource.type == Resource.URL_FILE
    assert job.remove_pending(str(opt_path))
    job.finish()
    assert job.is_complete()


def test_serve_job_03(tmp_path):
    """test ServeJob redirects"""
    smap = ServerMap()
    smap.set_redirect("one", "somefile.txt", required=False)
    smap.set_redirect("two", "reqfile.txt")
    job = ServeJob(str(tmp_path), server_map=smap)
    assert job.status == SERVED_NONE
    resource = job.check_request("one")
    assert resource.type == Resource.URL_REDIRECT
    resource = job.check_request("two?q=123")
    assert resource is not None
    assert resource.type == Resource.URL_REDIRECT
    assert job.pending_files() == 1
    assert job.remove_pending("two")
    assert job.pending_files() == 0


def test_serve_job_04(tmp_path):
    """test ServeJob includes"""
    srv_root = tmp_path / "root"
    srv_include = tmp_path / "test"
    srv_include_2 = tmp_path / "test_2"
    srv_include_nested = srv_include / "nested"
    srv_root.mkdir()
    srv_include.mkdir()
    srv_include_2.mkdir()
    srv_include_nested.mkdir()
    test_1 = srv_root / "req_file.txt"
    test_1.write_bytes(b"a")
    inc_1 = srv_include / "test_file.txt"
    inc_1.write_bytes(b"b")
    nst_1 = srv_include_nested / "nested_file.txt"
    nst_1.write_bytes(b"c")
    inc_2 = srv_include_2 / "test_file_2.txt"
    inc_2.write_bytes(b"d")
    smap = ServerMap()
    # stub out ServerMap._check_url() because it is too
    # restrictive to allow testing of some functionality
    smap._check_url = lambda x: x
    smap.set_include("testinc", str(srv_include))
    smap.set_include("testinc/fakedir", str(srv_include))
    smap.set_include("testinc/1/2/3", str(srv_include))
    smap.set_include("", str(srv_include))
    smap.set_include("testinc/inc2", str(srv_include_2))
    job = ServeJob(str(srv_root), server_map=smap)
    assert job.status == SERVED_NONE
    # test includes that map to 'srv_include'
    for incl, inc_path in smap.include.items():
        if inc_path != str(srv_include):  # only check 'srv_include' mappings
            continue
        resource = job.check_request("/".join([incl, "test_file.txt"]))
        assert resource.type == Resource.URL_INCLUDE
        assert resource.target == str(inc_1)
    # test nested include path pointing to a different include
    resource = job.check_request("testinc/inc2/test_file2.txt?q=123")
    assert resource.type == Resource.URL_INCLUDE
    assert resource.target == str(srv_include_2 / "test_file2.txt")
    # test redirect root without leading '/'
    resource = job.check_request("test_file.txt")
    assert resource.type == Resource.URL_INCLUDE
    assert resource.target == str(srv_include / "test_file.txt")
    # test redirect with file in a nested directory
    resource = job.check_request("/".join(["testinc", "nested", "nested_file.txt"]))
    assert resource.type == Resource.URL_INCLUDE
    assert resource.target == str(nst_1)
    assert not job.is_forbidden(str(srv_root / ".." / "test" / "test_file.txt"))
    assert not job.is_forbidden(str(srv_include / ".." / "root" / "req_file.txt"))


def test_serve_job_05(tmp_path):
    """test ServeJob dynamic"""
    smap = ServerMap()
    smap.set_dynamic_response("cb1", lambda: 0, mime_type="mime_type")
    smap.set_dynamic_response("cb2", lambda: 1)
    job = ServeJob(str(tmp_path / "root"), server_map=smap)
    assert job.status == SERVED_ALL
    assert job.pending_files() == 0
    resource = job.check_request("cb1")
    assert resource.type == Resource.URL_DYNAMIC
    assert callable(resource.target)
    assert isinstance(resource.mime, str)
    resource = job.check_request("cb2?q=123")
    assert resource is not None
    assert resource.type == Resource.URL_DYNAMIC
    assert callable(resource.target)
    assert isinstance(resource.mime, str)


def test_serve_job_06(tmp_path):
    """test accessing forbidden files"""
    srv_root = tmp_path / "root"
    srv_root.mkdir()
    test_1 = srv_root / "req_file.txt"
    test_1.write_bytes(b"a")
    no_access = tmp_path / "no_access.txt"
    no_access.write_bytes(b"a")
    job = ServeJob(str(srv_root))
    assert job.status == SERVED_NONE
    assert job.pending_files() == 1
    resource = job.check_request("../no_access.txt")
    assert resource.target == str(no_access)
    assert resource.type == Resource.URL_FILE
    assert not job.is_forbidden(str(test_1))
    assert job.is_forbidden(str(srv_root / "../no_access.txt"))


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="Unsupported on Windows")
def test_serve_job_07(tmp_path):
    """test ServeJob with file names containing invalid characters"""
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"a")
    (tmp_path / "?_2.txt").write_bytes(b"a")
    job = ServeJob(str(tmp_path))
    assert job.status == SERVED_NONE
    assert job.pending_files() == 1
    assert job.check_request("test.txt").target == str(test_file)


def test_response_data_01():
    """test _200_header()"""
    output = Sapphire._200_header("10", "text/html")  # pylint: disable=protected-access
    assert "Content-Length: 10" in output
    assert "Content-Type: text/html" in output


def test_response_data_02():
    """test _307_redirect()"""
    output = Sapphire._307_redirect("http://some.test.url")  # pylint: disable=protected-access
    assert "Location: http://some.test.url" in output


def test_response_data_03():
    """test _4xx_page() without close timeout"""
    output = Sapphire._4xx_page(400, "Bad Request")  # pylint: disable=protected-access
    assert "Content-Length: " in output
    assert "HTTP/1.1 400 Bad Request" in output
    assert "400!" in output


def test_response_data_04():
    """test _4xx_page() with close timeout"""
    try:
        Sapphire.CLOSE_CLIENT_ERROR = 10
        output = Sapphire._4xx_page(404, "Not Found")  # pylint: disable=protected-access
        assert "Content-Length: " in output
        assert "HTTP/1.1 404 Not Found" in output
        assert "<script>window.setTimeout(window.close, 10000)</script>" in output
    finally:
        Sapphire.CLOSE_CLIENT_ERROR = None
