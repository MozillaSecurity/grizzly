# coding=utf-8
"""
Sapphire unit tests
"""
# pylint: disable=protected-access

import hashlib
import os
import random
import socket
import threading
from platform import system
from urllib.parse import quote, urlparse

from pytest import mark, raises

from .core import Sapphire
from .job import Served
from .server_map import ServerMap
from .worker import Worker


class _TestFile:
    def __init__(self, url, url_prefix=None):
        self.code = None
        self.content_type = None
        self.custom_request = None
        if url_prefix:
            self.file = "".join((url_prefix, url))
        else:
            self.file = url
        self.len_org = 0  # original file length
        self.len_srv = 0  # served file length
        self.lock = threading.Lock()
        self.md5_org = None
        self.md5_srv = None
        self.requested = 0  # number of time file was requested
        url = urlparse(self.file.replace("\\", "/"))
        self.url = (
            "?".join((quote(url.path), url.query)) if url.query else quote(url.path)
        )


def _create_test(fname, path, data=b"Test!", calc_hash=False, url_prefix=None):
    test = _TestFile(fname, url_prefix=url_prefix)
    with (path / fname).open("w+b") as out_fp:
        out_fp.write(data)
        test.len_org = out_fp.tell()
        if calc_hash:
            out_fp.seek(0)
            test.md5_org = hashlib.md5(out_fp.read()).hexdigest()
    return test


def test_sapphire_00(client, tmp_path):
    """test requesting a single file"""
    with Sapphire(timeout=10) as serv:
        assert serv.timeout == 10
        test = _create_test("test_case.html", tmp_path)
        client.launch("127.0.0.1", serv.port, [test])
        assert serv.serve_path(tmp_path)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org


def test_sapphire_01(client, tmp_path):
    """test requesting multiple files (test cleanup code)"""
    to_serve = list()
    for i in range(100):
        to_serve.append(
            _create_test(
                "test_%03d.html" % i, tmp_path, data=os.urandom(5), calc_hash=True
            )
        )
    with Sapphire(timeout=30) as serv:
        client.launch("127.0.0.1", serv.port, to_serve)
        status, files_served = serv.serve_path(tmp_path)
    assert status == Served.ALL
    assert len(to_serve) == len(files_served)
    assert client.wait(timeout=10)
    for t_file in to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org
        assert t_file.md5_srv == t_file.md5_org


def test_sapphire_02(client, tmp_path):
    """test serving optional file"""
    files_to_serve = list()
    for i in range(3):
        files_to_serve.append(_create_test("test_case_%d.html" % i, tmp_path))
    optional = [files_to_serve[0].file]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, files_to_serve, in_order=True)
        status, served_list = serv.serve_path(tmp_path, optional_files=optional)
    assert status == Served.ALL
    assert len(files_to_serve) == len(served_list)
    assert client.wait(timeout=10)
    for t_file in files_to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org


def test_sapphire_03(client, tmp_path):
    """test skipping optional file"""
    files_to_serve = list()
    for i in range(3):
        files_to_serve.append(_create_test("test_case_%d.html" % i, tmp_path))
    optional = [files_to_serve[0].file]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, files_to_serve[1:])
        status, served_list = serv.serve_path(tmp_path, optional_files=optional)
    assert status == Served.ALL
    assert len(served_list) == len(files_to_serve) - 1
    assert client.wait(timeout=10)
    assert files_to_serve[0].code is None
    assert files_to_serve[0].len_srv == 0
    for t_file in files_to_serve[1:]:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org


def test_sapphire_04(client, tmp_path):
    """test requesting invalid file (404)"""
    files_to_serve = list()
    files_to_serve.append(_TestFile("does_not_exist.html"))
    files_to_serve.append(_create_test("test_case.html", tmp_path))
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, files_to_serve, in_order=True)
        assert serv.serve_path(tmp_path)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert "does_not_exist.html" in files_to_serve[0].file
    assert files_to_serve[0].code == 404
    assert files_to_serve[1].code == 200


def test_sapphire_05(client, tmp_path):
    """test requesting a file outside of the server root (403)"""
    files_to_serve = list()
    root_dir = tmp_path / "root"
    root_dir.mkdir()
    # add invalid file
    files_to_serve.append(_TestFile(os.path.abspath(__file__)))
    # add file in parent of root_dir
    files_to_serve.append(
        _create_test("no_access.html", tmp_path, data=b"no_access", url_prefix="../")
    )
    assert (tmp_path / "no_access.html").is_file()
    # add valid test
    files_to_serve.append(_create_test("test_case.html", root_dir))
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, files_to_serve, in_order=True)
        status, files_served = serv.serve_path(root_dir)
    assert status == Served.ALL
    assert len(files_served) == 1
    assert client.wait(timeout=10)
    assert os.path.basename(__file__) in files_to_serve[0].file
    assert files_to_serve[0].code == 403
    assert "no_access.html" in files_to_serve[1].file
    assert files_to_serve[1].code == 403
    assert files_to_serve[2].code == 200


def test_sapphire_06(client, tmp_path):
    """test serving no files... this should never happen but..."""
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [])
        status, files_served = serv.serve_path(tmp_path)
    assert status == Served.NONE
    assert not files_served


def test_sapphire_07(tmp_path):
    """test timeout of the server"""
    with Sapphire(timeout=60) as serv:
        assert serv.timeout == 60  # verify default
        serv.timeout = None  # disable timeout
        assert serv.timeout == 0
        serv.timeout = 0  # disable timeout
        assert serv.timeout == 0
        serv.timeout = 0.1  # set minimum time
        assert serv.timeout == 1
        _create_test("test_case.html", tmp_path)
        serv._timeout = 0.01  # force shorter timeout for faster tests
        status, files_served = serv.serve_path(tmp_path)
    assert status == Served.TIMEOUT
    assert not files_served


def test_sapphire_08(client, tmp_path):
    """test only serving some files (Served.REQUEST)"""
    cb_status = {"count": 0}

    def is_running():
        cb_status["count"] += 1
        return cb_status["count"] < 3  # return false after 2nd call

    files_to_serve = list()
    for i in range(3):
        files_to_serve.append(_create_test("test_case_%d.html" % i, tmp_path))
    with Sapphire() as serv:
        client.launch("127.0.0.1", serv.port, files_to_serve[1:])
        status, files_served = serv.serve_path(tmp_path, continue_cb=is_running)
    assert status == Served.REQUEST
    assert len(files_served) < len(files_to_serve)


def test_sapphire_09(client, tmp_path):
    """test serving interesting sized files"""
    tests = [
        {"size": Worker.DEFAULT_TX_SIZE, "name": "even.html"},
        {"size": Worker.DEFAULT_TX_SIZE - 1, "name": "minus_one.html"},
        {"size": Worker.DEFAULT_TX_SIZE + 1, "name": "plus_one.html"},
        {"size": Worker.DEFAULT_TX_SIZE * 2, "name": "double.html"},
        {"size": 1, "name": "one.html"},
        {"size": 0, "name": "zero.html"},
    ]
    for test in tests:
        test["file"] = _TestFile(test["name"])
        t_data = "".join(random.choice("ABCD1234") for _ in range(test["size"])).encode(
            "ascii"
        )
        (tmp_path / test["file"].file).write_bytes(t_data)
        test["file"].md5_org = hashlib.md5(t_data).hexdigest()
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [test["file"] for test in tests])
        status, served_list = serv.serve_path(tmp_path)
    assert status == Served.ALL
    assert len(served_list) == len(tests)
    assert client.wait(timeout=10)
    for test in tests:
        assert test["file"].code == 200
        assert test["file"].len_srv == test["size"]
        assert test["file"].md5_srv == test["file"].md5_org


def test_sapphire_10(client, tmp_path):
    """test serving a large (100MB) file"""
    t_file = _TestFile("test_case.html")
    data_hash = hashlib.md5()
    with (tmp_path / t_file.file).open("wb") as test_fp:
        # write 100MB of 'A'
        data = b"A" * (100 * 1024)  # 100KB of 'A'
        for _ in range(1024):
            test_fp.write(data)
            data_hash.update(data)
    t_file.md5_org = data_hash.hexdigest()
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [t_file])
        assert serv.serve_path(tmp_path)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == (100 * 1024 * 1024)
    assert t_file.md5_srv == t_file.md5_org


def test_sapphire_11(client, tmp_path):
    """test serving a binary file"""
    t_file = _create_test(
        "test_case.html", tmp_path, data=os.urandom(512), calc_hash=True
    )
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [t_file])
        assert serv.serve_path(tmp_path)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == t_file.len_org
    assert t_file.md5_srv == t_file.md5_org


def test_sapphire_12():
    """test requested port is used"""
    test_port = 0x1337
    with Sapphire(port=test_port, timeout=1) as serv:
        assert test_port == serv.port


def test_sapphire_13(client, tmp_path):
    """test serving multiple content types"""
    files_to_serve = list()
    files_to_serve.append(_create_test("test_case.html", tmp_path))
    # create binary file without an extension
    files_to_serve.append(_create_test("test_case", tmp_path, data=os.urandom(5)))
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, files_to_serve)
        assert serv.serve_path(tmp_path)[0] == Served.ALL
    assert client.wait(timeout=10)
    content_types = set()
    for test in files_to_serve:
        assert test.code == 200
        assert test.len_srv == test.len_org
        file_ext = os.path.splitext(test.file)[-1]
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

    with Sapphire(timeout=10) as serv:
        _create_test("test_case.html", tmp_path)
        assert serv.serve_path(tmp_path, continue_cb=_test_callback)[0] == Served.NONE
    assert cb_status["count"] == 2


def test_sapphire_15(client, tmp_path):
    """test calling serve_path multiple times"""
    with Sapphire(timeout=10) as serv:
        for i in range(3):
            test = _create_test("test_case_%d.html" % i, tmp_path)
            client.launch("127.0.0.1", serv.port, [test])
            assert serv.serve_path(tmp_path)[0] == Served.ALL
            assert client.wait(timeout=10)
            client.close()
            assert test.code == 200
            assert test.len_srv == test.len_org
            (tmp_path / test.file).unlink()


def test_sapphire_16(client, tmp_path):
    """test non required mapped redirects"""
    smap = ServerMap()
    smap.set_redirect("test_url", "blah", required=False)
    test = _create_test("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [test])
        assert serv.serve_path(tmp_path, server_map=smap)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org


@mark.parametrize(
    "path, query",
    [
        # simple path
        ("test.html", None),
        # simple path with query
        ("test.html", "foo=1&bar=2"),
        # non-alphanumeric chars (valid characters to use on filesystem)
        ("!@$%^&(_+-=[]),'~`{}", None),
        # extended ascii chars
        ("€d’é-ñÿ", None),
    ],
)
def test_sapphire_17(client, tmp_path, path, query):
    """test required mapped redirects"""
    smap = ServerMap()
    with Sapphire(timeout=10) as serv:
        # target will be requested indirectly via the redirect
        target = _create_test(path, tmp_path, data=b"Redirect DATA!")
        request_path = "redirect" if query is None else "?".join(("redirect", query))
        redirect = _TestFile(request_path)
        # point "redirect" at target
        smap.set_redirect("redirect", target.file, required=True)
        client.launch("127.0.0.1", serv.port, [redirect])
        status, served = serv.serve_path(tmp_path, server_map=smap)
    assert status == Served.ALL
    assert len(served) == 1
    assert client.wait(timeout=10)
    assert redirect.code == 200
    assert redirect.len_srv == target.len_org


def test_sapphire_18(client, tmp_path):
    """test include directories and permissions"""
    inc1_path = tmp_path / "inc1"
    inc2_path = tmp_path / "inc2"
    root_path = tmp_path / "root"
    inc1_path.mkdir()
    inc2_path.mkdir()
    root_path.mkdir()
    files_to_serve = list()
    smap = ServerMap()
    with Sapphire(timeout=10) as serv:
        # add files to inc dirs
        inc1 = _create_test("included_file1.html", inc1_path, data=b"blah....1")
        files_to_serve.append(inc1)
        # add a nested dir
        nest_path = inc1_path / "nested"
        nest_path.mkdir()
        # add file in a nested dir in inc1
        nest = _create_test(
            "nested_file.html", nest_path, data=b"blah... .nested", url_prefix="nested/"
        )
        assert nest_path / "nested_file.html"
        files_to_serve.append(nest)
        # test 404 in nested dir in inc1
        nest_404 = _TestFile("nested/nested_file_404.html")
        files_to_serve.append(nest_404)
        # test path mounted somewhere other than /
        inc2 = _create_test(
            "included_file2.html", inc2_path, data=b"blah....2", url_prefix="inc_test/"
        )
        files_to_serve.append(inc2)
        # test 404 in include dir
        inc404 = _TestFile("inc_test/included_file_404.html")
        assert not (nest_path / "included_file_404.html").is_file()
        files_to_serve.append(inc404)
        # test 403
        inc403 = _create_test(
            "no_access.html", tmp_path, data=b"no_access", url_prefix="inc_test/../"
        )
        assert (tmp_path / "no_access.html").is_file()
        files_to_serve.append(inc403)
        # test file (used to keep sever job alive)
        test = _create_test("test_case.html", root_path)
        files_to_serve.append(test)
        # add include paths
        smap.set_include("/", str(inc1_path))  # mount at '/'
        smap.set_include("inc_test", str(inc2_path))  # mount at '/inc_test'
        client.launch("127.0.0.1", serv.port, files_to_serve, in_order=True)
        status, files_served = serv.serve_path(root_path, server_map=smap)
    assert status == Served.ALL
    assert "test_case.html" in files_served
    assert (inc1_path / "included_file1.html").as_posix() in files_served
    assert (inc2_path / "included_file2.html").as_posix() in files_served
    assert (nest_path / "nested_file.html").as_posix() in files_served
    assert client.wait(timeout=10)
    assert inc1.code == 200
    assert inc2.code == 200
    assert nest.code == 200
    assert test.code == 200
    assert nest_404.code == 404
    assert inc404.code == 404
    assert inc403.code == 403


@mark.parametrize(
    "query, required",
    [
        # dynamic response not required
        (None, False),
        # dynamic response is required
        (None, True),
        # dynamic response with query string
        ("test123", True),
        # dynamic response with empty query string
        ("", True),
    ],
)
def test_sapphire_19(client, tmp_path, query, required):
    """test dynamic response"""
    _data = b"dynamic response -- TEST DATA!"
    # build request
    path = "dyn_test"
    if query is not None:
        request = "?".join([path, query])
    else:
        request = path

    # setup custom callback
    def dr_callback(data):
        if query:
            assert data == query
        else:
            assert data == ""
        return _data

    smap = ServerMap()
    smap.set_dynamic_response(
        path, dr_callback, mime_type="text/plain", required=required
    )
    # create files
    test_dr = _TestFile(request)
    test_dr.len_org = len(_data)
    test_dr.md5_org = hashlib.md5(_data).hexdigest()
    test = _create_test("test_case.html", tmp_path)
    if required:
        optional = [test.file]
        files = [test, test_dr]
    else:
        optional = [test_dr.file]
        files = [test_dr, test]
    # test request
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, files, in_order=True)
        assert (
            serv.serve_path(tmp_path, optional_files=optional, server_map=smap)[0]
            == Served.ALL
        )
    assert client.wait(timeout=10)
    if not required:
        assert test.code == 200
        assert test.len_srv == test.len_org
    assert test_dr.code == 200
    assert test_dr.len_srv == test_dr.len_org
    assert test_dr.md5_srv == test_dr.md5_org


def test_sapphire_20(client_factory, tmp_path):
    """test pending_files == 0 in worker thread"""
    client_defer = client_factory(rx_size=2)
    # server should shutdown while this file is being served
    test_defer = _create_test("defer_test.html", tmp_path)
    optional = [test_defer.file]
    test = _create_test("test_case.html", tmp_path, data=b"112233")
    with Sapphire(timeout=10) as serv:
        # this test needs to wait just long enough to have the required file served
        # but not too long or the connection will be closed by the server
        client_defer.launch(
            "127.0.0.1", serv.port, [test_defer], delay=0.1, indicate_failure=True
        )
        client = client_factory(rx_size=2)
        client.launch("127.0.0.1", serv.port, [test], throttle=0.1)
        assert serv.serve_path(tmp_path, optional_files=optional)[0] == Served.ALL
    assert client_defer.wait(timeout=10)
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test_defer.code == 0


def test_sapphire_21(client, tmp_path):
    """test handling an invalid request"""
    bad_test = _TestFile("bad.html")
    bad_test.custom_request = b"a bad request...0+%\xef\xb7\xba\r\n"
    optional = [bad_test.file]
    test = _create_test("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [bad_test, test], in_order=True)
        assert serv.serve_path(tmp_path, optional_files=optional)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert test.code == 200
    assert bad_test.code == 400


def test_sapphire_22(client, tmp_path):
    """test handling an empty request"""
    bad_test = _TestFile("bad.html")
    bad_test.custom_request = b""
    optional = [bad_test.file]
    test = _create_test("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch(
            "127.0.0.1",
            serv.port,
            [bad_test, test],
            indicate_failure=True,
            in_order=True,
        )
        assert serv.serve_path(tmp_path, optional_files=optional)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert test.code == 200
    assert bad_test.code == 0


def test_sapphire_23(client_factory, tmp_path):
    """test requesting multiple files via multiple connections"""
    to_serve = list()
    for i in range(2):
        to_serve.append(_create_test("test_%03d.html" % i, tmp_path, data=b"AAAA"))
    max_workers = 20
    with Sapphire(max_workers=max_workers, timeout=60) as serv:
        clients = list()
        try:
            for _ in range(max_workers):  # number of clients to spawn
                clients.append(client_factory(rx_size=1))
            for client in clients:
                client.launch(
                    "127.0.0.1", serv.port, to_serve, in_order=True, throttle=0.05
                )
            status, files_served = serv.serve_path(tmp_path)
            # call serv.close() instead of waiting for the clients to timeout
            serv.close()
        finally:
            for client in clients:
                assert client.wait(timeout=10)
                client.close()
    assert status == Served.ALL
    assert len(to_serve) == len(files_served)
    for t_file in to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org


def test_sapphire_24(client_factory, tmp_path):
    """test all request types via multiple connections"""

    def _dyn_test_cb(_):
        return b"A" if random.getrandbits(1) else b"AA"

    smap = ServerMap()
    with Sapphire(max_workers=10, timeout=60) as serv:
        to_serve = list()
        for i in range(50):
            # add required files
            to_serve.append(
                _create_test("test_%03d.html" % i, tmp_path, data=b"A" * ((i % 2) + 1))
            )
            # add a missing files
            to_serve.append(_TestFile("missing_%03d.html" % i))
            # add optional files
            opt_path = tmp_path / ("opt_%03d.html" % i)
            opt_path.write_bytes(b"A" * ((i % 2) + 1))
            to_serve.append(_TestFile(opt_path.name))
            # add redirects
            redir_target = _create_test("redir_%03d.html" % i, tmp_path, data=b"AA")
            to_serve.append(_TestFile("redir_%03d" % i))
            smap.set_redirect(
                to_serve[-1].file, redir_target.file, required=random.getrandbits(1) > 0
            )
            # add dynamic responses
            to_serve.append(_TestFile("dynm_%03d" % i))
            smap.set_dynamic_response(
                to_serve[-1].file, _dyn_test_cb, mime_type="text/plain"
            )
        clients = list()
        for _ in range(100):  # number of clients to spawn
            clients.append(client_factory(rx_size=1))
            throttle = 0.05 if random.getrandbits(1) else 0
            clients[-1].launch("127.0.0.1", serv.port, to_serve, throttle=throttle)
        assert serv.serve_path(tmp_path, server_map=smap)[0] == Served.ALL


def test_sapphire_25(client, tmp_path):
    """test dynamic response with bad callbacks"""
    test_dr = _TestFile("dynm_test")
    smap = ServerMap()
    smap.set_dynamic_response("dynm_test", lambda _: None, mime_type="text/plain")
    test = _create_test("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [test_dr, test], in_order=True)
        with raises(TypeError):
            serv.serve_path(tmp_path, server_map=smap)


def test_sapphire_26(client, tmp_path):
    """test serving to a slow client"""
    t_data = "".join(random.choice("ABCD1234") for _ in range(0x19000))  # 100KB
    t_file = _create_test(
        "test_case.html", tmp_path, data=t_data.encode("ascii"), calc_hash=True
    )
    # rx_size 10KB and throttle to 0.25 sec, which will be ~50KB/s
    # also taking 2.5 seconds to complete will hopefully find problems
    # with any assumptions that were made
    client.rx_size = 0x2800
    with Sapphire(timeout=60) as serv:
        client.launch("127.0.0.1", serv.port, [t_file], throttle=0.25)
        assert serv.serve_path(tmp_path)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == t_file.len_org
    assert t_file.md5_srv == t_file.md5_org


def test_sapphire_27(client, tmp_path):
    """test timeout while requesting multiple files"""
    files_to_serve = list()
    t_data = "".join(random.choice("ABCD1234") for _ in range(1024)).encode("ascii")
    for i in range(50):
        files_to_serve.append(
            _create_test("test_case_%03d.html" % i, tmp_path, data=t_data)
        )
    client.rx_size = 512
    with Sapphire(timeout=1) as serv:  # minimum timeout is 1 second
        client.launch(
            "127.0.0.1", serv.port, files_to_serve, indicate_failure=True, throttle=0.1
        )
        status, files_served = serv.serve_path(tmp_path)
    assert status == Served.TIMEOUT
    assert len(files_served) < len(files_to_serve)


def test_sapphire_28(client_factory, tmp_path):
    """test Sapphire.serve_path() with forever=True"""
    clients = list()
    with Sapphire(timeout=10) as serv:
        assert serv.timeout == 10
        test = _create_test("test_case.html", tmp_path)
        for _ in range(3):
            clients.append(client_factory())
        for client in clients:
            client.launch("127.0.0.1", serv.port, [test], skip_served=False)

        def _test_callback():
            with test.lock:
                return test.requested < 3

        assert (
            serv.serve_path(tmp_path, continue_cb=_test_callback, forever=True)[0]
            == Served.ALL
        )
    for client in clients:
        assert client.wait(timeout=10)
        client.close()
    assert test.requested == 3
    assert test.code == 200
    assert test.len_srv == test.len_org


@mark.parametrize(
    "file_name",
    [
        # space in file name
        "test case.html",
        # non-alphanumeric chars (valid characters to use on filesystem)
        "!@$%^&(_+-=[]),'~`{}",
        # extended ascii chars
        "€d’é-ñÿ",
    ],
)
def test_sapphire_29(client, tmp_path, file_name):
    """test interesting file names"""
    to_serve = [_create_test(file_name, tmp_path)]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, to_serve)
        assert serv.serve_path(tmp_path)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert all(t_file.code == 200 for t_file in to_serve)


def test_sapphire_30(client, tmp_path):
    """test interesting path string"""
    path = "".join(chr(i) for i in range(256))
    to_serve = [
        # should not trigger crash
        _TestFile(path),
        # used to keep server running
        _create_test("a.html", tmp_path),
    ]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, to_serve, in_order=True)
        assert serv.serve_path(tmp_path, optional_files=[path])[0] == Served.ALL
    assert client.wait(timeout=10)
    assert all(t_file.code is not None for t_file in to_serve)


def test_sapphire_31(mocker):
    """test Sapphire._create_listening_socket()"""
    fake_sleep = mocker.patch("sapphire.core.sleep", autospec=True)
    fake_sock = mocker.patch("sapphire.core.socket", autospec=True)
    assert Sapphire._create_listening_socket(False, None)
    assert fake_sock.return_value.close.call_count == 0
    assert fake_sock.return_value.setsockopt.call_count == 1
    assert fake_sock.return_value.settimeout.call_count == 1
    assert fake_sock.return_value.bind.call_count == 1
    assert fake_sock.return_value.listen.call_count == 1
    assert fake_sleep.call_count == 0
    fake_sock.reset_mock()
    # failure to bind
    fake_sock.return_value.bind.side_effect = OSError
    with raises(OSError):
        Sapphire._create_listening_socket(False, None)
    assert fake_sock.return_value.close.call_count == 1
    assert fake_sleep.call_count == 0
    fake_sock.reset_mock()
    # failure and pass on retry
    exc = OSError()
    exc.errno = 10013
    fake_sock.return_value.bind.side_effect = (exc, None)
    assert Sapphire._create_listening_socket(False, None)
    assert fake_sock.return_value.close.call_count == 1
    assert fake_sock.return_value.listen.call_count == 1
    assert fake_sleep.call_count == 1


def test_sapphire_32(mocker):
    """test Sapphire.clear_backlog()"""
    mocker.patch("sapphire.core.socket", autospec=True)
    mocker.patch("sapphire.core.time", autospec=True, return_value=1)
    pending = mocker.Mock(spec_set=socket.socket)
    with Sapphire(timeout=10) as serv:
        serv._socket = mocker.Mock(spec_set=socket.socket)
        serv._socket.accept.side_effect = ((pending, None), OSError, BlockingIOError)
        serv.clear_backlog()
        assert serv._socket.accept.call_count == 3
        assert serv._socket.settimeout.call_count == 2
    assert pending.close.call_count == 1


@mark.skipif(system() != "Windows", reason="Only supported on Windows")
def test_sapphire_33(client, tmp_path):
    """test serving from path using Windows short file name"""
    wwwroot = tmp_path / "long_path_name_that_can_be_truncated_on_windows"
    wwwroot.mkdir()
    with Sapphire(timeout=10) as serv:
        assert serv.timeout == 10
        test = _create_test("test_case.html", wwwroot)
        client.launch("127.0.0.1", serv.port, [test])
        assert serv.serve_path(tmp_path / "LONG_P~1")[0] == Served.ALL
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org


def test_main_01(mocker, tmp_path):
    """test Sapphire.main()"""
    args = mocker.Mock(path=str(tmp_path), port=4536, remote=False, timeout=None)
    fake_srv = mocker.patch("sapphire.core.Sapphire.serve_path", autospec=True)
    fake_srv.return_value = (Served.ALL, None)
    Sapphire.main(args)
    fake_srv.return_value = (Served.NONE, None)
    Sapphire.main(args)
    fake_srv.side_effect = KeyboardInterrupt
    Sapphire.main(args)
