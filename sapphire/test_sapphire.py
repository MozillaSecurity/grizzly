"""
Sapphire unit tests
"""

# pylint: disable=protected-access

import socket
from hashlib import sha1
from itertools import count, repeat
from os import urandom
from pathlib import Path
from platform import system
from random import choices, getrandbits
from threading import Lock
from urllib.parse import quote, urlsplit

from pytest import mark, raises

from .certificate_bundle import CertificateBundle
from .core import Sapphire, create_listening_socket
from .job import Served
from .server_map import ServerMap
from .worker import Worker


class _TestFile:
    def __init__(self, url, url_prefix=None):
        assert isinstance(url, str)
        self.code = None
        self.content_type = None
        self.custom_request = None
        self.file = f"{url_prefix}{url}" if url_prefix else url
        self.len_org = 0  # original file length
        self.len_srv = 0  # served file length
        self.lock = Lock()
        self.hash_org = None
        self.hash_srv = None
        self.requested = 0  # number of times file was requested
        url = urlsplit(self.file.replace("\\", "/"))
        self.url = (
            "?".join((quote(url.path), url.query)) if url.query else quote(url.path)
        )

    @classmethod
    def create(cls, fname, path, data=b"Test!", calc_hash=False, url_prefix=None):
        test = cls(fname, url_prefix=url_prefix)
        with (path / fname).open("w+b") as out_fp:
            out_fp.write(data)
            test.len_org = out_fp.tell()
            if calc_hash:
                out_fp.seek(0)
                test.hash_org = sha1(out_fp.read()).hexdigest()
        return test


@mark.parametrize("files", [1, 100])
def test_sapphire_01(client, tmp_path, files):
    """test serving files"""
    _TestFile.create("unrelated.bin", tmp_path)
    to_serve = [
        _TestFile.create(
            f"test_{i:04d}.html", tmp_path, data=urandom(5), calc_hash=True
        )
        for i in range(files)
    ]
    # all files are required
    required = [x.file for x in to_serve]
    with Sapphire(timeout=30) as serv:
        assert serv.timeout == 30
        assert serv.scheme == "http"
        client.launch("127.0.0.1", serv.port, to_serve)
        status, served = serv.serve_path(tmp_path, required_files=required)
    assert status == Served.ALL
    assert "unrelated.bin" not in served
    assert len(required) == len(served) == len(to_serve)
    assert client.wait(timeout=10)
    for t_file in to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org
        assert t_file.url in served


@mark.parametrize(
    "files, req_idx",
    [
        # multiple files (skip optional)
        (5, 0),
        # multiple files (serve optional)
        (5, 4),
    ],
)
def test_sapphire_02(client, tmp_path, files, req_idx):
    """test serving files"""
    _TestFile.create("unrelated.bin", tmp_path)
    to_serve = [
        _TestFile.create(
            f"test_{i:04d}.html", tmp_path, data=urandom(5), calc_hash=True
        )
        for i in range(files)
    ]
    required = to_serve[req_idx].file
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, to_serve, in_order=True)
        status, served = serv.serve_path(tmp_path, required_files=[required])
    assert status == Served.ALL
    assert "unrelated.bin" not in served
    assert required in served
    assert len(served) >= (req_idx + 1)
    assert client.wait(timeout=10)
    for t_file in to_serve:
        if t_file.file in served:
            assert t_file.code == 200
            assert t_file.len_srv == t_file.len_org


def test_sapphire_03(client, tmp_path):
    """test requesting invalid files (404 and 403)"""
    root_dir = tmp_path / "root"
    root_dir.mkdir()
    invalid = Path(__file__)
    to_serve = [
        # 0 - missing file
        _TestFile("does_not_exist.html"),
        # 1 - add invalid file
        _TestFile(str(invalid.resolve())),
        # 2 - add file in parent of root_dir
        _TestFile.create(
            "no_access.html", tmp_path, data=b"no_access", url_prefix="../"
        ),
        # 3 - add valid test
        _TestFile.create("test_case.html", root_dir),
    ]
    required = [to_serve[-1].file]
    assert (tmp_path / "no_access.html").is_file()
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, to_serve, in_order=True)
        status, served = serv.serve_path(root_dir, required_files=required)
    assert status == Served.ALL
    assert len(served) == 1
    assert client.wait(timeout=10)
    assert to_serve[0].code == 404
    assert invalid.name in to_serve[1].file
    assert to_serve[1].code == 404
    assert "no_access.html" in to_serve[2].file
    assert to_serve[2].code == 404
    assert to_serve[3].code == 200


def test_sapphire_04(tmp_path):
    """test timeout of the server"""
    with Sapphire(timeout=0.01) as serv:
        assert serv.timeout == 0.01
        to_serve = [_TestFile.create("test_case.html", tmp_path)]
        status, served = serv.serve_path(tmp_path, required_files=[to_serve[0].file])
    assert status == Served.TIMEOUT
    assert not served


def test_sapphire_05(client, tmp_path):
    """test only serving some files (Served.REQUEST)"""
    cb_status = {"count": 0}

    def is_running():
        cb_status["count"] += 1
        return cb_status["count"] < 3  # return false after 2nd call

    to_serve = [_TestFile.create(f"test_{i}.html", tmp_path) for i in range(3)]
    with Sapphire() as serv:
        client.launch("127.0.0.1", serv.port, to_serve[1:])
        status, served = serv.serve_path(
            tmp_path, continue_cb=is_running, required_files=[x.file for x in to_serve]
        )
    assert status == Served.REQUEST
    assert len(served) < len(to_serve)


def test_sapphire_06(client, tmp_path):
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
        test["file"] = _TestFile.create(
            test["name"],
            tmp_path,
            data="".join(choices("ABCD1234", k=test["size"])).encode("ascii"),
            calc_hash=True,
        )
    required = [test["file"].file for test in tests]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [test["file"] for test in tests])
        status, served_list = serv.serve_path(tmp_path, required_files=required)
    assert status == Served.ALL
    assert len(served_list) == len(tests)
    assert client.wait(timeout=10)
    for test in tests:
        assert test["file"].code == 200
        assert test["file"].len_srv == test["size"]
        assert test["file"].hash_srv == test["file"].hash_org


def test_sapphire_07(client, tmp_path):
    """test serving a large (100MB) file"""
    t_file = _TestFile("test_case.html")
    data_hash = sha1()
    with (tmp_path / t_file.file).open("wb") as test_fp:
        # write 100MB of 'A'
        data = b"A" * (100 * 1024)  # 100KB of 'A'
        for _ in range(1024):
            test_fp.write(data)
            data_hash.update(data)
    t_file.hash_org = data_hash.hexdigest()
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [t_file])
        assert serv.serve_path(tmp_path, required_files=[t_file.file])[0] == Served.ALL
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == (100 * 1024 * 1024)
    assert t_file.hash_srv == t_file.hash_org


def test_sapphire_08(client, tmp_path):
    """test serving a binary file"""
    t_file = _TestFile.create("test.html", tmp_path, data=urandom(512), calc_hash=True)
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [t_file])
        assert serv.serve_path(tmp_path, required_files=[t_file.file])[0] == Served.ALL
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == t_file.len_org
    assert t_file.hash_srv == t_file.hash_org


def test_sapphire_09():
    """test requested port is used"""
    test_port = 0x1337
    with Sapphire(port=test_port, timeout=1) as serv:
        assert test_port == serv.port


def test_sapphire_10(client, tmp_path):
    """test serving multiple content types"""
    to_serve = [
        _TestFile.create("test_case.html", tmp_path),
        # create binary file without an extension
        _TestFile.create("test_case", tmp_path, data=urandom(5)),
    ]
    required = [x.file for x in to_serve]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, to_serve)
        assert serv.serve_path(tmp_path, required_files=required)[0] == Served.ALL
    assert client.wait(timeout=10)
    content_types = set()
    for test in to_serve:
        assert test.code == 200
        assert test.len_srv == test.len_org
        if test.file.endswith(".html"):
            content_type = "text/html"
        else:
            content_type = "application/octet-stream"
        content_types.add(content_type)
        assert test.content_type == content_type
    assert len(content_types) == 2


def test_sapphire_11(client, tmp_path):
    """test calling serve_path multiple times"""
    with Sapphire(timeout=10) as serv:
        for i in range(3):
            name = f"test_{i}.html"
            test = _TestFile.create(name, tmp_path)
            client.launch("127.0.0.1", serv.port, [test])
            assert serv.serve_path(tmp_path, required_files=[name])[0] == Served.ALL
            assert client.wait(timeout=10)
            client.close()
            assert test.code == 200
            assert test.len_srv == test.len_org
            (tmp_path / test.file).unlink()


def test_sapphire_12(client, tmp_path):
    """test non required mapped redirects"""
    smap = ServerMap()
    smap.set_redirect("test_url", "blah", required=False)
    test = _TestFile.create("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [test])
        assert (
            serv.serve_path(tmp_path, server_map=smap, required_files=[test.file])[0]
            == Served.ALL
        )
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
        ("€d’é-ñÿ", None),  # noqa: RUF001
    ],
)
def test_sapphire_13(client, tmp_path, path, query):
    """test required mapped redirects"""
    smap = ServerMap()
    with Sapphire(timeout=10) as serv:
        # target will be requested indirectly via the redirect
        target = _TestFile.create(path, tmp_path, data=b"Redirect DATA!")
        request_path = "redirect" if query is None else f"redirect?{query}"
        redirect = _TestFile(request_path)
        # point "redirect" at target
        smap.set_redirect("redirect", target.file, required=True)
        client.launch("127.0.0.1", serv.port, [redirect])
        status, served = serv.serve_path(
            tmp_path, server_map=smap, required_files=[target.file]
        )
    assert status == Served.ALL
    assert len(served) == 1
    assert client.wait(timeout=10)
    assert redirect.code == 200
    assert redirect.len_srv == target.len_org


def test_sapphire_14(client, tmp_path):
    """test include directories and permissions"""
    inc1_path = tmp_path / "inc1"
    inc2_path = tmp_path / "inc2"
    root_path = tmp_path / "root"
    inc1_path.mkdir()
    inc2_path.mkdir()
    root_path.mkdir()
    to_serve = []
    smap = ServerMap()
    with Sapphire(timeout=10) as serv:
        # add files to inc dirs
        inc1 = _TestFile.create("included_file1.html", inc1_path, data=b"blah....1")
        to_serve.append(inc1)
        # add a nested dir
        nest_path = inc1_path / "nested"
        nest_path.mkdir()
        # add file in a nested dir in inc1
        nest = _TestFile.create(
            "nested_file.html", nest_path, data=b"blah... .nested", url_prefix="nested/"
        )
        assert nest_path / "nested_file.html"
        to_serve.append(nest)
        # test 404 in nested dir in inc1
        nest_404 = _TestFile("nested/nested_file_404.html")
        to_serve.append(nest_404)
        # test path mounted somewhere other than /
        inc2 = _TestFile.create(
            "included_file2.html", inc2_path, data=b"blah....2", url_prefix="inc_test/"
        )
        to_serve.append(inc2)
        # test 404 in include dir
        inc404 = _TestFile("inc_test/included_file_404.html")
        assert not (nest_path / "included_file_404.html").is_file()
        to_serve.append(inc404)
        # test 404 with file outside of include path
        inc_ext = _TestFile.create(
            "no_access.html", tmp_path, data=b"no_access", url_prefix="inc_test/../"
        )
        assert (tmp_path / "no_access.html").is_file()
        to_serve.append(inc_ext)
        # test file (used to keep sever job alive)
        test = _TestFile.create("test_case.html", root_path)
        to_serve.append(test)
        # add include paths
        smap.set_include("/", inc1_path)  # mount at '/'
        smap.set_include("inc_test", inc2_path)  # mount at '/inc_test'
        client.launch("127.0.0.1", serv.port, to_serve, in_order=True)
        status, served = serv.serve_path(
            root_path, server_map=smap, required_files=[x.file for x in to_serve]
        )
    assert status == Served.ALL
    assert "test_case.html" in served
    assert "included_file1.html" in served
    assert served["included_file1.html"] == (inc1_path / "included_file1.html")
    assert "inc_test/included_file2.html" in served
    assert served["inc_test/included_file2.html"] == (inc2_path / "included_file2.html")
    assert "nested/nested_file.html" in served
    assert served["nested/nested_file.html"] == (nest_path / "nested_file.html")
    assert client.wait(timeout=10)
    assert inc1.code == 200
    assert inc2.code == 200
    assert nest.code == 200
    assert test.code == 200
    assert nest_404.code == 404
    assert inc404.code == 404
    assert inc_ext.code == 404


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
def test_sapphire_15(client, tmp_path, query, required):
    """test dynamic response"""
    _data = b"dynamic response -- TEST DATA!"
    # build request
    path = "dyn_test"
    request = path if query is None else f"{path}?{query}"

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
    test_dr.hash_org = sha1(_data).hexdigest()
    test = _TestFile.create("test_case.html", tmp_path)
    if required:
        req_files = []
        files = [test, test_dr]
    else:
        req_files = [test.file]
        files = [test_dr, test]
    # test request
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, files, in_order=True)
        assert (
            serv.serve_path(tmp_path, required_files=req_files, server_map=smap)[0]
            == Served.ALL
        )
    assert client.wait(timeout=10)
    if not required:
        assert test.code == 200
        assert test.len_srv == test.len_org
    assert test_dr.code == 200
    assert test_dr.len_srv == test_dr.len_org
    assert test_dr.hash_srv == test_dr.hash_org


def test_sapphire_16(client_factory, tmp_path):
    """test pending_files == 0 in worker thread"""
    client_defer = client_factory(rx_size=2)
    # server should shutdown while this file is being served
    test_defer = _TestFile.create("defer_test.html", tmp_path)
    test = _TestFile.create("test_case.html", tmp_path, data=b"112233")
    with Sapphire(timeout=10) as serv:
        # this test needs to wait just long enough to have the required file served
        # but not too long or the connection will be closed by the server
        client_defer.launch(
            "127.0.0.1", serv.port, [test_defer], delay=0.1, indicate_failure=True
        )
        client = client_factory(rx_size=2)
        client.launch("127.0.0.1", serv.port, [test], throttle=0.1)
        assert serv.serve_path(tmp_path, required_files=[test.file])[0] == Served.ALL
    assert client_defer.wait(timeout=10)
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test_defer.code == 0


def test_sapphire_17(client, tmp_path):
    """test handling an invalid request"""
    bad_test = _TestFile("bad.html")
    bad_test.custom_request = b"a bad request...0+%\xef\xb7\xba\r\n"
    test = _TestFile.create("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [bad_test, test], in_order=True)
        assert serv.serve_path(tmp_path, required_files=[test.file])[0] == Served.ALL
    assert client.wait(timeout=10)
    assert test.code == 200
    assert bad_test.code == 400


def test_sapphire_18(client, tmp_path):
    """test handling an empty request"""
    bad_test = _TestFile("bad.html")
    bad_test.custom_request = b""
    test = _TestFile.create("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch(
            "127.0.0.1",
            serv.port,
            [bad_test, test],
            indicate_failure=True,
            in_order=True,
        )
        assert serv.serve_path(tmp_path, required_files=[test.file])[0] == Served.ALL
    assert client.wait(timeout=10)
    assert test.code == 200
    assert bad_test.code == 0


def test_sapphire_19(client_factory, tmp_path):
    """test requesting multiple files via multiple connections"""
    to_serve = [
        _TestFile.create(f"test_{i:03d}.html", tmp_path, data=b"AAAA") for i in range(2)
    ]
    max_workers = 20
    with Sapphire(max_workers=max_workers, timeout=60) as serv:
        clients = []
        try:
            clients = [client_factory(rx_size=1) for _ in range(max_workers)]
            for client in clients:
                client.launch(
                    "127.0.0.1", serv.port, to_serve, in_order=True, throttle=0.05
                )
            required = [x.file for x in to_serve]
            status, served = serv.serve_path(tmp_path, required_files=required)
            # call serv.close() instead of waiting for the clients to timeout
            serv.close()
        finally:
            for client in clients:
                assert client.wait(timeout=10)
                client.close()
    assert status == Served.ALL
    assert len(to_serve) == len(served)
    for t_file in to_serve:
        assert t_file.code == 200
        assert t_file.len_srv == t_file.len_org


def test_sapphire_20(client_factory, tmp_path):
    """test all request types via multiple connections"""

    def _dyn_test_cb(_):
        return b"A" if getrandbits(1) else b"AA"

    smap = ServerMap()
    with Sapphire(max_workers=10, timeout=60) as serv:
        to_serve = []
        required = []
        for i in range(50):
            # add required files
            to_serve.append(
                _TestFile.create(
                    f"test_{i:03d}.html", tmp_path, data=b"A" * ((i % 2) + 1)
                )
            )
            required.append(to_serve[-1].file)
            # add a missing files
            to_serve.append(_TestFile(f"missing_{i:03d}.html"))
            # add optional files
            opt_path = tmp_path / f"opt_{i:03d}.html"
            opt_path.write_bytes(b"A" * ((i % 2) + 1))
            to_serve.append(_TestFile(opt_path.name))
            # add redirects
            redir_target = _TestFile.create(f"redir_{i:03d}.html", tmp_path, data=b"AA")
            to_serve.append(_TestFile(f"redir_{i:03d}"))
            smap.set_redirect(
                to_serve[-1].file, redir_target.file, required=getrandbits(1) > 0
            )
            # add dynamic responses
            to_serve.append(_TestFile(f"dynm_{i:03d}"))
            smap.set_dynamic_response(
                to_serve[-1].file, _dyn_test_cb, mime_type="text/plain"
            )
        clients = []
        for _ in range(100):  # number of clients to spawn
            clients.append(client_factory(rx_size=1))
            throttle = 0.05 if getrandbits(1) else 0
            clients[-1].launch("127.0.0.1", serv.port, to_serve, throttle=throttle)
        assert (
            serv.serve_path(tmp_path, server_map=smap, required_files=required)[0]
            == Served.ALL
        )


def test_sapphire_21(client, tmp_path):
    """test dynamic response with bad callbacks"""
    test_dr = _TestFile("dynm_test")
    smap = ServerMap()
    smap.set_dynamic_response("dynm_test", lambda _: None, mime_type="text/plain")
    test = _TestFile.create("test_case.html", tmp_path)
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, [test_dr, test], in_order=True)
        with raises(TypeError, match="dynamic request callback must return 'bytes'"):
            serv.serve_path(tmp_path, server_map=smap, required_files=[test.file])


def test_sapphire_22(client, tmp_path):
    """test serving to a slow client"""
    t_data = "".join(choices("ABCD1234", k=0x19000)).encode("ascii")  # 100KB
    t_file = _TestFile.create("test_case.html", tmp_path, data=t_data, calc_hash=True)
    # rx_size 10KB and throttle to 0.25 sec, which will be ~50KB/s
    # also taking 2.5 seconds to complete will hopefully find problems
    # with any assumptions that were made
    client.rx_size = 0x2800
    with Sapphire(timeout=60) as serv:
        client.launch("127.0.0.1", serv.port, [t_file], throttle=0.25)
        assert serv.serve_path(tmp_path, required_files=[t_file.file])[0] == Served.ALL
    assert client.wait(timeout=10)
    assert t_file.code == 200
    assert t_file.len_srv == t_file.len_org
    assert t_file.hash_srv == t_file.hash_org


def test_sapphire_23(client, tmp_path):
    """test timeout while requesting multiple files"""
    t_data = "".join(choices("ABCD1234", k=1024)).encode("ascii")
    to_serve = [
        _TestFile.create(f"test_{i:03d}.html", tmp_path, data=t_data) for i in range(50)
    ]
    required = [x.file for x in to_serve]
    client.rx_size = 512
    with Sapphire(timeout=1) as serv:  # minimum timeout is 1 second
        client.launch(
            "127.0.0.1", serv.port, to_serve, indicate_failure=True, throttle=0.1
        )
        status, served = serv.serve_path(tmp_path, required_files=required)
    assert status == Served.TIMEOUT
    assert len(served) < len(to_serve)


def test_sapphire_24(client_factory, tmp_path):
    """test Sapphire.serve_path() with forever=True"""
    with Sapphire(timeout=10) as serv:
        test = _TestFile.create("test_case.html", tmp_path)
        clients = [client_factory() for _ in range(3)]
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
        "€d’é-ñÿ",  # noqa: RUF001
    ],
)
def test_sapphire_25(client, tmp_path, file_name):
    """test interesting file names"""
    to_serve = [_TestFile.create(file_name, tmp_path)]
    required = [x.file for x in to_serve]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, to_serve)
        assert serv.serve_path(tmp_path, required_files=required)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert all(t_file.code == 200 for t_file in to_serve)


def test_sapphire_26(client, tmp_path):
    """test interesting path string"""
    path = "".join(chr(i) for i in range(256))
    to_serve = [
        # should not trigger crash
        _TestFile(path),
        # used to keep server running
        _TestFile.create("a.html", tmp_path),
    ]
    required = [to_serve[-1].file]
    with Sapphire(timeout=10) as serv:
        client.launch("127.0.0.1", serv.port, to_serve, in_order=True)
        assert serv.serve_path(tmp_path, required_files=required)[0] == Served.ALL
    assert client.wait(timeout=10)
    assert all(t_file.code is not None for t_file in to_serve)


def test_sapphire_27(mocker):
    """test Sapphire.clear_backlog()"""
    mocker.patch("sapphire.core.perf_counter", autospec=True, side_effect=count())
    mocker.patch("sapphire.core.sleep", autospec=True)
    # test clearing backlog
    pending = mocker.Mock(spec_set=socket.socket)
    pending.accept.side_effect = ((pending, None), OSError, BlockingIOError)
    pending.getblocking.return_value = False
    pending.getsockname.return_value = (None, 1337)
    mocker.patch("sapphire.core.socket", return_value=pending)
    with Sapphire(timeout=10) as serv:
        assert serv.clear_backlog()
        assert serv._socket.accept.call_count == 3
        assert pending.close.call_count == 1
    pending.reset_mock()
    # test hang
    pending.accept.side_effect = None
    pending.accept.return_value = (pending, None)
    with Sapphire(timeout=1) as serv:
        assert not serv.clear_backlog()


@mark.skipif(system() != "Windows", reason="Only supported on Windows")
def test_sapphire_28(client, tmp_path):
    """test serving from path using Windows short file name"""
    wwwroot = tmp_path / "long_path_name_that_can_be_truncated_on_windows"
    wwwroot.mkdir()
    with Sapphire(timeout=10) as serv:
        assert serv.timeout == 10
        test = _TestFile.create("test_case.html", wwwroot)
        client.launch("127.0.0.1", serv.port, [test])
        assert (
            serv.serve_path(tmp_path / "LONG_P~1", required_files=[test.file])[0]
            == Served.ALL
        )
    assert client.wait(timeout=10)
    assert test.code == 200
    assert test.len_srv == test.len_org


def test_sapphire_29():
    """test Sapphire with certificates"""
    certs = CertificateBundle.create()
    try:
        with Sapphire(timeout=10, certs=certs) as serv:
            assert serv.scheme == "https"
    finally:
        certs.cleanup()


@mark.parametrize(
    "bind,",
    [
        # success
        (None,),
        # failure and success on retry
        (PermissionError("foo", 10013), None),
    ],
)
def test_create_listening_socket_01(mocker, bind):
    """test create_listening_socket()"""
    fake_sleep = mocker.patch("sapphire.core.sleep", autospec=True)
    fake_sock = mocker.patch("sapphire.core.socket", autospec=True)
    fake_sock.return_value.bind.side_effect = bind
    bind_calls = len(bind)
    assert create_listening_socket()
    assert fake_sock.return_value.close.call_count == bind_calls - 1
    assert fake_sock.return_value.setsockopt.call_count == bind_calls
    assert fake_sock.return_value.bind.call_count == bind_calls
    assert fake_sock.return_value.listen.call_count == 1
    assert fake_sleep.call_count == bind_calls - 1


@mark.parametrize(
    "bind, attempts, raised",
    [
        # failure to bind (no retry)
        ((OSError("foo"),), 1, OSError),
        # failure and fail on retry
        (repeat(PermissionError("foo", 10013), 2), 2, PermissionError),
    ],
)
def test_create_listening_socket_02(mocker, bind, attempts, raised):
    """test create_listening_socket() - bind/listen failure"""
    mocker.patch("sapphire.core.sleep", autospec=True)
    fake_sock = mocker.patch("sapphire.core.socket", autospec=True)
    fake_sock.return_value.bind.side_effect = bind
    with raises(raised, match="foo"):
        create_listening_socket(attempts=attempts)
    assert fake_sock.return_value.close.call_count == attempts


def test_create_listening_socket_03(mocker):
    """test create_listening_socket() - fail to find port"""
    fake_sock = mocker.patch("sapphire.core.socket", autospec=True)
    # specify blocked port
    with raises(ValueError, match="Cannot bind to blocked ports"):
        create_listening_socket(port=6000, attempts=1)
    # specify reserved port
    with raises(ValueError, match="Cannot bind to blocked ports"):
        create_listening_socket(port=123, attempts=1)
    # always choose a blocked port
    fake_sock.return_value.getsockname.return_value = (None, 6665)
    with raises(RuntimeError, match="Could not find available port"):
        create_listening_socket(attempts=1)
    assert fake_sock.return_value.listen.call_count == 1
    assert fake_sock.return_value.close.call_count == 1


def test_main_01(mocker, tmp_path):
    """test Sapphire.main()"""
    args = mocker.Mock(path=tmp_path, port=4536, remote=False, timeout=0)
    fake_srv = mocker.patch("sapphire.core.Sapphire.serve_path", autospec=True)
    fake_srv.return_value = (Served.ALL, None)
    Sapphire.main(args)
    fake_srv.return_value = (Served.NONE, None)
    Sapphire.main(args)
    fake_srv.side_effect = KeyboardInterrupt
    Sapphire.main(args)
