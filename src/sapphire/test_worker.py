"""
Sapphire unit tests
"""

# pylint: disable=protected-access

import socket
from random import randint
from threading import Thread, ThreadError

from pytest import mark, raises

from .job import Job
from .worker import Request, Worker


def test_worker_01(mocker):
    """test a Worker"""
    wthread = mocker.Mock(spec_set=Thread)
    wsocket = mocker.Mock(spec_set=socket.socket)
    worker = Worker(wsocket, wthread)
    # it is assumed that launch() has already been called at this point
    assert worker.is_alive()
    assert wthread.is_alive.call_count == 1
    assert not worker.join(timeout=0)
    assert wthread.join.call_count == 1
    # simulator closing a worker that is alive
    # have shutdown raise OSError for coverage
    wsocket.shutdown.side_effect = (OSError("test"),)
    worker.close()
    assert wsocket.shutdown.call_count == 1
    assert wsocket.close.call_count == 1
    # at this point the worker should be complete
    wthread.is_alive.return_value = False
    assert not worker.is_alive()
    assert worker.join(timeout=0)
    # calling a close when the worker is not alive should do nothing
    worker.close()
    assert wsocket.shutdown.call_count == 1
    assert wsocket.close.call_count == 1


@mark.parametrize(
    "exc",
    [
        socket.timeout("test"),
        OSError("test"),
        BlockingIOError("test"),
    ],
)
def test_worker_02(mocker, exc):
    """test Worker.launch() socket exception cases"""
    mocker.patch("sapphire.worker.Thread", autospec=True)
    serv_con = mocker.Mock(spec_set=socket.socket)
    serv_job = mocker.Mock(spec_set=Job)
    serv_con.accept.side_effect = exc
    mocker.patch("sapphire.worker.select", return_value=([serv_con], None, None))
    assert Worker.launch(serv_con, serv_job) is None
    assert serv_job.accepting.clear.call_count == 0
    assert serv_job.accepting.set.call_count == 0


def test_worker_03(mocker):
    """test Worker.launch() thread exception case"""
    mocker.patch("sapphire.worker.sleep", autospec=True)
    mocker.patch("sapphire.worker.Thread", side_effect=ThreadError("test"))
    serv_con = mocker.Mock(spec_set=socket.socket)
    serv_job = mocker.Mock(spec_set=Job)
    conn = mocker.Mock(spec_set=socket.socket)
    serv_con.accept.return_value = (conn, None)
    mocker.patch("sapphire.worker.select", return_value=([serv_con], None, None))
    assert Worker.launch(serv_con, serv_job) is None
    assert conn.close.call_count == 1
    assert serv_job.accepting.clear.call_count == 0
    assert serv_job.accepting.set.call_count == 1


@mark.parametrize(
    "url",
    [
        "/testfile",
        "/./testfile",
        "http://localhost/testfile",
        "http://127.0.0.1/testfile",
        "http://sub.host:1234/testfile",
    ],
)
def test_worker_04(mocker, tmp_path, url):
    """test Worker.launch()"""
    (tmp_path / "testfile").touch()
    job = Job(tmp_path, required_files=["testfile"])
    clnt_sock = mocker.Mock(spec_set=socket.socket)
    clnt_sock.recv.return_value = f"GET {url} HTTP/1.1".encode()
    serv_sock = mocker.Mock(spec_set=socket.socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    mocker.patch("sapphire.worker.select", return_value=([serv_sock], None, None))
    worker = Worker.launch(serv_sock, job)
    assert worker is not None
    try:
        assert job.is_complete(wait=1)
    finally:
        worker.close()
        if not job.exceptions.empty():
            raise job.exceptions.get()[1]
    assert worker.join(timeout=10)
    assert clnt_sock.sendall.called
    assert serv_sock.accept.call_count == 1
    assert clnt_sock.close.call_count == 1


@mark.parametrize(
    "req, response",
    [
        (b"a", b"400 Bad Request"),
        (b"BAD / HTTP/1.1", b"405 Method Not Allowed"),
    ],
)
def test_worker_05(mocker, tmp_path, req, response):
    """test Worker.launch() with invalid/unsupported requests"""
    (tmp_path / "testfile").touch()
    job = Job(tmp_path, required_files=["testfile"])
    clnt_sock = mocker.Mock(spec_set=socket.socket)
    clnt_sock.recv.return_value = req
    serv_sock = mocker.Mock(spec_set=socket.socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    mocker.patch("sapphire.worker.select", return_value=([serv_sock], None, None))
    worker = Worker.launch(serv_sock, job)
    assert worker is not None
    assert worker.join(timeout=10)
    worker.close()
    if not job.exceptions.empty():
        raise job.exceptions.get()[1]
    assert serv_sock.accept.call_count == 1
    assert clnt_sock.close.call_count == 1
    assert clnt_sock.sendall.called
    assert response in clnt_sock.sendall.call_args[0][0]


def test_worker_06(mocker):
    """test Worker.handle_request() socket errors"""
    serv_con = mocker.Mock(spec_set=socket.socket)
    serv_con.recv.side_effect = OSError
    serv_job = mocker.Mock(spec_set=Job)
    Worker.handle_request(serv_con, serv_job)
    assert serv_job.accepting.set.call_count == 1
    assert serv_con.sendall.call_count == 0
    assert serv_con.shutdown.call_count == 0
    assert serv_con.close.call_count == 1


def test_response_data_01():
    """test _200_header()"""
    output = Worker._200_header(10, "text/html")
    assert b"Content-Length: 10" in output
    assert b"Content-Type: text/html" in output


def test_response_data_02():
    """test _307_redirect()"""
    output = Worker._307_redirect("http://some.test.url")
    assert b"Location: http://some.test.url" in output


def test_response_data_03():
    """test _4xx_page() without close timeout"""
    output = Worker._4xx_page(400, "Bad Request")
    assert b"Content-Length: " in output
    assert b"HTTP/1.1 400 Bad Request" in output
    assert b"400!" in output


def test_response_data_04():
    """test _4xx_page() with close timeout"""
    output = Worker._4xx_page(404, "Not Found", close=10)
    assert b"Content-Length: " in output
    assert b"HTTP/1.1 404 Not Found" in output
    assert b"window.onload = () => { window.setTimeout(window.close, 10000) }" in output


@mark.parametrize(
    "req, method, scheme, path",
    [
        (b"GET / HTTP/1.1\r\n", "GET", "", "/"),
        (b"GET /foo HTTP/1.1\r\n", "GET", "", "/foo"),
        (b"GET /foo/bar HTTP/1.1\r\n", "GET", "", "/foo/bar"),
        (b"GET http://foo/ HTTP/1.1\r\n", "GET", "http", "/"),
        (b"GET http://foo/bar HTTP/1.1\r\n", "GET", "http", "/bar"),
    ],
)
def test_response_01(req, method, scheme, path):
    """test Request.parse() success"""
    request = Request.parse(req)
    assert request.method == method
    assert request.url.path == path
    assert request.url.scheme == scheme


@mark.parametrize(
    "req",
    [
        b"a",
        # Invalid IPv6 URL
        b"GET http://[test/ HTTP/1.1",
        b"GET  HTTP/1.1",
        b"GET a a a a a HTTP/1.1",
        # Invalid characters under NFKC normalization
        b"GET http://%E2%84%80/ HTTP/1.1",
    ],
)
def test_response_02(req):
    """test Request.parse() failures"""
    assert Request.parse(req) is None


def test_response_03(mocker):
    """test Request.parse() fail to parse"""
    mocker.patch("sapphire.worker.urlparse", side_effect=ValueError("foo"))
    with raises(ValueError, match="foo"):
        Request.parse(b"GET http://foo HTTP/1.1")


def test_response_04():
    """test Request.parse() by passing random urls"""
    for _ in range(1000):
        # create random 'netloc', for example '%1A%EF%09'
        chars = "".join([f"%{randint(0, 255):02X}" for _ in range(randint(1, 8))])
        Request.parse(f"GET http://{chars}/ HTTP/1.1".encode())
