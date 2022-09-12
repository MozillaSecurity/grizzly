# coding=utf-8
"""
Sapphire unit tests
"""
# pylint: disable=protected-access

import socket
import threading

import pytest

from .job import Job
from .worker import Worker, WorkerError


def test_worker_01(mocker):
    """test simple Worker in running state"""
    wthread = mocker.Mock(spec_set=threading.Thread)
    wthread.is_alive.return_value = True
    worker = Worker(mocker.Mock(spec_set=socket.socket), wthread)
    assert worker._conn is not None
    assert worker._thread is not None
    # it is assumed that launch() has already been called at this point
    assert not worker.done
    assert wthread.join.call_count == 0
    assert wthread.is_alive.call_count == 1
    worker.join(timeout=0)
    assert wthread.join.call_count == 1
    assert wthread.is_alive.call_count == 2
    assert worker._conn.close.call_count == 0
    wthread.is_alive.return_value = False
    worker.close()
    assert worker._conn.close.call_count == 1
    assert worker._thread is None
    assert worker.done


def test_worker_02(mocker):
    """test simple Worker fails to close"""
    worker = Worker(
        mocker.Mock(spec_set=socket.socket), mocker.Mock(spec_set=threading.Thread)
    )
    # it is assumed that launch() has already been called at this point
    worker._thread.is_alive.return_value = True
    with pytest.raises(WorkerError, match="Worker thread failed to join!"):
        worker.close()


def test_worker_03(mocker):
    """test Worker.launch() fail cases"""
    serv_con = mocker.Mock(spec_set=socket.socket)
    serv_job = mocker.Mock(spec_set=Job)
    fake_thread = mocker.patch("sapphire.worker.Thread", autospec=True)
    mocker.patch("sapphire.worker.sleep", autospec=True)

    serv_con.accept.side_effect = socket.timeout
    assert Worker.launch(serv_con, serv_job) is None

    serv_con.accept.side_effect = None
    conn = mocker.Mock(spec_set=socket.socket)
    serv_con.accept.return_value = (conn, None)
    fake_thread.side_effect = threading.ThreadError
    assert Worker.launch(serv_con, serv_job) is None
    assert conn.close.call_count == 1
    assert serv_job.accepting.clear.call_count == 0
    assert serv_job.accepting.set.call_count == 1


def test_worker_04(mocker, tmp_path):
    """test Worker.launch()"""
    (tmp_path / "testfile").touch()
    job = Job(tmp_path)
    clnt_sock = mocker.Mock(spec_set=socket.socket)
    clnt_sock.recv.return_value = b"GET /testfile HTTP/1.1"
    serv_sock = mocker.Mock(spec_set=socket.socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    worker = Worker.launch(serv_sock, job)
    assert worker is not None
    try:
        assert job.is_complete(wait=1)
    finally:
        worker.close()
    assert worker.done
    assert serv_sock.accept.call_count == 1
    assert clnt_sock.close.call_count == 2


def test_worker_05(mocker):
    """test Worker.handle_request() socket errors"""
    serv_con = mocker.Mock(spec_set=socket.socket)
    serv_con.recv.side_effect = socket.error
    serv_job = mocker.Mock(spec_set=Job)
    Worker.handle_request(serv_con, serv_job)
    assert serv_job.accepting.set.call_count == 1
    assert serv_con.sendall.call_count == 0
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
