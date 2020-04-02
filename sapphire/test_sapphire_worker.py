# coding=utf-8
"""
Sapphire unit tests
"""
# pylint: disable=protected-access

import socket
import threading

import pytest

from .sapphire_job import SapphireJob
from .sapphire_worker import SapphireWorker


def test_sapphire_worker_01(mocker):
    """test simple SapphireWorker()"""
    conn = mocker.Mock(spec=socket.socket)
    wthread = mocker.Mock(spec=threading.Thread)
    worker = SapphireWorker(conn, wthread)
    assert not worker.done
    assert wthread.join.call_count == 0
    assert wthread.is_alive.call_count == 1
    worker.close()
    assert conn.close.call_count == 1
    assert worker._thread is None
    assert wthread.join.call_count == 1
    assert worker.done

def test_sapphire_worker_02(mocker):
    """test SapphireWorker.launch() fail cases"""
    serv_con = mocker.Mock(spec=socket.socket)
    serv_job = mocker.Mock(spec=SapphireJob)
    fake_thread = mocker.patch("threading.Thread", autospec=True)

    serv_con.accept.side_effect = socket.timeout
    assert SapphireWorker.launch(serv_con, serv_job) is None

    serv_con.accept.side_effect = None
    conn = mocker.Mock(spec=socket.socket)
    serv_con.accept.return_value = (conn, None)
    fake_thread.side_effect = threading.ThreadError
    with pytest.raises(threading.ThreadError):
        SapphireWorker.launch(serv_con, serv_job)
    assert conn.close.call_count == 1
    assert serv_job.accepting.clear.call_count == 0
    assert serv_job.accepting.set.call_count == 1

def test_sapphire_worker_03(mocker):
    """test SapphireWorker.launch()"""
    serv_con = mocker.Mock(spec=socket.socket)
    conn = mocker.Mock(spec=socket.socket)
    serv_con.accept.return_value = (conn, None)
    serv_job = mocker.Mock(spec=SapphireJob)
    fake_thread = mocker.patch("threading.Thread", autospec=True)
    worker = SapphireWorker.launch(serv_con, serv_job)
    assert serv_job.accepting.clear.call_count == 1
    assert serv_job.accepting.set.call_count == 0
    assert fake_thread.return_value.start.call_count == 1
    assert not worker.done
    fake_thread.return_value.is_alive.return_value = False
    assert worker.done
    worker.close()
    assert conn.close.call_count == 1

def test_response_data_01():
    """test _200_header()"""
    output = SapphireWorker._200_header("10", "text/html")
    assert b"Content-Length: 10" in output
    assert b"Content-Type: text/html" in output

def test_response_data_02():
    """test _307_redirect()"""
    output = SapphireWorker._307_redirect("http://some.test.url")
    assert b"Location: http://some.test.url" in output

def test_response_data_03():
    """test _4xx_page() without close timeout"""
    output = SapphireWorker._4xx_page(400, "Bad Request")
    assert b"Content-Length: " in output
    assert b"HTTP/1.1 400 Bad Request" in output
    assert b"400!" in output

def test_response_data_04():
    """test _4xx_page() with close timeout"""
    output = SapphireWorker._4xx_page(404, "Not Found", close=10)
    assert b"Content-Length: " in output
    assert b"HTTP/1.1 404 Not Found" in output
    assert b"<script>window.setTimeout(window.close, 10000)</script>" in output
