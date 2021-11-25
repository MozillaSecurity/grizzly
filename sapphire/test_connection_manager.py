# coding=utf-8
"""
ConnectionManager unit tests
"""
# pylint: disable=protected-access

from itertools import count
from socket import socket
from threading import ThreadError

from pytest import raises

from .connection_manager import ConnectionManager
from .job import Job


def test_connection_manager_01(mocker, tmp_path):
    """test basic ConnectionManager"""
    (tmp_path / "testfile").write_bytes(b"test")
    job = Job(tmp_path)
    clnt_sock = mocker.Mock(spec_set=socket)
    clnt_sock.recv.return_value = b"GET /testfile HTTP/1.1"
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    assert not job.is_complete()
    with ConnectionManager(job, serv_sock) as loadmgr:
        assert loadmgr.wait(1)
    assert clnt_sock.close.call_count == 1
    assert job.is_complete()
    assert not job.accepting.is_set()
    assert job.exceptions.empty()


def test_connection_manager_02(mocker):
    """test ConnectionManager.start() failure"""
    mocker.patch("sapphire.connection_manager.sleep", autospec=True)
    fake_thread = mocker.patch("sapphire.connection_manager.Thread", autospec=True)
    fake_thread.return_value.start.side_effect = ThreadError
    job = mocker.Mock(spec_set=Job)
    job.pending = True
    loadmgr = ConnectionManager(job, None)
    with raises(ThreadError):
        loadmgr.start()
    loadmgr.close()
    assert job.is_complete()


def test_connection_manager_03(mocker, tmp_path):
    """test ConnectionManager multiple files and requests"""
    (tmp_path / "test1").touch()
    (tmp_path / "test2").touch()
    (tmp_path / "test3").touch()
    job = Job(tmp_path)
    clnt_sock = mocker.Mock(spec_set=socket)
    clnt_sock.recv.side_effect = (
        b"GET /test1 HTTP/1.1",
        b"GET /missing HTTP/1.1",
        b"badrequest",
        b"",
        b"GET /test2 HTTP/1.1",
        b"GET /test1 HTTP/1.1",
        b"GET /test1 HTTP/1.1",
        b"GET /test3 HTTP/1.1",
    )
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    assert not job.is_complete()
    with ConnectionManager(job, serv_sock, max_workers=2) as loadmgr:
        assert loadmgr.wait(1)
    assert clnt_sock.close.call_count == 8
    assert job.is_complete()


def test_connection_manager_04(mocker, tmp_path):
    """test ConnectionManager.wait()"""
    (tmp_path / "test1").touch()
    job = Job(tmp_path)
    clnt_sock = mocker.Mock(spec_set=socket)
    clnt_sock.recv.return_value = b""
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    with ConnectionManager(job, serv_sock, max_workers=10) as loadmgr:
        # invalid callback
        with raises(TypeError, match="continue_cb must be callable"):
            loadmgr.wait(0, continue_cb="test")
        # callback abort
        assert loadmgr.wait(1, continue_cb=lambda: False, poll=0.01)
    # timeout
    job = Job(tmp_path)
    fake_time = mocker.patch("sapphire.connection_manager.time", autospec=True)
    fake_time.side_effect = count()
    with ConnectionManager(job, serv_sock, max_workers=10) as loadmgr:
        assert not loadmgr.wait(1, continue_cb=lambda: False, poll=0.01)


def test_connection_manager_05(mocker, tmp_path):
    """test ConnectionManager re-raise worker exceptions"""
    (tmp_path / "test1").touch()
    job = Job(tmp_path)
    clnt_sock = mocker.Mock(spec_set=socket)
    clnt_sock.recv.side_effect = Exception("worker exception")
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    with raises(Exception, match="worker exception"):
        with ConnectionManager(job, serv_sock) as loadmgr:
            loadmgr.wait(1)
    assert clnt_sock.close.call_count == 1
    assert job.is_complete()
    assert job.exceptions.empty()


def test_connection_manager_06(mocker, tmp_path):
    """test ConnectionManager re-raise launcher exceptions"""
    (tmp_path / "test1").touch()
    job = Job(tmp_path)
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.side_effect = Exception("launcher exception")
    with raises(Exception, match="launcher exception"):
        with ConnectionManager(job, serv_sock) as loadmgr:
            loadmgr.wait(1)
    assert job.is_complete()
    assert job.exceptions.empty()
