# coding=utf-8
"""
SapphireLoadManager unit tests
"""
# pylint: disable=protected-access

import socket
import threading

import pytest

from .sapphire_load_manager import SapphireLoadManager
from .sapphire_job import SapphireJob


def test_sapphire_load_manager_01(mocker, tmp_path):
    """test basic SapphireLoadManager"""
    (tmp_path / "testfile").write_bytes(b"test")
    job = SapphireJob(str(tmp_path))
    clnt_sock = mocker.Mock(spec=socket.socket)
    clnt_sock.recv.return_value = b"GET /testfile HTTP/1.1"
    serv_sock = mocker.Mock(spec=socket.socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    assert not job.is_complete()
    with SapphireLoadManager(job, serv_sock) as loadmgr:
        assert loadmgr.wait(1)
    assert clnt_sock.close.call_count == 1
    assert job.is_complete()
    assert not job.accepting.is_set()
    assert job.exceptions.empty()

def test_sapphire_load_manager_02(mocker):
    """test SapphireLoadManager.start() failure"""
    mocker.patch("sapphire.sapphire_load_manager.time.sleep", autospec=True)
    fake_thread = mocker.patch("sapphire.sapphire_load_manager.threading.Thread", autospec=True)
    fake_thread.return_value.start.side_effect = threading.ThreadError
    job = mocker.Mock(spec=SapphireJob)
    job.pending = True
    loadmgr = SapphireLoadManager(job, None)
    with pytest.raises(threading.ThreadError):
        loadmgr.start()
    loadmgr.close()
    assert job.is_complete()

def test_sapphire_load_manager_03(mocker, tmp_path):
    """test SapphireLoadManager multiple files and requests"""
    (tmp_path / "test1").touch()
    (tmp_path / "test2").touch()
    (tmp_path / "test3").touch()
    job = SapphireJob(str(tmp_path))
    clnt_sock = mocker.Mock(spec=socket.socket)
    clnt_sock.recv.side_effect = (
        b"GET /test1 HTTP/1.1",
        b"GET /missing HTTP/1.1",
        b"badrequest",
        b"",
        b"GET /test2 HTTP/1.1",
        b"GET /test1 HTTP/1.1",
        b"GET /test1 HTTP/1.1",
        b"GET /test3 HTTP/1.1")
    serv_sock = mocker.Mock(spec=socket.socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    assert not job.is_complete()
    with SapphireLoadManager(job, serv_sock, max_workers=2) as loadmgr:
        assert loadmgr.wait(1)
    assert clnt_sock.close.call_count == 8
    assert job.is_complete()

def test_sapphire_load_manager_04(mocker, tmp_path):
    """test SapphireLoadManager.wait()"""
    (tmp_path / "test1").touch()
    job = SapphireJob(str(tmp_path))
    clnt_sock = mocker.Mock(spec=socket.socket)
    clnt_sock.recv.return_value = b""
    serv_sock = mocker.Mock(spec=socket.socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    with SapphireLoadManager(job, serv_sock, max_workers=10) as loadmgr:
        # invalid callback
        with pytest.raises(TypeError, match="continue_cb must be callable"):
            loadmgr.wait(0, continue_cb="test")
        # callback abort
        assert loadmgr.wait(1, continue_cb=lambda: False, poll=0.01)
    # timeout
    job = SapphireJob(str(tmp_path))
    fake_time = mocker.patch("sapphire.sapphire_load_manager.time", autospec=True)
    fake_time.time.side_effect = (1, 2, 3)
    with SapphireLoadManager(job, serv_sock, max_workers=10) as loadmgr:
        assert not loadmgr.wait(1, continue_cb=lambda: False, poll=0.01)

def test_sapphire_load_manager_05(mocker, tmp_path):
    """test SapphireLoadManager re-raise worker exceptions"""
    (tmp_path / "test1").touch()
    job = SapphireJob(str(tmp_path))
    clnt_sock = mocker.Mock(spec=socket.socket)
    clnt_sock.recv.side_effect = Exception("worker exception")
    serv_sock = mocker.Mock(spec=socket.socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    with pytest.raises(Exception, match="worker exception"):
        with SapphireLoadManager(job, serv_sock) as loadmgr:
            loadmgr.wait(1)
    assert clnt_sock.close.call_count == 1
    assert job.is_complete()
    assert job.exceptions.empty()

def test_sapphire_load_manager_06(mocker, tmp_path):
    """test SapphireLoadManager re-raise launcher exceptions"""
    (tmp_path / "test1").touch()
    job = SapphireJob(str(tmp_path))
    serv_sock = mocker.Mock(spec=socket.socket)
    serv_sock.accept.side_effect = Exception("launcher exception")
    with pytest.raises(Exception, match="launcher exception"):
        with SapphireLoadManager(job, serv_sock) as loadmgr:
            loadmgr.wait(1)
    assert job.is_complete()
    assert job.exceptions.empty()
