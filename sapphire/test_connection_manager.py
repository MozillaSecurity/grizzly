"""
ConnectionManager unit tests
"""

# pylint: disable=protected-access

from itertools import count
from socket import socket

from pytest import mark, raises

from .connection_manager import ConnectionManager
from .job import Job
from .worker import Worker


@mark.parametrize("timeout", [10, 0])
def test_connection_manager_01(mocker, tmp_path, timeout):
    """test basic ConnectionManager"""
    (tmp_path / "testfile").write_bytes(b"test")
    job = Job(tmp_path, required_files=["testfile"])
    clnt_sock = mocker.Mock(spec_set=socket)
    clnt_sock.recv.return_value = b"GET /testfile HTTP/1.1"
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    mocker.patch("sapphire.worker.select", return_value=([serv_sock], None, None))
    assert not job.is_complete()
    with ConnectionManager(job, serv_sock) as mgr:
        assert mgr.serve(timeout)
    assert clnt_sock.close.call_count == 1
    assert job.is_complete()
    assert not job.accepting.is_set()
    assert job.exceptions.empty()


@mark.parametrize("worker_limit", [1, 2, 10])
def test_connection_manager_02(mocker, tmp_path, worker_limit):
    """test ConnectionManager multiple files and requests"""
    (tmp_path / "test1").touch()
    (tmp_path / "test2").touch()
    (tmp_path / "test3").touch()
    job = Job(tmp_path, required_files=["test1", "test2", "test3"])
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
    mocker.patch("sapphire.worker.select", return_value=([serv_sock], None, None))
    assert not job.is_complete()
    with ConnectionManager(job, serv_sock, limit=worker_limit) as mgr:
        assert mgr.serve(10)
    assert clnt_sock.close.call_count == 8
    assert job.is_complete()


def test_connection_manager_03(mocker, tmp_path):
    """test ConnectionManager re-raise worker exceptions"""
    (tmp_path / "file").touch()
    job = Job(tmp_path, required_files=["file"])
    clnt_sock = mocker.Mock(spec_set=socket)
    clnt_sock.recv.side_effect = Exception("worker exception")
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    mocker.patch("sapphire.worker.select", return_value=([serv_sock], None, None))
    with raises(Exception, match="worker exception"):
        with ConnectionManager(job, serv_sock) as mgr:
            mgr.serve(10)
    assert clnt_sock.close.call_count == 1
    assert job.is_complete()
    assert job.exceptions.empty()


def test_connection_manager_04(mocker, tmp_path):
    """test ConnectionManager.serve() with callback"""
    (tmp_path / "file").touch()
    job = Job(tmp_path, required_files=["file"])
    with ConnectionManager(job, mocker.Mock(spec_set=socket), poll=0.01) as mgr:
        # invalid callback
        with raises(TypeError, match="continue_cb must be callable"):
            mgr.serve(10, continue_cb="test")
        # job did not start
        assert not job.is_complete()
        # callback abort
        assert mgr.serve(10, continue_cb=lambda: False)
        assert job.is_complete()


def test_connection_manager_05(mocker, tmp_path):
    """test ConnectionManager.serve() with timeout"""
    mocker.patch("sapphire.connection_manager.time", autospec=True, side_effect=count())
    (tmp_path / "file").touch()
    clnt_sock = mocker.Mock(spec_set=socket)
    clnt_sock.recv.return_value = b""
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    mocker.patch("sapphire.worker.select", return_value=([serv_sock], None, None))
    job = Job(tmp_path, required_files=["file"])
    with ConnectionManager(job, serv_sock, poll=0.01) as mgr:
        assert not mgr.serve(10)
        assert job.is_complete()


def test_connection_manager_06(mocker, tmp_path):
    """test ConnectionManager.serve() worker fails to exit"""
    mocker.patch("sapphire.worker.Thread", autospec=True)
    mocker.patch("sapphire.connection_manager.time", autospec=True, side_effect=count())
    (tmp_path / "file").touch()
    clnt_sock = mocker.Mock(spec_set=socket)
    serv_sock = mocker.Mock(spec_set=socket)
    serv_sock.accept.return_value = (clnt_sock, None)
    mocker.patch("sapphire.worker.select", return_value=([serv_sock], None, None))
    job = Job(tmp_path, required_files=["file"])
    mocker.patch.object(job, "worker_complete")
    with ConnectionManager(job, serv_sock) as mgr:
        with raises(RuntimeError, match="Failed to close workers"):
            mgr.serve(10)
        assert job.is_complete()
    assert clnt_sock.close.call_count == 1


def test_connection_manager_07(mocker):
    """test ConnectionManager._join_workers()"""
    # no workers
    assert not ConnectionManager._join_workers([])
    # worker fails to join, without timeout
    fake_worker = mocker.Mock(spec_set=Worker)
    fake_worker.join.return_value = False
    assert ConnectionManager._join_workers([fake_worker], timeout=0)
    assert fake_worker.join.call_count == 1
    fake_worker.reset_mock()
    # worker fails to join, with timeout
    assert ConnectionManager._join_workers([fake_worker], timeout=1)
    assert fake_worker.join.call_count == 1
    fake_worker.reset_mock()
    # worker joins
    fake_worker.join.return_value = True
    assert not ConnectionManager._join_workers([fake_worker], timeout=0)
    assert fake_worker.join.call_count == 1
