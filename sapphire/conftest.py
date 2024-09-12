"""
Sapphire unit test fixtures
"""

import socket
from hashlib import sha1
from http.client import BadStatusLine
from logging import getLogger
from random import shuffle
from re import match
from sys import exc_info
from threading import Event, Thread
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pytest

LOG = getLogger(__name__)


@pytest.fixture
def client_factory():
    """
    factory fixture to create test clients to make http requests against sapphire
    """
    clients = []

    class _SimpleClient:
        # pylint: disable=missing-docstring

        def __init__(self, rx_size=0x10000):
            self.thread = None
            self.rx_size = rx_size
            # use this event to add delays instead of sleep
            # this will help avoid shutdown hangs when there are test failures
            self._closed = Event()
            self._closed.set()
            self._idle = Event()
            self._idle.set()

        def close(self):
            self._closed.set()
            if self.thread is not None:
                self.thread.join()
                self.thread = None
            self._idle.set()

        def launch(
            self,
            addr,
            port,
            files_to_serve,
            delay=0,
            in_order=False,
            indicate_failure=False,
            skip_served=True,
            throttle=0,
        ):
            assert self._closed.is_set()
            assert self._idle.is_set()
            assert self.thread is None
            self._closed.clear()
            self._idle.clear()
            self.thread = Thread(
                target=self._handle_request,
                args=(addr, port, files_to_serve),
                kwargs={
                    "delay": delay,
                    "in_order": in_order,
                    "indicate_failure": indicate_failure,
                    "skip_served": skip_served,
                    "throttle": throttle,
                },
            )
            self.thread.start()

        def _handle_request(
            self,
            addr,
            port,
            files_to_request,
            delay=0,
            in_order=False,
            indicate_failure=False,
            skip_served=True,
            throttle=0,
        ):
            assert isinstance(files_to_request, list)
            if delay:
                self._closed.wait(delay)
            indexes = list(range(len(files_to_request)))
            if not in_order:
                # request files in random order
                shuffle(indexes)
            for index in indexes:
                t_file = files_to_request[index]
                with t_file.lock:
                    # check if the file has been served
                    if skip_served and t_file.code is not None:
                        continue
                    # if t_file.hash_org is set to anything but None the test client
                    # will calculate the hash
                    data_hash = sha1() if t_file.hash_org is not None else None
                try:
                    if t_file.custom_request is None:
                        with urlopen(
                            f"http://{addr}:{port}/{t_file.url}", timeout=10
                        ) as cli:
                            data_length = 0
                            resp_code = cli.getcode()
                            content_type = cli.info().get("Content-Type")
                            if resp_code == 200:
                                while not self._closed.is_set():
                                    data = cli.read(self.rx_size)
                                    data_length += len(data)
                                    if data_hash is not None:
                                        data_hash.update(data)
                                    if len(data) < self.rx_size:
                                        break
                                    if throttle > 0:
                                        # try to simulate a slow connection
                                        # this might not be very effective with
                                        # a larger receive buffer size and sendall()
                                        # used on the other side of the connection
                                        self._closed.wait(throttle)
                                if data_hash is not None:
                                    data_hash = data_hash.hexdigest()
                    # custom request
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        try:
                            sock.connect((addr, port))
                            # safety, so test doesn't hang on failure
                            sock.settimeout(10)
                            sock.sendall(t_file.custom_request)
                            data = (
                                sock.recv(self.rx_size)
                                if t_file.custom_request
                                else b""
                            )
                        finally:
                            sock.close()
                        content_type = None
                        data_length = len(data)
                        try:
                            resp_code = int(
                                match(
                                    r"HTTP/1\.\d\s(?P<code>\d+)\s", data.decode("ascii")
                                ).group("code")
                            )
                        except AttributeError:
                            # set code to zero to help testing
                            resp_code = 0 if indicate_failure else None

                    # update test info
                    with t_file.lock:
                        if skip_served and t_file.code is not None:
                            # test has already be updated
                            continue
                        t_file.requested += 1
                        t_file.code = resp_code
                        if resp_code == 200:
                            t_file.content_type = content_type
                            t_file.len_srv = data_length
                            t_file.hash_srv = data_hash

                except HTTPError as http_err:
                    with t_file.lock:
                        t_file.requested += 1
                        if not skip_served or t_file.code is None:
                            t_file.code = http_err.code
                except (BadStatusLine, OSError, URLError):
                    exc_type, exc_obj, exc_tb = exc_info()
                    # set code to zero to help testing
                    with t_file.lock:
                        LOG.debug(
                            "%s - %s - line %r (processing: %s)",
                            exc_type.__name__,
                            exc_obj,
                            exc_tb.tb_lineno if exc_tb else None,
                            t_file.file,
                        )
                        if indicate_failure and (
                            not skip_served or t_file.code is None
                        ):
                            t_file.code = 0
                            break
            self._idle.set()

        def wait(self, timeout=None):
            """
            Used to help prevent checking test cases before client is complete.
            """
            return self._idle.wait(timeout)

    def _get_client(*args, **kwds):
        cli = _SimpleClient(*args, **kwds)
        clients.append(cli)
        return cli

    yield _get_client

    for cli in clients:
        cli.close()


@pytest.fixture
def client(client_factory):  # pylint: disable=redefined-outer-name
    """
    create a test client to make http requests against sapphire
    """
    return client_factory()
