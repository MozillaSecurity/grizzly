"""
A WebTransport over HTTP/3 server for testing.

The server interprets the underlying protocols (WebTransport, HTTP/3 and QUIC)
and passes events to a particular webtransport handler. From the standpoint of
test authors, a webtransport handler is a Python script which contains some
callback functions. See handler.py for available callbacks.
"""

# pylint: skip-file
# ruff: noqa
import asyncio
import logging
import ssl
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from aioquic.asyncio import QuicConnectionProtocol  # type: ignore[attr-defined]
from aioquic.asyncio.client import connect
from aioquic.buffer import Buffer  # type: ignore[attr-defined]
from aioquic.h3.connection import (
    H3_ALPN,
    FrameType,
    H3Connection,
    ProtocolError,
    Setting,
)
from aioquic.h3.events import (
    DatagramReceived,
    DataReceived,
    H3Event,
    HeadersReceived,
    WebTransportStreamDataReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import stream_is_unidirectional
from aioquic.quic.events import (
    ConnectionTerminated,
    ProtocolNegotiated,
    QuicEvent,
    StreamReset,
)
from aioquic.tls import SessionTicket

from .capsule import CapsuleType, H3Capsule, H3CapsuleDecoder

SERVER_NAME = "webtransport-h3-server"

LOG: logging.Logger = logging.getLogger(__name__)
DOC_ROOT: Path = Path(__file__).resolve().parent / "handlers"


class H3ConnectionWithDatagram04(H3Connection):
    """
    A H3Connection subclass, to make it work with the latest
    HTTP Datagram protocol.
    """

    H3_DATAGRAM_04 = 0xFFD277
    # https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-h3-websockets-00#section-5
    ENABLE_CONNECT_PROTOCOL = 0x08

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._supports_h3_datagram_04 = False

    def _validate_settings(self, settings: Dict[int, int]) -> None:
        H3_DATAGRAM_04 = H3ConnectionWithDatagram04.H3_DATAGRAM_04
        if H3_DATAGRAM_04 in settings and settings[H3_DATAGRAM_04] == 1:
            settings[Setting.H3_DATAGRAM] = 1
            self._supports_h3_datagram_04 = True
        return super()._validate_settings(settings)

    def _get_local_settings(self) -> Dict[int, int]:
        H3_DATAGRAM_04 = H3ConnectionWithDatagram04.H3_DATAGRAM_04
        settings = super()._get_local_settings()
        settings[H3_DATAGRAM_04] = 1
        settings[H3ConnectionWithDatagram04.ENABLE_CONNECT_PROTOCOL] = 1
        return settings

    @property
    def supports_h3_datagram_04(self) -> bool:
        """
        True if the client supports the latest HTTP Datagram protocol.
        """
        return self._supports_h3_datagram_04


class WebTransportH3Protocol(QuicConnectionProtocol):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._handler: Optional[Any] = None
        self._http: Optional[H3ConnectionWithDatagram04] = None
        self._session_stream_id: Optional[int] = None
        self._close_info: Optional[Tuple[int, bytes]] = None
        self._capsule_decoder_for_session_stream: H3CapsuleDecoder = H3CapsuleDecoder()
        self._allow_calling_session_closed = True
        self._allow_datagrams = False

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3ConnectionWithDatagram04(
                self._quic, enable_webtransport=True
            )
            if not self._http.supports_h3_datagram_04:
                self._allow_datagrams = True

        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self._h3_event_received(http_event)

        if isinstance(event, ConnectionTerminated):
            self._call_session_closed(close_info=None, abruptly=True)
        if isinstance(event, StreamReset):
            if self._handler:
                self._handler.stream_reset(event.stream_id, event.error_code)

    def _h3_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            # Convert from List[Tuple[bytes, bytes]] to Dict[bytes, bytes].
            # Only the last header will be kept when there are duplicate
            # headers.
            headers = {}
            for header, value in event.headers:
                headers[header] = value

            method = headers.get(b":method")
            protocol = headers.get(b":protocol")
            origin = headers.get(b"origin")
            # Accept any Origin but the client must send it.
            if method == b"CONNECT" and protocol == b"webtransport" and origin:
                self._session_stream_id = event.stream_id
                self._handshake_webtransport(event, headers)
            else:
                status_code = 404 if origin else 403
                self._send_error_response(event.stream_id, status_code)

        if (
            isinstance(event, DataReceived)
            and self._session_stream_id == event.stream_id
        ):
            if (
                self._http
                and not self._http.supports_h3_datagram_04
                and len(event.data) > 0
            ):
                raise ProtocolError("Unexpected data on the session stream")
            self._receive_data_on_session_stream(event.data, event.stream_ended)
        elif self._handler is not None:
            if isinstance(event, WebTransportStreamDataReceived):
                self._handler.stream_data_received(
                    stream_id=event.stream_id,
                    data=event.data,
                    stream_ended=event.stream_ended,
                )
            elif isinstance(event, DatagramReceived):
                if self._allow_datagrams:
                    self._handler.datagram_received(data=event.data)

    def _receive_data_on_session_stream(self, data: bytes, fin: bool) -> None:
        self._capsule_decoder_for_session_stream.append(data)
        if fin:
            self._capsule_decoder_for_session_stream.final()
        for capsule in self._capsule_decoder_for_session_stream:
            if capsule.type in {
                CapsuleType.DATAGRAM,
                CapsuleType.REGISTER_DATAGRAM_CONTEXT,
                CapsuleType.CLOSE_DATAGRAM_CONTEXT,
            }:
                raise ProtocolError(f"Unimplemented capsule type: {capsule.type}")
            if capsule.type in {
                CapsuleType.REGISTER_DATAGRAM_NO_CONTEXT,
                CapsuleType.CLOSE_WEBTRANSPORT_SESSION,
            }:
                # We'll handle this case below.
                pass
            else:
                # We should ignore unknown capsules.
                continue

            if self._close_info is not None:
                raise ProtocolError(
                    (
                        "Receiving a capsule with type = {} after receiving "
                        + "CLOSE_WEBTRANSPORT_SESSION"
                    ).format(capsule.type)
                )

            if capsule.type == CapsuleType.REGISTER_DATAGRAM_NO_CONTEXT:
                buffer = Buffer(data=capsule.data)
                format_type = buffer.pull_uint_var()
                # https://ietf-wg-webtrans.github.io/draft-ietf-webtrans-http3/draft-ietf-webtrans-http3.html#name-datagram-format-type
                WEBTRANPORT_FORMAT_TYPE = 0xFF7C00
                if format_type != WEBTRANPORT_FORMAT_TYPE:
                    raise ProtocolError(
                        f"Unexpected datagram format type: {format_type}"
                    )
                self._allow_datagrams = True
            elif capsule.type == CapsuleType.CLOSE_WEBTRANSPORT_SESSION:
                buffer = Buffer(data=capsule.data)
                code = buffer.pull_uint32()
                # 4 bytes for the uint32.
                reason = buffer.pull_bytes(len(capsule.data) - 4)
                # TODO(yutakahirano): Make sure `reason` is a UTF-8 text.
                self._close_info = (code, reason)
                if fin:
                    self._call_session_closed(self._close_info, abruptly=False)

    def _send_error_response(self, stream_id: int, status_code: int) -> None:
        assert self._http is not None
        headers = [
            (b":status", str(status_code).encode()),
            (b"server", SERVER_NAME.encode()),
        ]
        self._http.send_headers(stream_id=stream_id, headers=headers, end_stream=True)

    def _handshake_webtransport(
        self, event: HeadersReceived, request_headers: Dict[bytes, bytes]
    ) -> None:
        assert self._http is not None
        path = request_headers.get(b":path")
        if path is None:
            # `:path` must be provided.
            self._send_error_response(event.stream_id, 400)
            return

        # Create a handler using `:path`.
        try:
            self._handler = self._create_event_handler(
                session_id=event.stream_id, path=path, request_headers=event.headers
            )
        except OSError:
            self._send_error_response(event.stream_id, 404)
            return

        response_headers = [
            (b"server", SERVER_NAME.encode()),
            (b"sec-webtransport-http3-draft", b"draft02"),
        ]
        self._handler.connect_received(response_headers=response_headers)

        status_code = None
        for name, value in response_headers:
            if name == b":status":
                status_code = value
                response_headers.remove((b":status", status_code))
                response_headers.insert(0, (b":status", status_code))
                break
        if not status_code:
            response_headers.insert(0, (b":status", b"200"))
        self._http.send_headers(stream_id=event.stream_id, headers=response_headers)

        if status_code is None or status_code == b"200":
            self._handler.session_established()

    def _create_event_handler(
        self,
        session_id: int,
        path: bytes,
        request_headers: List[Tuple[bytes, bytes]],
    ) -> Any:
        parsed = urlparse(path.decode())
        handler = (DOC_ROOT / parsed.path.lstrip("/")).with_suffix(".py")
        callbacks = {"__file__": handler}
        exec(compile(handler.read_text(), path, "exec"), callbacks)
        session = WebTransportSession(self, session_id, request_headers)
        return WebTransportEventHandler(session, callbacks)

    def _call_session_closed(
        self, close_info: Optional[Tuple[int, bytes]], abruptly: bool
    ) -> None:
        allow_calling_session_closed = self._allow_calling_session_closed
        self._allow_calling_session_closed = False
        if self._handler and allow_calling_session_closed:
            self._handler.session_closed(close_info, abruptly)


class WebTransportSession:
    """
    A WebTransport session.
    """

    def __init__(
        self,
        protocol: WebTransportH3Protocol,
        session_id: int,
        request_headers: List[Tuple[bytes, bytes]],
    ) -> None:
        self.session_id = session_id
        self.request_headers = request_headers

        self._protocol: WebTransportH3Protocol = protocol
        self._http: H3Connection = protocol._http  # type: ignore

        self._dict_for_handlers: Dict[str, Any] = {}

    @property
    def dict_for_handlers(self) -> Dict[str, Any]:
        """A dictionary that handlers can attach arbitrary data."""
        return self._dict_for_handlers

    def stream_is_unidirectional(self, stream_id: int) -> bool:
        """Return True if the stream is unidirectional."""
        return stream_is_unidirectional(stream_id)

    def close(self, close_info: Optional[Tuple[int, bytes]]) -> None:
        """
        Close the session.

        :param close_info The close information to send.
        """
        self._protocol._allow_calling_session_closed = False
        assert self._protocol._session_stream_id is not None
        session_stream_id = self._protocol._session_stream_id
        if close_info is not None:
            code = close_info[0]
            reason = close_info[1]
            buffer = Buffer(capacity=len(reason) + 4)
            buffer.push_uint32(code)
            buffer.push_bytes(reason)
            capsule = H3Capsule(CapsuleType.CLOSE_WEBTRANSPORT_SESSION, buffer.data)
            self._http.send_data(session_stream_id, capsule.encode(), end_stream=False)

        self._http.send_data(session_stream_id, b"", end_stream=True)
        # TODO(yutakahirano): Reset all other streams.
        # TODO(yutakahirano): Reject future stream open requests
        # We need to wait for the stream data to arrive at the client, and then
        # we need to close the connection. At this moment we're relying on the
        # client's behavior.
        # TODO(yutakahirano): Implement the above.

    def create_unidirectional_stream(self) -> int:
        """
        Create a unidirectional WebTransport stream and return the stream ID.
        """
        return self._http.create_webtransport_stream(
            session_id=self.session_id, is_unidirectional=True
        )

    def create_bidirectional_stream(self) -> int:
        """
        Create a bidirectional WebTransport stream and return the stream ID.
        """
        stream_id = self._http.create_webtransport_stream(
            session_id=self.session_id, is_unidirectional=False
        )
        # TODO(bashi): Remove this workaround when aioquic supports receiving
        # data on server-initiated bidirectional streams.
        stream = self._http._get_or_create_stream(stream_id)
        assert stream.frame_type is None
        assert stream.session_id is None
        stream.frame_type = FrameType.WEBTRANSPORT_STREAM
        stream.session_id = self.session_id
        return stream_id

    def send_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> None:
        """
        Send data on the specific stream.

        :param stream_id: The stream ID on which to send the data.
        :param data: The data to send.
        :param end_stream: If set to True, the stream will be closed.
        """
        self._http._quic.send_stream_data(
            stream_id=stream_id, data=data, end_stream=end_stream
        )

    def send_datagram(self, data: bytes) -> None:
        """
        Send data using a datagram frame.

        :param data: The data to send.
        """
        if not self._protocol._allow_datagrams:
            LOG.warning("Sending a datagram while that's now allowed - discarding it")
            return
        flow_id = self.session_id
        if self._http.supports_h3_datagram_04:  # type: ignore[attr-defined]
            # The REGISTER_DATAGRAM_NO_CONTEXT capsule was on the session
            # stream, so we must have the ID of the stream.
            assert self._protocol._session_stream_id is not None
            # TODO(yutakahirano): Make sure if this is the correct logic.
            # Chrome always use 0 for the initial stream and the initial flow
            # ID, we cannot check the correctness with it.
            flow_id = self._protocol._session_stream_id // 4
        self._http.send_datagram(flow_id=flow_id, data=data)

    def stop_stream(self, stream_id: int, code: int) -> None:
        """
        Send a STOP_SENDING frame to the given stream.
        :param code: the reason of the error.
        """
        self._http._quic.stop_stream(stream_id, code)

    def reset_stream(self, stream_id: int, code: int) -> None:
        """
        Send a RESET_STREAM frame to the given stream.
        :param code: the reason of the error.
        """
        self._http._quic.reset_stream(stream_id, code)


class WebTransportEventHandler:
    def __init__(self, session: WebTransportSession, callbacks: Dict[str, Any]) -> None:
        self._session = session
        self._callbacks = callbacks

    def _run_callback(self, callback_name: str, *args: Any, **kwargs: Any) -> None:
        if callback_name not in self._callbacks:
            return
        try:
            self._callbacks[callback_name](*args, **kwargs)
        except Exception as e:
            LOG.warning(str(e))
            traceback.print_exc()

    def connect_received(self, response_headers: List[Tuple[bytes, bytes]]) -> None:
        self._run_callback(
            "connect_received",
            self._session.request_headers,
            response_headers,
        )

    def session_established(self) -> None:
        self._run_callback("session_established", self._session)

    def stream_data_received(
        self, stream_id: int, data: bytes, stream_ended: bool
    ) -> None:
        self._run_callback(
            "stream_data_received", self._session, stream_id, data, stream_ended
        )

    def datagram_received(self, data: bytes) -> None:
        self._run_callback("datagram_received", self._session, data)

    def session_closed(
        self,
        close_info: Optional[Tuple[int, bytes]],
        abruptly: bool,
    ) -> None:
        self._run_callback(
            "session_closed", self._session, close_info, abruptly=abruptly
        )

    def stream_reset(self, stream_id: int, error_code: int) -> None:
        self._run_callback("stream_reset", self._session, stream_id, error_code)


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


def server_is_running(host: str, port: int, timeout: float) -> bool:
    """
    Check the WebTransport over HTTP/3 server is running at the given `host` and
    `port`.
    """
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_connect_server_with_timeout(host, port, timeout))


async def _connect_server_with_timeout(host: str, port: int, timeout: float) -> bool:
    try:
        await asyncio.wait_for(_connect_to_server(host, port), timeout=timeout)
    except asyncio.TimeoutError:
        LOG.warning("Failed to connect WebTransport over HTTP/3 server")
        return False
    return True


async def _connect_to_server(host: str, port: int) -> None:
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        verify_mode=ssl.CERT_NONE,
    )

    async with connect(host, port, configuration=configuration) as protocol:
        await protocol.ping()
