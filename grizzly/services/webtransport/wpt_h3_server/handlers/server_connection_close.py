# pylint: skip-file
from ..webtransport_h3_server import WebTransportSession


def session_established(session: WebTransportSession) -> None:
    session.create_bidirectional_stream()


def stream_data_received(
    session: WebTransportSession,
    stream_id: int,
    data: bytes,
    stream_ended: bool,
) -> None:
    session._http._quic.close()
