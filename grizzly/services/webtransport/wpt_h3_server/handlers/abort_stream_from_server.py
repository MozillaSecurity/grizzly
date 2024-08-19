# pylint: skip-file
from ..webtransport_h3_server import WebTransportSession


def session_established(session: WebTransportSession) -> None:
    session.dict_for_handlers["code"] = 400


def stream_data_received(
    session: WebTransportSession,
    stream_id: int,
    data: bytes,
    stream_ended: bool,
) -> None:
    code: int = session.dict_for_handlers["code"]
    if session.stream_is_unidirectional(stream_id):
        session.stop_stream(stream_id, code)
    else:
        session.stop_stream(stream_id, code)
        session.reset_stream(stream_id, code)
