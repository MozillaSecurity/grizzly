# pylint: skip-file
from typing import Dict, Tuple

from ..webtransport_h3_server import WebTransportSession

streams_dict: Dict[Tuple[int, int], int] = {}


def session_established(session: WebTransportSession) -> None:
    # When a WebTransport session is established, a bidirectional stream is
    # created by the server, which is used to echo back stream data from the
    # client.
    session.create_bidirectional_stream()


def stream_data_received(
    session: WebTransportSession,
    stream_id: int,
    data: bytes,
    stream_ended: bool,
) -> None:
    # If a stream is unidirectional, create a new unidirectional stream and echo
    # back the data on that stream.
    if session.stream_is_unidirectional(stream_id):
        # pylint: disable=consider-iterating-dictionary
        if (session.session_id, stream_id) not in streams_dict.keys():
            new_stream_id = session.create_unidirectional_stream()
            streams_dict[(session.session_id, stream_id)] = new_stream_id
        session.send_stream_data(
            streams_dict[(session.session_id, stream_id)], data, end_stream=stream_ended
        )
        if stream_ended:
            del streams_dict[(session.session_id, stream_id)]
        return
    # Otherwise (e.g. if the stream is bidirectional), echo back the data on the
    # same stream.
    session.send_stream_data(stream_id, data, end_stream=stream_ended)


def datagram_received(session: WebTransportSession, data: bytes) -> None:
    session.send_datagram(data)
