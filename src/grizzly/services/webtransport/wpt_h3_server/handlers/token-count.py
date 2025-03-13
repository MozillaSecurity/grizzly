"""
This is a WebTransport handler that reads tokens sent from client streams and
tracks how many times the token was sent. When a client sends a token, the
server will send the total token count back to the client.
"""

streams_dict = {}


def session_established(session):
    # When a WebTransport session is established, a bidirectional stream is
    # created by the server, which is used to echo back stream data from the
    # client.
    session.create_bidirectional_stream()


def stream_data_received(session, stream_id: int, data: bytes, stream_ended: bool):
    count = 0
    try:
        value = session.stash.take(data)
        if isinstance(value, int):
            count = value
    except Exception:
        # The stash will raise if data is empty
        pass

    count += 1

    try:
        session.stash.put(key=data, value=count)
    except Exception:
        # The stash will raise if the key already exists
        pass

    # If a stream is unidirectional, create a new unidirectional stream and echo
    # the token count on that stream.
    if session.stream_is_unidirectional(stream_id):
        if (session.session_id, stream_id) not in streams_dict.keys():
            new_stream_id = session.create_unidirectional_stream()
            streams_dict[(session.session_id, stream_id)] = new_stream_id
        session.send_stream_data(
            streams_dict[(session.session_id, stream_id)], str(count).encode()
        )
        if stream_ended:
            del streams_dict[(session.session_id, stream_id)]
        return
    # Otherwise (e.g. if the stream is bidirectional), echo back the token count
    # on the same stream.
    session.send_stream_data(stream_id, str(count).encode())
