# pylint: skip-file
def session_established(session):
    session.dict_for_handlers["code"] = 400


def stream_data_received(session, stream_id: int, data: bytes, stream_ended: bool):
    code: int = session.dict_for_handlers["code"]
    if session.stream_is_unidirectional(stream_id):
        session.stop_stream(stream_id, code)
    else:
        session.stop_stream(stream_id, code)
        session.reset_stream(stream_id, code)
