from logging import getLogger

LOG = getLogger(__name__)

def session_established(session):
    stream_id = session.create_bidirectional_stream()


def stream_data_received(session, stream_id: int, data: bytes, stream_ended: bool):
    try:
        session.close(None)
    except Exception as e:
        LOG.debug(e, exc_info=True)

