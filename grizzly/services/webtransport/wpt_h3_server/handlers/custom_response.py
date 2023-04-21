# pylint: skip-file
from typing import List, Tuple
from urllib.parse import parse_qsl, urlsplit


def connect_received(
    request_headers: List[Tuple[bytes, bytes]],
    response_headers: List[Tuple[bytes, bytes]],
) -> None:
    for data in request_headers:
        if data[0] == b":path":
            path = data[1].decode("utf-8")

            qs = dict(parse_qsl(urlsplit(path).query))
            for key, value in qs.items():
                response_headers.append((key.encode("utf-8"), value.encode("utf-8")))

            break
