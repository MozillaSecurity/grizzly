from typing import AnyStr


def isomorphic_decode(s: AnyStr) -> str:
    """Decodes a binary string into a text string using iso-8859-1.

    Returns `str`. The function is a no-op if the argument already has a text
    type. iso-8859-1 is chosen because it is an 8-bit encoding whose code
    points range from 0x0 to 0xFF and the values are the same as the binary
    representations, so any binary string can be decoded into and encoded from
    iso-8859-1 without any errors or data loss. Python 3 also uses iso-8859-1
    (or latin-1) extensively in http:
    https://github.com/python/cpython/blob/273fc220b25933e443c82af6888eb1871d032fb8/Lib/http/client.py#L213
    """
    if isinstance(s, str):
        return s

    if isinstance(s, bytes):
        return s.decode("iso-8859-1")

    raise TypeError("Unexpected value (expecting string-like): %r" % s)


def isomorphic_encode(s: AnyStr) -> bytes:
    """Encodes a text-type string into binary data using iso-8859-1.

    Returns `bytes`. The function is a no-op if the argument already has a
    binary type. This is the counterpart of isomorphic_decode.
    """
    if isinstance(s, bytes):
        return s

    if isinstance(s, str):
        return s.encode("iso-8859-1")

    raise TypeError("Unexpected value (expecting string-like): %r" % s)
