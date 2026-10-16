"""Qt ``qCompress`` framing.

Packet Tracer serialises its XML through Qt's ``QByteArray::qCompress``, which is
a 4-byte big-endian *uncompressed* length prefix followed by an ordinary zlib
stream. Qt's own ``qUncompress`` insists that the prefix agree with the inflated
size, so we reproduce that check: it is a cheap corruption detector and it keeps
us byte-faithful to what the application expects.
"""

from __future__ import annotations

import struct
import zlib
from typing import Final

from pkt_core.errors import CompressionError, TruncatedFileError

__all__ = ["qcompress", "quncompress", "LENGTH_PREFIX_SIZE"]

LENGTH_PREFIX_SIZE: Final[int] = 4

_HEADER: Final[struct.Struct] = struct.Struct(">I")

# Qt refuses to allocate absurd buffers from a corrupt prefix; mirror that guard.
_MAX_PLAUSIBLE: Final[int] = 1 << 31


def quncompress(payload: bytes) -> bytes:
    """Inflate a Qt ``qCompress`` payload back to its original bytes.

    Args:
        payload: ``4-byte BE uncompressed length || zlib stream``.

    Returns:
        The decompressed bytes.

    Raises:
        TruncatedFileError: if the buffer cannot even hold a length prefix.
        CompressionError: if the zlib stream is invalid or its real length
            disagrees with the prefix.
    """
    if len(payload) < LENGTH_PREFIX_SIZE:
        raise TruncatedFileError(
            f"qCompress payload is {len(payload)} bytes; need at least "
            f"{LENGTH_PREFIX_SIZE} for the length prefix"
        )
    expected = _HEADER.unpack_from(payload)[0]
    if expected > _MAX_PLAUSIBLE:
        raise CompressionError(f"qCompress length prefix is implausible: {expected}")

    try:
        data = zlib.decompress(payload[LENGTH_PREFIX_SIZE:])
    except zlib.error as exc:
        raise CompressionError(f"zlib inflate failed: {exc}") from exc

    if expected != len(data):
        raise CompressionError(
            f"qCompress length mismatch: header says {expected}, inflated {len(data)}"
        )
    return data


def qcompress(data: bytes, level: int = -1) -> bytes:
    """Build a Qt ``qCompress`` payload.

    Args:
        data: The bytes to compress.
        level: zlib compression level (``-1`` is Qt's default).

    Returns:
        ``4-byte BE len(data) || zlib(data)``.

    Note:
        zlib's output is not required to be bit-stable across zlib builds or
        versions, so byte-exact container round-tripping treats this as the
        canonical *encoder* and validates round-trips against the inflated form
        plus the AEAD tag, not against zlib's byte stream.
    """
    return _HEADER.pack(len(data)) + zlib.compress(data, level)
