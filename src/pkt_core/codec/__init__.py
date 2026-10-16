"""Container codec: qCompress framing and the outer Packet Tracer container."""

from __future__ import annotations

from pkt_core.codec.container import (
    DEFAULT_FORMAT,
    Container,
    decode,
    decode_bytes,
    detect_format,
    encode,
    encode_bytes,
    root_tag,
)
from pkt_core.codec.qcompress import qcompress, quncompress

__all__ = [
    "Container",
    "decode",
    "decode_bytes",
    "encode",
    "encode_bytes",
    "detect_format",
    "root_tag",
    "DEFAULT_FORMAT",
    "qcompress",
    "quncompress",
]
