"""Fuzz and robustness tests.

The contract under test: malformed input must produce a typed
:class:`~pkt_core.errors.PacketTracerError`, never a bare exception, an
``IndexError``, a hang, or a crash. These files are frequently corrupt in the
wild (partial downloads, truncated copies), so the failure mode matters.

Random payloads are generated with a fixed seed so failures reproduce; the
point is not exhaustive fuzzing but that no input class reaches a crash.
"""

from __future__ import annotations

import zlib

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pkt_core import decode_bytes, encode_bytes
from pkt_core.codec.container import detect_format
from pkt_core.codec.qcompress import qcompress, quncompress
from pkt_core.crypto.stream import layer_b
from pkt_core.errors import (
    CompressionError,
    FormatError,
    PacketTracerError,
    TruncatedFileError,
)
from pkt_core.xml import parse_xml_bytes, write_xml

# A small, valid container to mutate.
GOOD_XML = b"<PACKETTRACER5><VERSION>7.3.1.0362</VERSION><NETWORK/></PACKETTRACER5>"
GOOD = encode_bytes(GOOD_XML, "pkt")
GOOD_LEGACY = encode_bytes(GOOD_XML, "legacy")


def _is_typed(exc: BaseException) -> bool:
    return isinstance(exc, PacketTracerError)


# --------------------------------------------------------------------------
# Truncation
# --------------------------------------------------------------------------
@pytest.mark.parametrize("n", [0, 1, 2, 8, 15, 16, 17, 32, len(GOOD) // 2])
def test_truncated_container_never_crashes(n: int) -> None:
    try:
        decode_bytes(GOOD[:n])
    except PacketTracerError:
        pass  # the contract
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"truncation to {n} raised {type(exc).__name__}, not PacketTracerError")


@pytest.mark.parametrize("n", [0, 1, 3, 4, 5, 10, len(GOOD_LEGACY) // 2])
def test_truncated_legacy_container_never_crashes(n: int) -> None:
    try:
        decode_bytes(GOOD_LEGACY[:n])
    except PacketTracerError:
        pass
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"legacy truncation to {n} raised {type(exc).__name__}")


# --------------------------------------------------------------------------
# Bit flips and corruption
# --------------------------------------------------------------------------
@given(
    position=st.integers(min_value=0, max_value=len(GOOD) - 1),
    xor=st.integers(min_value=1, max_value=255),
)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_single_bitflip_never_crashes(position: int, xor: int) -> None:
    data = bytearray(GOOD)
    data[position] ^= xor
    try:
        decode_bytes(bytes(data))
    except PacketTracerError:
        pass
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"byte flip at {position} raised {type(exc).__name__}")


@given(data=st.binary(min_size=0, max_size=512))
@settings(max_examples=300, deadline=None)
def test_arbitrary_bytes_never_crash(data: bytes) -> None:
    for fn in (decode_bytes, detect_format):
        try:
            fn(data)
        except PacketTracerError:
            pass
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"{fn.__name__} raised {type(exc).__name__} on {len(data)} random bytes")


@given(
    blob=st.binary(min_size=6, max_size=256),
    declared=st.integers(min_value=0, max_value=1 << 24),
)
@settings(max_examples=200, deadline=None)
def test_qcompress_with_lying_length_never_crashes(blob: bytes, declared: int) -> None:
    payload = declared.to_bytes(4, "big") + blob
    try:
        quncompress(payload)
    except (CompressionError, TruncatedFileError):
        pass
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"qcompress mismatch raised {type(exc).__name__}")


def test_qcompress_random_zlib_streams() -> None:
    for junk in (b"", b"\x00", b"\x78\x9c", b"notzlib", b"\x78\x9c" + b"\xff" * 20):
        try:
            quncompress((10).to_bytes(4, "big") + junk)
        except (CompressionError, TruncatedFileError):
            pass
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"junk zlib raised {type(exc).__name__}")


# --------------------------------------------------------------------------
# XML layer
# --------------------------------------------------------------------------
@given(data=st.binary(min_size=0, max_size=512))
@settings(max_examples=300, deadline=None)
def test_xml_parser_never_crashes(data: bytes) -> None:
    try:
        doc = parse_xml_bytes(data)
    except FormatError:
        return
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"parse_xml_bytes raised {type(exc).__name__}")
    # If it parsed, writing must not raise and must not fabricate bytes.
    out = write_xml(doc)
    assert isinstance(out, bytes)


@pytest.mark.parametrize(
    "data",
    [
        b"<",
        b"<>",
        b"</>",
        b"<A",
        b"<A>",
        b"<A></B>",
        b"<A " + b"x" * 10000,
        b"<A a=",
        b"<A a=>",
        b"<A a='unclosed>",
        b"<A><" * 500,
        b"\x00" * 100,
        b"<A>" + b"\x00\x01\x02" * 100 + b"</A>",
    ],
)
def test_pathological_xml_is_handled(data: bytes) -> None:
    try:
        doc = parse_xml_bytes(data)
    except FormatError:
        return
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"raised {type(exc).__name__} on {data[:20]!r}")
    write_xml(doc)


def test_huge_attribute_list_never_hangs() -> None:
    data = b"<R " + b" ".join(f'a{i}="{i}"'.encode() for i in range(2000)) + b"/>"
    doc = parse_xml_bytes(data)
    assert write_xml(doc) == data


# --------------------------------------------------------------------------
# Round-trip must survive being mutated then re-read
# --------------------------------------------------------------------------
def test_encode_of_random_xml_roundtrips() -> None:
    """Any XML-ish bytes we can encode must decode back to themselves."""
    for xml in (b"<A/>", b"<A></A>", b"<A>x\x03y</A>", b"<A>\x00</A>"):
        assert decode_bytes(encode_bytes(xml, "legacy")).xml == xml
        assert decode_bytes(encode_bytes(xml, "pkt")).xml == xml


def test_legacy_and_modern_do_not_cross_accept() -> None:
    """Mutating one family's bytes must never authenticate as the other."""
    mutated = bytearray(GOOD_LEGACY)
    mutated[0] ^= 0xFF
    with pytest.raises(PacketTracerError):
        decode_bytes(bytes(mutated), "pkt")
