"""Tests for Qt qCompress framing and the key schedule."""

from __future__ import annotations

import pytest

from pkt_core.codec.qcompress import LENGTH_PREFIX_SIZE, qcompress, quncompress
from pkt_core.crypto.keys import (
    BLOCK_SIZE,
    FORMATS,
    TAG_SIZE,
    FormatSpec,
    expand_iv,
    expand_key,
    get_format,
)
from pkt_core.errors import CompressionError, TruncatedFileError

# --------------------------------------------------------------------------
# qCompress
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"x",
        b"<PACKETTRACER5></PACKETTRACER5>",
        bytes(range(256)) * 40,
    ],
)
def test_qcompress_roundtrip(payload: bytes) -> None:
    assert quncompress(qcompress(payload)) == payload


def test_qcompress_prefix_is_big_endian_length() -> None:
    payload = b"abcde" * 10
    blob = qcompress(payload)
    assert blob[:LENGTH_PREFIX_SIZE] == (len(payload)).to_bytes(4, "big")
    assert blob[LENGTH_PREFIX_SIZE : LENGTH_PREFIX_SIZE + 2] == b"\x78\x9c" or blob[
        LENGTH_PREFIX_SIZE + 1
    ] in (0x01, 0x5E, 0x9C, 0xDA)


def test_quncompress_rejects_short_input() -> None:
    with pytest.raises(TruncatedFileError):
        quncompress(b"\x00\x00")


def test_quncompress_rejects_length_mismatch() -> None:
    good = qcompress(b"hello world")
    # Flip the declared length.
    bad = (len(b"hello world") + 5).to_bytes(4, "big") + good[4:]
    with pytest.raises(CompressionError):
        quncompress(bad)


def test_quncompress_rejects_corrupt_zlib_stream() -> None:
    with pytest.raises(CompressionError):
        quncompress(b"\x00\x00\x00\x05" + b"not zlib at all")


def test_quncompress_rejects_implausible_length() -> None:
    good = qcompress(b"hi")
    bad = (0xFFFFFFFF).to_bytes(4, "big") + good[4:]
    with pytest.raises(CompressionError):
        quncompress(bad)


# --------------------------------------------------------------------------
# Key schedule
# --------------------------------------------------------------------------


def test_expand_key_and_iv_are_16_repeats() -> None:
    assert expand_key(0x89) == b"\x89" * 16
    assert expand_iv(0x10) == b"\x10" * 16
    assert len(expand_key(0x00)) == BLOCK_SIZE
    assert len(expand_iv(0xFF)) == BLOCK_SIZE


def test_documented_key_schedule_is_pinned() -> None:
    """These constants are the reverse-engineered result; never change silently."""
    pkt = get_format("pkt")
    assert (pkt.cipher, pkt.key_byte, pkt.iv_byte) == ("twofish", 0x89, 0x10)
    assert pkt.key == b"\x89" * 16
    assert pkt.iv == b"\x10" * 16

    assert get_format("log").key_byte == 0xBA
    assert get_format("log").iv_byte == 0xBE
    assert get_format("pkc").cipher == "serpent128"
    assert get_format("pkc").key_byte == 0xAB
    assert get_format("pkc").iv_byte == 0x23
    assert get_format("pta").iv_byte == 0xCD
    assert get_format("sm").cipher == "cast256"
    assert get_format("userapp").key_byte == 0xF1


def test_every_format_has_a_description() -> None:
    for name, spec in FORMATS.items():
        assert spec.description, f"format {name!r} lacks a description"
        assert isinstance(spec, FormatSpec)


def test_format_spec_rejects_out_of_range_bytes() -> None:
    with pytest.raises(ValueError):
        FormatSpec(cipher="twofish", key_byte=256, iv_byte=0, description="x")
    with pytest.raises(ValueError):
        FormatSpec(cipher="twofish", key_byte=0, iv_byte=-1, description="x")


def test_tag_size_is_16() -> None:
    assert TAG_SIZE == 16
