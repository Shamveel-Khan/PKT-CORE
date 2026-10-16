"""Tests for the positional-XOR obfuscation layers.

These transforms are pure arithmetic over bytes, so they can be verified
exhaustively and property-wise without any cipher backend present.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pkt_core.crypto.stream import (
    deobfuscate,
    layer_a,
    layer_a_inverse,
    layer_b,
    obfuscate,
)


# --------------------------------------------------------------------------
# Layer A
# --------------------------------------------------------------------------
def test_layer_a_reference_vector() -> None:
    """Pin the closed form against a hand-computed tiny vector.

    For n=3 and F = (a, b, c):
        C[0] = F[2] ^ ((3 * 1) & 0xff) = c ^ 3
        C[1] = F[1] ^ ((3 * 0) & 0xff) = b ^ 0
        C[2] = F[0] ^ ((3 * -1) & 0xff) = a ^ 0xfd
    """
    a, b, c = 0x10, 0x20, 0x30
    out = layer_a(bytes([a, b, c]))
    assert out == bytes([c ^ 0x03, b ^ 0x00, a ^ 0xFD])


def test_layer_a_is_reversal_plus_xor() -> None:
    """The first output byte must depend on the LAST input byte (no prefix)."""
    n = 64
    base = bytes(range(n))
    flipped = base[:-1] + bytes([base[-1] ^ 0xFF])
    assert layer_a(base)[0] != layer_a(flipped)[0]
    # ...and changing the first byte must NOT change the first output byte.
    flipped_head = bytes([base[0] ^ 0xFF]) + base[1:]
    assert layer_a(base)[0] == layer_a(flipped_head)[0]


@pytest.mark.parametrize("n", [0, 1, 2, 3, 15, 16, 17, 255, 256, 257, 1024])
def test_layer_a_inverse_roundtrips(n: int) -> None:
    data = bytes((i * 7 + 13) & 0xFF for i in range(n))
    assert layer_a_inverse(layer_a(data)) == data
    assert layer_a(layer_a_inverse(data)) == data


@given(st.binary(min_size=0, max_size=2048))
def test_layer_a_property_roundtrip(data: bytes) -> None:
    assert layer_a_inverse(layer_a(data)) == data
    assert layer_a(layer_a_inverse(data)) == data


def test_layer_a_preserves_length() -> None:
    for n in (0, 1, 16, 1000):
        data = bytes(n)
        assert len(layer_a(data)) == n
        assert len(layer_a_inverse(data)) == n


# --------------------------------------------------------------------------
# Layer B
# --------------------------------------------------------------------------
def test_layer_b_reference_vector() -> None:
    """n=4, values (a,b,c,d): out[i] = v ^ ((4-i) & 0xff)."""
    a, b, c, d = 0x11, 0x22, 0x33, 0x44
    out = layer_b(bytes([a, b, c, d]))
    assert out == bytes([a ^ 4, b ^ 3, c ^ 2, d ^ 1])


def test_layer_b_is_an_involution() -> None:
    data = bytes((i * 31) & 0xFF for i in range(300))
    assert layer_b(layer_b(data)) == data


@given(st.binary(min_size=0, max_size=2048))
def test_layer_b_involution_property(data: bytes) -> None:
    assert layer_b(layer_b(data)) == data
    assert deobfuscate(obfuscate(data)) == data


def test_layer_b_aliases_are_the_same_function() -> None:
    assert deobfuscate is layer_b
    assert obfuscate is layer_b


# --------------------------------------------------------------------------
# Composition: the full outer/inner wrapper as applied around the AEAD.
# --------------------------------------------------------------------------
@given(st.binary(min_size=0, max_size=2048))
def test_full_wrapper_roundtrips(data: bytes) -> None:
    """file -> layer A -> layer B -> layer B -> layer A^-1 -> file."""
    wrapped = layer_a_inverse(layer_b(layer_b(layer_a(data))))
    assert wrapped == data
