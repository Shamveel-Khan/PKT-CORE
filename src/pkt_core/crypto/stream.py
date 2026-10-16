"""Positional XOR obfuscation layers.

Packet Tracer wraps the authenticated-encryption step in two cheap, fully
invertible byte transforms recovered from ``Util::`` in the PT 9 binary:

* **Layer A** (outer "scramble"): byte reversal combined with a position-dependent
  XOR. Applied to turn file bytes into AEAD input on read, and inverted on write.
* **Layer B** (inner ``Util::deobfuscateBytes``): XOR each byte with
  ``(len - i)``. It is an involution — the same call decrypts and encrypts.

Both are expressed over :class:`bytes` and are length-preserving. They exist to
defeat naive ``file``/``strings`` inspection; they are not cryptography.
"""

from __future__ import annotations

from typing import Final

__all__ = ["layer_a", "layer_a_inverse", "layer_b", "deobfuscate", "obfuscate"]

_MASK: Final[int] = 0xFF


def layer_a(buf: bytes) -> bytes:
    """Map file bytes ``F`` to AEAD input ``C``.

    For a buffer of length ``n``::

        C[i] = F[n - 1 - i] ^ ((n * (1 - i)) & 0xFF)

    The output's first byte therefore depends on the input's *last* byte: there
    is no constant prefix to key off, which is why these files look like noise.

    Args:
        buf: The raw file bytes.

    Returns:
        The AEAD input (ciphertext || tag domain).
    """
    n = len(buf)
    return bytes(buf[n - 1 - i] ^ ((n * (1 - i)) & _MASK) for i in range(n))


def layer_a_inverse(buf: bytes) -> bytes:
    """Map AEAD input ``C`` back to file bytes ``F`` (inverse of :func:`layer_a`).

    Written directly from the closed form rather than by re-deriving, so the two
    directions cannot drift apart::

        F[j] = C[n - 1 - j] ^ ((n * (1 - (n - 1 - j))) & 0xFF)
    """
    n = len(buf)
    return bytes(buf[n - 1 - j] ^ ((n * (1 - (n - 1 - j))) & _MASK) for j in range(n))


def layer_b(buf: bytes) -> bytes:
    """``Util::deobfuscateBytes``: XOR byte ``i`` with ``(len(buf) - i) & 0xFF``.

    This transform is **self-inverse**, so the same function serves both
    directions. Aliases :func:`deobfuscate` and :func:`obfuscate` document intent.
    """
    n = len(buf)
    return bytes(v ^ ((n - i) & _MASK) for i, v in enumerate(buf))


#: Intent-revealing alias for the read path (AEAD plaintext -> qCompress payload).
deobfuscate = layer_b

#: Intent-revealing alias for the write path (qCompress payload -> AEAD plaintext).
obfuscate = layer_b
