"""Authenticated-encryption primitives: CMAC, CTR and the Crypto++ EAX variant.

Packet Tracer seals containers with ``CryptoPP::EAX_Final`` over Twofish/Serpent/
CAST-256. Crypto++'s EAX differs from the "textbook" presentation in its nonce
handling, and the difference matters — getting it wrong yields files that look
plausible but fail the tag check. The exact construction recovered from the
binary is:

* ``N = CMAC_K( 0^128 || IV )`` — the nonce is a **zero block concatenated with
  the IV**, then CMAC'd. Not ``CMAC_K(IV)``.
* Keystream is CTR with a **big-endian, full-width counter** starting at ``N``:
  ``keystream_i = E_K(N + i)``.
* The 16-byte tag is **appended** after the ciphertext and equals
  ``N ^ CMAC_K( 0x02-block || ciphertext ) ^ CMAC_K( 0x01-block )``,
  where ``0x0N-block`` is the 16-byte block ``00…00 || N`` (i.e. the last byte is
  the small integer, the other 15 bytes are zero).

Because the key and IV are fixed per format, ``N`` and the whole keystream are
constant for a given format — see :mod:`pkt_core.crypto.keys`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Final, NamedTuple

from pkt_core.errors import UnsupportedCipherError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pkt_core.crypto.ciphers import BlockCipher

__all__ = [
    "BLOCK_SIZE",
    "EncryptBlock",
    "cmac_subkeys",
    "cmac",
    "ctr_crypt",
    "eax_seal",
    "eax_open",
    "EaxResult",
]

BLOCK_SIZE: Final[int] = 16

#: A block-cipher encryption oracle: 16 bytes in, 16 bytes out.
EncryptBlock = Callable[[bytes], bytes]

_R: Final[int] = 0x87  # reduction polynomial for GF(2^8) doubling in CMAC
_FULL_MASK: Final[int] = (1 << 128) - 1


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# --------------------------------------------------------------------------
# CMAC (RFC 4493 / NIST SP 800-38B)
# --------------------------------------------------------------------------
def cmac_subkeys(encrypt_block: EncryptBlock) -> tuple[bytes, bytes]:
    """Derive the CMAC sub-keys ``k1`` and ``k2`` from the block cipher."""
    l = encrypt_block(b"\x00" * BLOCK_SIZE)

    k1 = (int.from_bytes(l, "big") << 1) & _FULL_MASK
    if l[0] & 0x80:
        k1 ^= _R
    k1_b = k1.to_bytes(BLOCK_SIZE, "big")

    k2 = (int.from_bytes(k1_b, "big") << 1) & _FULL_MASK
    if k1_b[0] & 0x80:
        k2 ^= _R
    return k1_b, k2.to_bytes(BLOCK_SIZE, "big")


def cmac(
    encrypt_block: EncryptBlock,
    msg: bytes,
    subkeys: tuple[bytes, bytes],
) -> bytes:
    """Compute the CMAC of ``msg`` under the given block cipher.

    Args:
        encrypt_block: The cipher's block-encryption function.
        msg: Message of any length, including empty.
        subkeys: Output of :func:`cmac_subkeys` for the same cipher instance.

    Returns:
        A 16-byte authentication tag.
    """
    k1, k2 = subkeys
    n = max(1, (len(msg) + BLOCK_SIZE - 1) // BLOCK_SIZE)
    complete = len(msg) > 0 and len(msg) % BLOCK_SIZE == 0

    last = msg[(n - 1) * BLOCK_SIZE :]
    if complete:
        last = _xor(last, k1)
    else:
        pad = b"\x80" + b"\x00" * (BLOCK_SIZE - 1 - len(last))
        last = _xor(last + pad, k2)

    state = b"\x00" * BLOCK_SIZE
    for i in range(n - 1):
        state = encrypt_block(_xor(state, msg[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]))
    return encrypt_block(_xor(state, last))


# --------------------------------------------------------------------------
# CTR (big-endian, full 128-bit counter)
# --------------------------------------------------------------------------
def ctr_crypt(encrypt_block: EncryptBlock, nonce: bytes, data: bytes) -> bytes:
    """CTR-mode keystream application. Encryption and decryption are identical.

    The counter is a **big-endian 128-bit integer** starting at ``nonce`` and
    incremented by one per block; it is not a little-endian byte counter and it
    does not wrap within a partial block.
    """
    out = bytearray()
    counter = int.from_bytes(nonce, "big")
    for i in range(0, len(data), BLOCK_SIZE):
        ks = encrypt_block((counter & _FULL_MASK).to_bytes(BLOCK_SIZE, "big"))
        blk = data[i : i + BLOCK_SIZE]
        out += _xor(blk, ks[: len(blk)])
        counter += 1
    return bytes(out)


# --------------------------------------------------------------------------
# EAX (Crypto++ variant)
# --------------------------------------------------------------------------
class EaxResult(NamedTuple):
    """``(plaintext, computed_tag, stored_tag)`` from :func:`eax_open`.

    A named tuple so call sites can use ``result.valid`` / ``result.plaintext``
    without pulling in ``dataclasses`` for what is fundamentally a triple.
    """

    plaintext: bytes
    computed_tag: bytes
    stored_tag: bytes

    @property
    def valid(self) -> bool:
        """Whether the AEAD tag verified. This is the format-detection oracle."""
        return self.computed_tag == self.stored_tag


def _build_encrypt_block(cipher_name: str, key: bytes) -> EncryptBlock:
    # Imported lazily so the AEAD maths does not hard-depend on a particular
    # cipher backend: the backend is pluggable (pure Python or an accelerator),
    # and this module only needs an encrypt-block oracle.
    from pkt_core.crypto.ciphers import get_cipher

    try:
        cipher: BlockCipher = get_cipher(cipher_name, key)
    except (KeyError, ValueError) as exc:
        raise UnsupportedCipherError(
            f"cipher {cipher_name!r} is unavailable or rejected a "
            f"{len(key)}-byte key"
        ) from exc
    return cipher.encrypt_block


def _nonce_of(encrypt_block: EncryptBlock, iv: bytes, subkeys: tuple[bytes, bytes]) -> bytes:
    """``N = CMAC_K(0^128 || IV)`` — Crypto++ EAX's nonce derivation."""
    return cmac(encrypt_block, b"\x00" * BLOCK_SIZE + iv, subkeys)


def _tag_of(
    encrypt_block: EncryptBlock,
    nonce: bytes,
    body: bytes,
    subkeys: tuple[bytes, bytes],
) -> bytes:
    """``tag = N ^ CMAC(0x02-block || body) ^ CMAC(0x01-block)``."""
    m1 = cmac(encrypt_block, b"\x00" * 15 + b"\x02" + body, subkeys)
    m2 = cmac(encrypt_block, b"\x00" * 15 + b"\x01", subkeys)
    return _xor(_xor(nonce, m1), m2)


def eax_seal(cipher_name: str, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt-and-authenticate: returns ``ciphertext || tag``.

    Args:
        cipher_name: Backend cipher name.
        key: 16/24/32-byte key.
        iv: 16-byte IV.
        plaintext: Data to seal.

    Returns:
        Ciphertext with the 16-byte tag appended.
    """
    encrypt_block = _build_encrypt_block(cipher_name, key)
    subkeys = cmac_subkeys(encrypt_block)
    nonce = _nonce_of(encrypt_block, iv, subkeys)
    ct = ctr_crypt(encrypt_block, nonce, plaintext)
    return ct + _tag_of(encrypt_block, nonce, ct, subkeys)


def eax_open(cipher_name: str, key: bytes, iv: bytes, data: bytes) -> EaxResult:
    """Verify and decrypt ``ciphertext || tag``.

    The plaintext is returned **even when the tag fails**, so callers can inspect
    or salvage; use :attr:`EaxResult.valid` (or :func:`eax_verify`) to gate on
    authenticity. This is deliberate — it is what makes the tag usable as a
    format-detection oracle while still exposing the data.

    Args:
        cipher_name: Backend cipher name.
        key: 16/24/32-byte key.
        iv: 16-byte IV.
        data: Ciphertext with the 16-byte tag appended.

    Returns:
        :class:`EaxResult` triple.
    """
    if len(data) < BLOCK_SIZE:
        from pkt_core.errors import TruncatedFileError

        raise TruncatedFileError(
            f"EAX input is {len(data)} bytes; need at least {BLOCK_SIZE} for the tag"
        )
    encrypt_block = _build_encrypt_block(cipher_name, key)
    subkeys = cmac_subkeys(encrypt_block)
    body, stored = data[:-BLOCK_SIZE], data[-BLOCK_SIZE:]
    nonce = _nonce_of(encrypt_block, iv, subkeys)
    pt = ctr_crypt(encrypt_block, nonce, body)
    return EaxResult(
        plaintext=pt,
        computed_tag=_tag_of(encrypt_block, nonce, body, subkeys),
        stored_tag=stored,
    )


def eax_verify(cipher_name: str, key: bytes, iv: bytes, data: bytes) -> bool:
    """Return whether ``data`` authenticates under this key/IV. Cheap rejection."""
    return eax_open(cipher_name, key, iv, data).valid
