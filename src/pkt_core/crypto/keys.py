"""Key schedule and per-format parameters.

Packet Tracer derives every container key from a *single repeated byte* for the
key and another for the IV — both are 16 bytes. These values were recovered from
the `Util::encrypt*`/`decrypt*` thunks in the Packet Tracer 9 binary and are
reproduced in ``docs/FORMAT_SPECIFICATION.md``.

The important structural consequence: with a fixed key and fixed IV, the EAX
keystream is **file-independent** (``keystream_i = E_K(N + i)`` with a constant
``N``). The container is therefore fully deterministic — re-encoding identical
XML always yields identical bytes, and format detection can use the AEAD tag as
a cryptographic oracle rather than a magic prefix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping

__all__ = [
    "BLOCK_SIZE",
    "TAG_SIZE",
    "FormatSpec",
    "FORMATS",
    "FormatName",
    "expand_key",
    "expand_iv",
    "get_format",
]

BLOCK_SIZE: Final[int] = 16
"""Block size in bytes for every cipher Packet Tracer uses."""

TAG_SIZE: Final[int] = 16
"""Size of the EAX authentication tag appended to the ciphertext."""


@dataclass(frozen=True, slots=True)
class FormatSpec:
    """Everything needed to seal or open one container flavour.

    Attributes:
        cipher: Backend cipher name — see :mod:`pkt_core.crypto.ciphers`.
            ``"none"`` for the legacy family, which is not encrypted at all.
        key_byte: Single byte that is repeated 16x to form the key (modern family).
        iv_byte: Single byte that is repeated 16x to form the IV/nonce (modern family).
        description: Human-readable origin, for the format specification.
    """

    cipher: str
    key_byte: int
    iv_byte: int
    description: str

    def __post_init__(self) -> None:
        if not 0 <= self.key_byte <= 0xFF:
            raise ValueError(f"key_byte out of range: {self.key_byte!r}")
        if not 0 <= self.iv_byte <= 0xFF:
            raise ValueError(f"iv_byte out of range: {self.iv_byte!r}")

    @property
    def is_legacy(self) -> bool:
        """True for the unencrypted PT 5.x family (no AEAD, no byte reversal)."""
        return self.cipher == "none"

    @property
    def key(self) -> bytes:
        """The 16-byte key: ``key_byte`` repeated."""
        return expand_key(self.key_byte)

    @property
    def iv(self) -> bytes:
        """The 16-byte IV/nonce: ``iv_byte`` repeated."""
        return expand_iv(self.iv_byte)


def expand_key(key_byte: int) -> bytes:
    """Expand a single byte into the 16-byte block-cipher key."""
    return bytes([key_byte]) * BLOCK_SIZE


def expand_iv(iv_byte: int) -> bytes:
    """Expand a single byte into the 16-byte IV/nonce."""
    return bytes([iv_byte]) * BLOCK_SIZE


FormatName = str
"""Name of a container flavour (``"pkt"``, ``"log"``, …)."""


FORMATS: Final[Mapping[FormatName, FormatSpec]] = {
    "pkt": FormatSpec(
        cipher="twofish",
        key_byte=0x89,
        iv_byte=0x10,
        description="Util::encrypt/decryptPTSave — .pkt and .pka save files",
    ),
    "log": FormatSpec(
        cipher="twofish",
        key_byte=0xBA,
        iv_byte=0xBE,
        description="Util::encrypt/decryptLog — internal log files",
    ),
    "pkc": FormatSpec(
        cipher="serpent128",
        key_byte=0xAB,
        iv_byte=0x23,
        description="Util::encrypt/decryptPKCSave — PKC saves",
    ),
    "pta": FormatSpec(
        cipher="serpent128",
        key_byte=0xAB,
        iv_byte=0xCD,
        description="Util::encrypt/decryptPta — .pta activity files",
    ),
    "sm": FormatSpec(
        cipher="cast256",
        key_byte=0x12,
        iv_byte=0xFE,
        description="Util::encrypt/decryptSM — saved simulations",
    ),
    "userapp": FormatSpec(
        cipher="cast256",
        key_byte=0xF1,
        iv_byte=0x1F,
        description="Util::encrypt/decryptUserApp — user applications",
    ),
    # --- Family L: the legacy (PT 5.x) container -----------------------------
    # No AEAD and no byte reversal: the file is just layer-B-obfuscated qCompress.
    # Recorded here so detection can name what it found. Verified byte-exact on
    # 193 real PT 5.1 containers. See docs/LEGACY_FORMAT.md.
    "legacy": FormatSpec(
        cipher="none",
        key_byte=0x00,
        iv_byte=0x00,
        description="PT 5.x .pkt/.pka — layer B + qCompress only (no AEAD, no reversal)",
    ),
}


def get_format(name: FormatName) -> FormatSpec:
    """Look up a container flavour by name.

    Raises:
        KeyError: if no such flavour is registered.
    """
    return FORMATS[name]
