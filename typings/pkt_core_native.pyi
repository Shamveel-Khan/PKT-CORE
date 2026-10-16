# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 pkt-core contributors
"""Type stub for the optional ``pkt_core_native`` Rust accelerator.

The real module is built from ``native/pkt_core_native/`` with PyO3 + maturin
and is *optional*: ``pkt_core`` imports and works without it.  This stub keeps
``mypy --strict`` honest about the native surface whether or not the extension
is installed (see ``mypy_path`` in ``pyproject.toml``).
"""

from typing import Final

__version__: Final[str]
BLOCK_SIZE: Final[int]

__all__ = ["BLOCK_SIZE", "Cipher", "__version__", "available_ciphers", "version"]

class Cipher:
    """A keyed 128-bit block cipher (ECB, encrypt only).

    Mirrors :class:`pkt_core.crypto.ciphers.BlockCipher`.
    """

    block_size: int
    key_size: int
    name: str

    def __init__(self, name: str, key: bytes) -> None:
        """Build the key schedule for ``name`` (twofish / serpent* / cast256)."""
        ...

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one 16-byte block and return the 16-byte ciphertext."""
        ...

    def encrypt_blocks(self, data: bytes) -> bytes:
        """Bulk ECB over whole 16-byte blocks."""
        ...

    def decrypt_block(self, block: bytes) -> bytes:
        """CAST-256 only: the inverse of :meth:`encrypt_block`."""
        ...

    def key_schedule(
        self,
    ) -> tuple[list[tuple[int, int, int, int]], list[tuple[int, int, int, int]]]:
        """CAST-256 only: the ``(kr, km)`` quad-round keys of RFC 2612."""
        ...

def available_ciphers() -> list[str]:
    """Registry names this accelerator implements."""
    ...

def version() -> str:
    """Version string of the native module."""
    ...
