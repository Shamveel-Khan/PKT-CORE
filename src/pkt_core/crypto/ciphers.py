"""Block-cipher backends: selection, acceleration and fallback.

The container needs exactly one primitive from the cipher: *encrypt a 16-byte
block*. Everything above this module (CMAC, CTR, EAX) is expressed purely in
terms of that oracle, so the backend is swappable.

Three backends are provided, tried in this order:

* **Rust** (:mod:`pkt_core_native`, optional) — the fastest path, built from
  ``native/pkt_core_native/`` with PyO3 + maturin.  Covers Twofish, Serpent and
  CAST-256.  It is a *pure accelerator*: importing :mod:`pkt_core` works fine
  when the module is absent, and the probe is lazy.
* **libgcrypt** — used when it covers the algorithm and Rust is unavailable,
  because it is roughly 100x faster than Python and a container run is
  CTR + CMAC over the whole payload (a 600 KB file is ~38k blocks).  It does
  **not** implement CAST-256.
* **Pure Python** (:mod:`pkt_core.crypto.ciphers_pure`) — the portable
  fallback, and the reference implementation every other backend is checked
  against.

The three are cross-checked against each other and against published
known-answer tests in ``tests/test_ciphers.py`` and
``tests/test_rust_backend.py``, so the fast path is not the unverified one.

The backend can be pinned per process with ``PKT_CORE_BACKEND`` — one of
``auto`` (default), ``rust``, ``gcrypt`` or ``pure`` — and the Rust module can
be masked out entirely with ``PKT_CORE_DISABLE_RUST=1`` (useful to prove the
portable path still works).  :func:`get_cipher` also accepts an explicit
``backend=`` keyword.

.. note::

   ``libgcrypt`` 1.12 **renumbered** its static cipher identifiers:
   ``SERPENT128/192/256`` are now ``304/305/306``, not ``12/13/14``, and
   ``TWOFISH128`` is ``303``. Hard-coding the historical values silently breaks
   those algorithms. This module therefore resolves names through
   ``gcry_cipher_map_name`` and never assumes a numeric id.
"""

from __future__ import annotations

import ctypes
import os
from typing import TYPE_CHECKING, Callable, Final, Literal, Protocol, runtime_checkable

from pkt_core.errors import UnsupportedCipherError

if TYPE_CHECKING:  # pragma: no cover - typing only; stub in typings/
    from pkt_core_native import Cipher as NativeCipher

__all__ = [
    "BLOCK_SIZE",
    "Backend",
    "BlockCipher",
    "LibgcryptCipher",
    "get_cipher",
    "encrypt_block",
    "available_ciphers",
    "available_backends",
    "cipher_available",
    "rust_available",
    "rust_check",
    "CIPHER_KEY_SIZES",
    # re-exported from the pure-Python backend
    "CIPHERS",
    "KEY_SIZES",
    "CipherRegistry",
    "Twofish",
    "Serpent",
    "CAST256",
]

#: A selectable block-cipher backend.  ``"auto"`` walks the preference order
#: Rust -> libgcrypt -> pure Python.
Backend = Literal["auto", "rust", "gcrypt", "pure"]

BLOCK_SIZE: Final[int] = 16

#: Permitted key sizes in bytes for each named cipher.
CIPHER_KEY_SIZES: Final[dict[str, tuple[int, ...]]] = {
    "twofish": (16, 24, 32),
    "serpent128": (16,),
    "serpent192": (24,),
    "serpent256": (32,),
    "cast256": (16, 24, 32),
    "aes": (16, 24, 32),
}

_GCRY_ECB: Final[int] = 1

#: Names ``libgcrypt`` may know, for the accelerated path.
_GCRY_NAMES: Final[tuple[str, ...]] = (
    "twofish",
    "serpent128",
    "serpent192",
    "serpent256",
    "aes",
)


@runtime_checkable
class BlockCipher(Protocol):
    """Minimal interface required by :mod:`pkt_core.crypto.primitives`.

    Both backends implement this, so callers never need to know which one they
    were handed.
    """

    block_size: int
    key_size: int

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt one block and return the ciphertext block."""
        ...


# --------------------------------------------------------------------------
# libgcrypt backend
# --------------------------------------------------------------------------
class _Libgcrypt:
    """Module-scoped ctypes binding to ``libgcrypt``.

    Used in ECB mode only, so no IV is involved here — EAX's nonce handling
    lives in :mod:`pkt_core.crypto.primitives`.
    """

    def __init__(self) -> None:
        self._lib = self._load()
        lib = self._lib
        lib.gcry_check_version.restype = ctypes.c_char_p
        lib.gcry_check_version(None)
        lib.gcry_cipher_map_name.restype = ctypes.c_int
        lib.gcry_cipher_map_name.argtypes = [ctypes.c_char_p]
        lib.gcry_cipher_open.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        lib.gcry_cipher_open.restype = ctypes.c_int
        lib.gcry_cipher_setkey.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.gcry_cipher_setkey.restype = ctypes.c_int
        lib.gcry_cipher_encrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.gcry_cipher_encrypt.restype = ctypes.c_int

    @staticmethod
    def _load() -> ctypes.CDLL:
        for name in ("libgcrypt.so.20", "libgcrypt.so"):
            try:
                return ctypes.CDLL(name)
            except OSError:
                continue
        raise UnsupportedCipherError("libgcrypt not found (install libgcrypt20)")

    def algo_id(self, name: str) -> int:
        """Resolve a cipher name to this build's identifier (never hard-coded)."""
        return int(self._lib.gcry_cipher_map_name(name.encode("ascii")))

    def has(self, name: str) -> bool:
        return self.algo_id(name) != 0

    def open(self, name: str) -> ctypes.c_void_p:
        algo = self.algo_id(name)
        if algo == 0:
            raise UnsupportedCipherError(f"libgcrypt has no cipher named {name!r}")
        handle = ctypes.c_void_p()
        if self._lib.gcry_cipher_open(ctypes.byref(handle), algo, _GCRY_ECB, 0) != 0:
            raise UnsupportedCipherError(f"gcry_cipher_open failed for {name!r}")
        return handle

    def setkey(self, handle: ctypes.c_void_p, key: bytes) -> None:
        if self._lib.gcry_cipher_setkey(handle, key, len(key)) != 0:
            raise UnsupportedCipherError(f"gcry_cipher_setkey rejected {len(key)}-byte key")

    def encrypt(self, handle: ctypes.c_void_p, block: bytes) -> bytes:
        out = ctypes.create_string_buffer(BLOCK_SIZE)
        if self._lib.gcry_cipher_encrypt(handle, out, BLOCK_SIZE, block, BLOCK_SIZE) != 0:
            raise UnsupportedCipherError("gcry_cipher_encrypt failed")
        return out.raw


_LIB: _Libgcrypt | None = None


def _libgcrypt() -> _Libgcrypt | None:
    global _LIB
    if _LIB is None:
        try:
            _LIB = _Libgcrypt()
        except UnsupportedCipherError:
            return None
    return _LIB


class LibgcryptCipher:
    """A block cipher backed by ``libgcrypt`` in ECB mode."""

    block_size: int = BLOCK_SIZE
    #: Length of the key this instance was constructed with.
    key_size: int

    def __init__(self, name: str, key: bytes) -> None:
        lib = _libgcrypt()
        if lib is None or not lib.has(name):
            raise UnsupportedCipherError(f"{name!r} is not available in libgcrypt")
        if len(key) not in CIPHER_KEY_SIZES.get(name, ()):
            raise ValueError(f"{name} does not accept a {len(key)}-byte key")
        self._name = name
        self.key_size = len(key)
        self._handle = lib.open(name)
        lib.setkey(self._handle, key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"block must be {BLOCK_SIZE} bytes, got {len(block)}")
        lib = _libgcrypt()
        if lib is None:  # pragma: no cover - already constructed
            raise UnsupportedCipherError("libgcrypt disappeared")
        return lib.encrypt(self._handle, block)


# --------------------------------------------------------------------------
# Rust accelerator backend (optional)
# --------------------------------------------------------------------------
# ``pkt_core_native`` is a PyO3 extension built from native/pkt_core_native/.
# It is *optional*: probing is lazy (nothing happens at import time), a missing
# module is a silent fall-through to the next backend, and
# PKT_CORE_DISABLE_RUST=1 masks it even when it is installed.
_NATIVE_NAMES: Final[tuple[str, ...]] = (
    "twofish",
    "serpent128",
    "serpent192",
    "serpent256",
    "cast256",
)

_RUST_PROBED: bool = False
_RUST_CIPHER_CLS: Callable[..., NativeCipher] | None = None


def _rust_cipher_class() -> Callable[..., NativeCipher] | None:
    """Lazily probe for the Rust accelerator's ``Cipher`` class.

    Returns ``None`` when the module is absent, unusable or masked out; the
    result (including failure) is cached, because this sits on the hot path.
    """
    global _RUST_PROBED, _RUST_CIPHER_CLS
    if _RUST_PROBED:
        return _RUST_CIPHER_CLS
    _RUST_PROBED = True
    if os.environ.get("PKT_CORE_DISABLE_RUST"):
        return None
    try:
        import pkt_core_native  # typed by typings/pkt_core_native.pyi
    except Exception:  # pragma: no cover - absent or broken extension
        return None
    cipher_cls: Callable[..., NativeCipher] | None = getattr(pkt_core_native, "Cipher", None)
    if cipher_cls is None:  # pragma: no cover - malformed extension
        return None
    _RUST_CIPHER_CLS = cipher_cls
    return cipher_cls


def _reset_rust_probe() -> None:
    """Forget the cached probe result (used by tests that toggle the module)."""
    global _RUST_PROBED, _RUST_CIPHER_CLS
    _RUST_PROBED = False
    _RUST_CIPHER_CLS = None


def rust_available() -> bool:
    """Whether the Rust accelerator module is importable and not disabled."""
    return _rust_cipher_class() is not None


def rust_check() -> dict[str, str] | None:
    """Self-check the accelerator against known-answer vectors.

    Returns ``None`` when the accelerator is unavailable, otherwise a mapping
    with the module ``version`` and one entry per cipher whose KAT passes
    (``"ok"``) — a cheap way to prove the fast path is the verified one.
    """
    if not rust_available():
        return None
    try:
        import pkt_core_native
    except Exception:  # pragma: no cover - probed a moment ago
        return None
    vectors: Final[dict[str, tuple[str, str, str]]] = {
        # name: (key, plaintext, ciphertext) from the published KATs
        "twofish": (
            "00" * 16,
            "00" * 16,
            "9F589F5CF6122C32B6BFEC2F2AE8C35A",
        ),
        "serpent128": (
            "80" + "00" * 15,
            "00" * 16,
            "264E5481EFF42A4606ABDA06C0BFDA3D",
        ),
        "cast256": (
            "2342bb9efa38542c0af75647f29f615d",
            "00" * 16,
            "c842a08972b43d20836c91d1b7530f6b",
        ),
    }
    report: dict[str, str] = {
        "version": str(getattr(pkt_core_native, "__version__", "unknown")),
    }
    for name, (key, pt, ct) in vectors.items():
        got = pkt_core_native.Cipher(name, bytes.fromhex(key)).encrypt_block(
            bytes.fromhex(pt)
        )
        report[name] = "ok" if got == bytes.fromhex(ct) else "MISMATCH"
    return report


def _rust_cipher(name: str, key: bytes) -> BlockCipher | None:
    """Return a Rust-backed cipher, or ``None`` if that path is unavailable."""
    if name not in _NATIVE_NAMES:
        return None
    cipher_cls = _rust_cipher_class()
    if cipher_cls is None:
        return None
    try:
        cipher: BlockCipher = cipher_cls(name, key)
    except (ValueError, TypeError):  # pragma: no cover - validated by caller
        return None
    return cipher


# --------------------------------------------------------------------------
# Pure-Python backend
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Re-export the pure-Python implementation surface
# --------------------------------------------------------------------------
from pkt_core.crypto.ciphers_pure import (  # noqa: E402,F401
    CAST256,
    CIPHERS,
    KEY_SIZES,
    CipherRegistry,
    Serpent,
    Twofish,
)


def _pure_cipher(name: str, key: bytes) -> BlockCipher | None:
    """Return a pure-Python cipher, or ``None`` if this name is unsupported."""
    try:
        from pkt_core.crypto import ciphers_pure as pure
    except ImportError:  # pragma: no cover - optional module
        return None
    registry: dict[str, Callable[[bytes], BlockCipher]] | None = getattr(
        pure, "CIPHERS", None
    )
    if not registry or name not in registry:
        return None
    return registry[name](key)


def _gcrypt_cipher(name: str, key: bytes) -> BlockCipher | None:
    """Return a libgcrypt-backed cipher, or ``None`` if unavailable."""
    if name not in _GCRY_NAMES:
        return None
    try:
        return LibgcryptCipher(name, key)
    except UnsupportedCipherError:
        return None


def get_cipher(
    name: str,
    key: bytes,
    backend: Backend | None = None,
) -> BlockCipher:
    """Construct the named block cipher.

    Preference order: the **Rust** accelerator where it covers the algorithm,
    then **libgcrypt** where it covers it, then **pure Python** (portable, and
    the reference the other two are proven equal to).

    Args:
        name: ``"twofish"``, ``"serpent128"``, ``"serpent256"``, ``"cast256"``…
        key: 16/24/32-byte key.
        backend: Pin a specific backend — ``"rust"``, ``"gcrypt"`` or
            ``"pure"`` — instead of the ``"auto"`` preference order.  When
            ``None`` (default) the ``PKT_CORE_BACKEND`` environment variable is
            consulted, then ``"auto"``.

    Raises:
        UnsupportedCipherError: if no backend can provide the cipher.
        ValueError: if the key length is wrong for that cipher, or ``backend``
            is not a recognised name.
    """
    if name not in CIPHER_KEY_SIZES:
        raise UnsupportedCipherError(f"unknown cipher {name!r}")
    if len(key) not in CIPHER_KEY_SIZES[name]:
        raise ValueError(f"{name} does not accept a {len(key)}-byte key")

    choice: Backend | str = backend or os.environ.get("PKT_CORE_BACKEND") or "auto"
    if choice not in ("auto", "rust", "gcrypt", "pure"):
        raise ValueError(
            f"unknown backend {choice!r}; expected auto, rust, gcrypt or pure"
        )

    # Accelerators first: this is on the hot path for every container
    # operation and the backends are proven byte-identical in the test suite.
    candidates: list[Callable[[str, bytes], BlockCipher | None]] = []
    if choice == "auto":
        candidates = [_rust_cipher, _gcrypt_cipher, _pure_cipher]
    elif choice == "rust":
        candidates = [_rust_cipher]
    elif choice == "gcrypt":
        candidates = [_gcrypt_cipher]
    else:
        candidates = [_pure_cipher]

    for make in candidates:
        impl = make(name, key)
        if impl is not None:
            return impl

    wanted = f"backend {choice!r} cannot provide" if choice != "auto" else "no backend can provide"
    raise UnsupportedCipherError(
        f"{wanted} cipher {name!r}: libgcrypt has no {name!r}, the Rust "
        "accelerator does not cover it or is not installed, and no pure-Python "
        "implementation is registered"
    )


def encrypt_block(name: str, key: bytes, block: bytes) -> bytes:
    """One-shot convenience: encrypt a single block."""
    return get_cipher(name, key).encrypt_block(block)


def available_backends() -> list[str]:
    """Names of the backends this build can actually use.

    Always contains ``"pure"`` (it is in-tree); the others depend on the host —
    ``"rust"`` when ``pkt_core_native`` is installed and not disabled,
    ``"gcrypt"`` when ``libgcrypt`` loads.
    """
    backends: list[str] = []
    if rust_available():
        backends.append("rust")
    if _libgcrypt() is not None:
        backends.append("gcrypt")
    backends.append("pure")
    return backends


def cipher_available(name: str) -> bool:
    """Whether this build can actually provide the named cipher."""
    sizes = CIPHER_KEY_SIZES.get(name)
    if not sizes:
        return False
    try:
        get_cipher(name, b"\x00" * sizes[0])
    except (UnsupportedCipherError, ValueError):
        return False
    return True


def available_ciphers() -> list[str]:
    """Names of every cipher this build can provide."""
    return [n for n in CIPHER_KEY_SIZES if cipher_available(n)]
