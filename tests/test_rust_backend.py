# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 pkt-core contributors
"""Validation harness for the optional Rust accelerator (:mod:`pkt_core_native`).

The accelerator must be *exactly* as correct as the pure-Python reference —
there is no "fast and slightly different" mode for cryptography.  These tests
therefore mirror the published known-answer tests of ``tests/test_ciphers.py``
through the native module, prove ``Rust == pure Python`` on random data for
every cipher and key size, and prove that real corpus containers decode to
byte-identical XML through the Rust backend and the pure-Python one.

They also pin the *optional* contract: with the module absent (or masked with
``PKT_CORE_DISABLE_RUST=1``) ``pkt_core`` imports fine and the pure-Python path
stays fully functional.

Run them with the module installed and with it removed / masked; both must pass.
"""

from __future__ import annotations

import csv
import os
import random
import subprocess
import sys
import types
from pathlib import Path
from typing import Protocol

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from pkt_core.crypto import ciphers  # noqa: E402
from pkt_core.crypto.ciphers import (  # noqa: E402
    BLOCK_SIZE,
    get_cipher,
    rust_available,
    rust_check,
)
from pkt_core.crypto.ciphers_pure import (  # noqa: E402
    CAST256,
    KEY_SIZES,
    Serpent,
    Twofish,
)
from pkt_core.errors import UnsupportedCipherError  # noqa: E402

# Same known-answer tables as tests/test_ciphers.py — imported so the two
# suites cannot drift apart.
from test_ciphers import (  # noqa: E402
    CAST256_KATS,
    SERPENT_KATS,
    TWOFISH_KATS,
)

CORPUS_DIR = REPO_ROOT / "corpus"
CORPUS_INDEX = CORPUS_DIR / "CORPUS_INDEX.tsv"
CORPUS_FILES_DIR = CORPUS_DIR / "internet"

_PURE_CLASSES = {
    "twofish": Twofish,
    "serpent128": Serpent,
    "serpent192": Serpent,
    "serpent256": Serpent,
    "cast256": CAST256,
}


class NativeCipherLike(Protocol):
    """The subset of the native ``Cipher`` surface these tests exercise."""

    block_size: int
    key_size: int

    def encrypt_block(self, block: bytes) -> bytes: ...
    def encrypt_blocks(self, data: bytes) -> bytes: ...
    def decrypt_block(self, block: bytes) -> bytes: ...
    def key_schedule(
        self,
    ) -> tuple[list[tuple[int, int, int, int]], list[tuple[int, int, int, int]]]: ...
    def cast256_quad_round(
        self, state: tuple[int, int, int, int], index: int
    ) -> tuple[int, int, int, int]: ...


def _native() -> types.ModuleType | None:
    """The accelerator module, or ``None`` when it is not installed."""
    try:
        import pkt_core_native
    except ImportError:
        return None
    return pkt_core_native


requires_rust = pytest.mark.skipif(
    not rust_available(),
    reason="pkt_core_native (the Rust accelerator) is not installed",
)


def _native_cipher(name: str, key: bytes) -> NativeCipherLike:
    native = _native()
    assert native is not None, "test requires the Rust accelerator"
    cipher: NativeCipherLike = native.Cipher(name, key)
    return cipher


CIPHER_KEY_SIZES_FOR_TEST = [
    ("twofish", 16),
    ("twofish", 24),
    ("twofish", 32),
    ("serpent128", 16),
    ("serpent192", 24),
    ("serpent256", 32),
    ("cast256", 16),
    ("cast256", 24),
    ("cast256", 32),
]


# ---------------------------------------------------------------------------
# module surface
# ---------------------------------------------------------------------------
@requires_rust
def test_native_module_identity() -> None:
    """The extension exposes the documented surface and the cipher names."""
    native = _native()
    assert native is not None
    assert native.BLOCK_SIZE == BLOCK_SIZE
    assert set(native.available_ciphers()) == {
        "twofish",
        "serpent128",
        "serpent192",
        "serpent256",
        "cast256",
    }
    assert native.version() == native.__version__
    assert isinstance(native.version(), str) and native.version()


@requires_rust
def test_rust_check_reports_ok() -> None:
    """rust_check() runs the published KATs through the accelerator."""
    report = rust_check()
    assert report is not None
    assert report["version"]
    assert report["twofish"] == "ok"
    assert report["serpent128"] == "ok"
    assert report["cast256"] == "ok"


# ---------------------------------------------------------------------------
# known-answer tests (mirrored from tests/test_ciphers.py)
# ---------------------------------------------------------------------------
@requires_rust
@pytest.mark.parametrize(
    ("key_hex", "pt_hex", "ct_hex"),
    TWOFISH_KATS,
    ids=[f"key{len(k) // 2}b-{i}" for i, (k, _, _) in enumerate(TWOFISH_KATS)],
)
def test_rust_twofish_kat(key_hex: str, pt_hex: str, ct_hex: str) -> None:
    """Rust Twofish matches the published AES-submission test vectors."""
    cipher = _native_cipher("twofish", bytes.fromhex(key_hex))
    assert cipher.encrypt_block(bytes.fromhex(pt_hex)) == bytes.fromhex(ct_hex)


@requires_rust
@pytest.mark.parametrize(
    ("key_hex", "pt_hex", "ct_hex"),
    SERPENT_KATS,
    ids=[f"key{len(k) // 2}b-{i}" for i, (k, _, _) in enumerate(SERPENT_KATS)],
)
def test_rust_serpent_kat(key_hex: str, pt_hex: str, ct_hex: str) -> None:
    """Rust Serpent matches the published AES-submission / NESSIE vectors."""
    key_len = len(bytes.fromhex(key_hex))
    name = {16: "serpent128", 24: "serpent192", 32: "serpent256"}[key_len]
    cipher = _native_cipher(name, bytes.fromhex(key_hex))
    assert cipher.encrypt_block(bytes.fromhex(pt_hex)) == bytes.fromhex(ct_hex)


@requires_rust
@pytest.mark.parametrize(
    ("key_hex", "pt_hex", "ct_hex"),
    CAST256_KATS,
    ids=["128", "192", "256"],
)
def test_rust_cast256_kat(key_hex: str, pt_hex: str, ct_hex: str) -> None:
    """Rust CAST-256 matches RFC 2612 appendix A for every published key size."""
    cipher = _native_cipher("cast256", bytes.fromhex(key_hex))
    assert cipher.encrypt_block(bytes.fromhex(pt_hex)) == bytes.fromhex(ct_hex)


@requires_rust
def test_rust_cast256_rfc2612_intermediate_values() -> None:
    """RFC 2612 appendix A intermediates, through the Rust key schedule.

    Pins the quad-round key ordering: Kr_(0) = 5LSB(A, C, E, G) and
    Km_(0) = (H, F, D, B) after the first two octaves, and the state after
    Q_0 on a zero block.
    """
    cipher = _native_cipher("cast256", bytes.fromhex("2342bb9efa38542c0af75647f29f615d"))
    kr, km = cipher.key_schedule()
    assert tuple(kr[0]) == (0x1C, 0x1D, 0x18, 0x06)
    assert tuple(km[0]) == (0xF364D7F9, 0x233500C0, 0x83CEE501, 0x01F857C6)
    state = cipher.cast256_quad_round((0, 0, 0, 0), 0)
    expected = bytes.fromhex("e2c604af966715811b377f12de19e459")
    assert tuple(state) == tuple(
        int.from_bytes(expected[i : i + 4], "big") for i in range(0, 16, 4)
    )


@requires_rust
def test_rust_cast256_decrypt_matches_rfc_direction() -> None:
    """Rust CAST-256 decryption is the exact inverse of encryption."""
    for key_hex, pt_hex, ct_hex in CAST256_KATS:
        cipher = _native_cipher("cast256", bytes.fromhex(key_hex))
        assert cipher.decrypt_block(bytes.fromhex(ct_hex)) == bytes.fromhex(pt_hex)
        assert cipher.decrypt_block(bytes.fromhex(pt_hex)) != bytes.fromhex(pt_hex)


# ---------------------------------------------------------------------------
# Rust == pure Python, on random data
# ---------------------------------------------------------------------------
@requires_rust
@pytest.mark.parametrize(
    ("name", "key_len"),
    [
        pytest.param(name, key_len, id=f"{name}-{key_len * 8}")
        for name, sizes in KEY_SIZES.items()
        for key_len in sizes
    ],
)
def test_rust_matches_pure_random_grid(name: str, key_len: int) -> None:
    """200 random key/plaintext pairs per cipher and key size are byte-equal.

    This is the check that catches the traps zero-key vectors miss: the
    Twofish h() key-byte indices, the RS/MDS polynomials, the Serpent prekey
    ``w[i]`` indexing and the CAST-256 trailing-word zero padding all only
    show up once the key is non-trivial.
    """
    rng = random.Random(f"rust-vs-pure/{name}/{key_len}")
    pure_cls = _PURE_CLASSES[name]
    for _ in range(200):
        key = rng.randbytes(key_len)
        block = rng.randbytes(BLOCK_SIZE)
        fast = _native_cipher(name, key).encrypt_block(block)
        slow = pure_cls(key).encrypt_block(block)
        assert fast == slow, (
            f"mismatch for {name} key={key.hex()} block={block.hex()}: "
            f"{fast.hex()} != {slow.hex()}"
        )


@requires_rust
def test_rust_bulk_matches_single_block() -> None:
    """``encrypt_blocks`` is the per-block primitive, applied to each block."""
    rng = random.Random("bulk")
    for name in ("twofish", "serpent256", "cast256"):
        key_len = max(KEY_SIZES[name])
        key = rng.randbytes(key_len)
        cipher = _native_cipher(name, key)
        data = rng.randbytes(16 * 37)
        bulk = cipher.encrypt_blocks(data)
        single = b"".join(
            cipher.encrypt_block(data[i : i + 16])
            for i in range(0, len(data), 16)
        )
        assert bulk == single
        with pytest.raises(ValueError):
            cipher.encrypt_blocks(data[:15])


# ---------------------------------------------------------------------------
# end-to-end container equivalence on real corpus files
# ---------------------------------------------------------------------------
def _index_paths() -> list[Path]:
    """Candidate CORPUS_INDEX.tsv locations (repo corpus, then ../corpus)."""
    return [
        CORPUS_INDEX,
        REPO_ROOT.parent / "corpus" / "CORPUS_INDEX.tsv",
    ]


def _corpus_dirs() -> list[Path]:
    """Candidate corpus file directories; ``../corpus/internet`` first."""
    return [
        REPO_ROOT.parent / "corpus" / "internet",
        CORPUS_FILES_DIR,
    ]


def _ok_corpus_files() -> list[Path]:
    """First five corpus files whose index ``decode_status`` is ``OK``.

    The index is read with ``csv.DictReader`` (tab separated) because the
    filenames contain spaces and must never be shell-split.
    """
    for index in _index_paths():
        if not index.is_file():
            continue
        for files_dir in _corpus_dirs():
            if not files_dir.is_dir():
                continue
            chosen: list[Path] = []
            with index.open(newline="", encoding="utf-8") as handle:
                for row in csv.DictReader(handle, delimiter="\t"):
                    if row.get("decode_status") != "OK":
                        continue
                    path = files_dir / row["filename"]
                    if path.is_file():
                        chosen.append(path)
                    if len(chosen) == 5:
                        return chosen
    return []


@requires_rust
def test_container_end_to_end_rust_vs_pure() -> None:
    """Real containers decode to byte-identical XML: Rust backend vs pure.

    The strongest end-to-end proof: the whole detect -> EAX open -> qUncompress
    chain runs with every block cipher coming from a different backend, and the
    XML must come out identical.
    """
    from pkt_core.codec.container import decode_bytes

    files = _ok_corpus_files()
    if len(files) < 5:
        pytest.skip("corpus index / internet corpus files are unavailable")

    os.environ["PKT_CORE_BACKEND"] = "pure"
    try:
        pure_xml = {path.name: decode_bytes(path.read_bytes()).xml for path in files}
        os.environ["PKT_CORE_BACKEND"] = "rust"
        rust_xml = {path.name: decode_bytes(path.read_bytes()).xml for path in files}
    finally:
        os.environ.pop("PKT_CORE_BACKEND", None)

    assert rust_xml.keys() == pure_xml.keys()
    for name in pure_xml:
        assert rust_xml[name] == pure_xml[name], (
            f"{name}: Rust-backed decode diverges from the pure-Python one "
            f"({len(rust_xml[name])} vs {len(pure_xml[name])} XML bytes)"
        )


# ---------------------------------------------------------------------------
# the backend is optional
# ---------------------------------------------------------------------------
_SUBPROCESS_SNIPPET = """
import sys
sys.path.insert(0, {src!r})

class _Blocker:
    \"\"\"Make `import pkt_core_native` fail as if the module were absent.\"\"\"
    def find_spec(self, name, path=None, target=None):
        if name == "pkt_core_native":
            raise ImportError("pkt_core_native is blocked by the test harness")
        return None

sys.modules.pop("pkt_core_native", None)
sys.meta_path.insert(0, _Blocker())

import pkt_core
from pkt_core.crypto import ciphers

assert ciphers.rust_available() is False, "blocked module must probe as absent"
assert "rust" not in ciphers.available_backends()
key = bytes.fromhex("00" * 16)
cipher = ciphers.get_cipher("twofish", key)
assert type(cipher).__module__.startswith("pkt_core"), type(cipher)
assert cipher.encrypt_block(bytes.fromhex("00" * 16)) == bytes.fromhex(
    "9F589F5CF6122C32B6BFEC2F2AE8C35A"
)
assert ciphers.get_cipher("cast256", bytes.fromhex("2342bb9efa38542c0af75647f29f615d"))
print("OK")
"""


def test_import_and_pure_path_work_without_rust_module() -> None:
    """A fresh interpreter with the accelerator removed still does everything.

    This is the portability contract: ``import pkt_core`` and the pure-Python
    cipher path must not depend on the Rust module in any way.
    """
    script = _SUBPROCESS_SNIPPET.format(src=str(SRC_DIR))
    # Drop any caller-supplied backend pin: this subprocess deliberately blocks
    # the accelerator, so inheriting PKT_CORE_BACKEND=rust would be a
    # contradiction rather than a meaningful assertion.
    clean_env = {k: v for k, v in os.environ.items()
                 if k not in ("PKT_CORE_BACKEND", "PKT_CORE_DISABLE_RUST")}
    clean_env["PYTHONPATH"] = str(SRC_DIR)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=clean_env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


@requires_rust
def test_disable_rust_env_masks_the_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """PKT_CORE_DISABLE_RUST=1 makes the probe report the module as absent."""
    monkeypatch.setenv("PKT_CORE_DISABLE_RUST", "1")
    ciphers._reset_rust_probe()
    try:
        assert ciphers.rust_available() is False
        assert "rust" not in ciphers.available_backends()
        key = b"\x89" * 16
        cipher = get_cipher("twofish", key)
        assert type(cipher).__module__.startswith("pkt_core")
    finally:
        monkeypatch.delenv("PKT_CORE_DISABLE_RUST")
        ciphers._reset_rust_probe()
    assert ciphers.rust_available() is True


# ---------------------------------------------------------------------------
# backend selection
# ---------------------------------------------------------------------------
@requires_rust
def test_auto_prefers_rust() -> None:
    """With the accelerator installed, the auto order selects it first."""
    for name, sizes in CIPHER_KEY_SIZES_FOR_TEST:
        key = b"\x42" * sizes
        cipher = get_cipher(name, key)
        assert type(cipher).__module__ == "pkt_core_native", (
            f"auto backend for {name} is {type(cipher).__module__}, expected rust"
        )
        assert cipher.block_size == BLOCK_SIZE
        assert cipher.key_size == sizes


@requires_rust
@pytest.mark.parametrize(("name", "key_len"), CIPHER_KEY_SIZES_FOR_TEST)
def test_backend_pinning_agrees(name: str, key_len: int) -> None:
    """Explicit backend= and PKT_CORE_BACKEND both work and agree byte-wise."""
    rng = random.Random(f"pin/{name}/{key_len}")
    key = rng.randbytes(key_len)
    block = rng.randbytes(BLOCK_SIZE)
    expected = _native_cipher(name, key).encrypt_block(block)

    forced = get_cipher(name, key, backend="rust")
    assert type(forced).__module__ == "pkt_core_native"
    assert forced.encrypt_block(block) == expected

    pure = get_cipher(name, key, backend="pure")
    assert type(pure) is _PURE_CLASSES[name]
    assert pure.encrypt_block(block) == expected

    os.environ["PKT_CORE_BACKEND"] = "pure"
    try:
        env_forced = get_cipher(name, key)
        assert type(env_forced) is _PURE_CLASSES[name]
    finally:
        os.environ.pop("PKT_CORE_BACKEND", None)
    assert get_cipher(name, key).encrypt_block(block) == expected


def test_backend_pinning_gcrypt_and_errors() -> None:
    """gcrypt pinning works where it applies; bad names are rejected."""
    with pytest.raises(ValueError):
        get_cipher("twofish", b"\x00" * 16, backend="openssl")
    with pytest.raises(UnsupportedCipherError):
        get_cipher("nope", b"\x00" * 16)
    with pytest.raises(ValueError):
        get_cipher("twofish", b"\x00" * 15)
    try:
        cipher = get_cipher("twofish", b"\x00" * 16, backend="gcrypt")
    except UnsupportedCipherError:
        pytest.skip("libgcrypt is not available")
    assert type(cipher).__name__ == "LibgcryptCipher"
    assert cipher.encrypt_block(b"\x00" * 16) == bytes.fromhex(
        "9F589F5CF6122C32B6BFEC2F2AE8C35A"
    )


@requires_rust
def test_native_rejects_bad_keys_and_blocks() -> None:
    """The native class raises ValueError exactly like the pure classes."""
    native = _native()
    assert native is not None
    with pytest.raises(ValueError):
        native.Cipher("twofish", b"\x00" * 15)
    with pytest.raises(ValueError):
        native.Cipher("serpent128", b"\x00" * 24)
    with pytest.raises(ValueError):
        native.Cipher("cast256", b"\x00" * 17)
    with pytest.raises(ValueError):
        native.Cipher("aes", b"\x00" * 16)  # not implemented natively
    cipher = native.Cipher("twofish", b"\x00" * 16)
    with pytest.raises(ValueError):
        cipher.encrypt_block(b"\x00" * 15)
    with pytest.raises(ValueError):
        cipher.encrypt_block(b"\x00" * 17)
