"""Validation harness for :mod:`pkt_core.crypto.ciphers`.

Three levels of proof that the pure-Python ciphers are byte-identical to the
implementations Packet Tracer interoperates with:

1. **Known-answer tests** against the published test vectors
   (Twofish AES submission / ``twofishv.dat``, Serpent NESSIE/AES-submission
   vectors, CAST-256 RFC 2612 appendix A including intermediate values).
2. **A randomised cross-check against libgcrypt** (Twofish gcry id 10,
   Serpent128/192/256) over 200 key/plaintext pairs per key size.
3. **End-to-end container equivalence**: real ``.pkt`` corpus files must
   decode to byte-identical XML through this module's pure-Python Twofish and
   through ``pt9.py`` (which uses libgcrypt).

CAST-256 has no libgcrypt counterpart, so it is pinned by the RFC vectors,
the RFC intermediate key-schedule values, and decrypt round-trips.
"""

from __future__ import annotations

import csv
import ctypes
import importlib.util
import random
import struct
import sys
import time
import types
import zlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from pkt_core.crypto.ciphers import (  # noqa: E402
    BLOCK_SIZE,
    CIPHERS,
    KEY_SIZES,
    CAST256,
    CipherRegistry,
    Serpent,
    Twofish,
    encrypt_block,
    get_cipher,
)

CORPUS_DIR = REPO_ROOT / "corpus"
CORPUS_INDEX = CORPUS_DIR / "CORPUS_INDEX.tsv"
CORPUS_FILES_DIR = CORPUS_DIR / "internet"
PT9_PATH = REPO_ROOT / "packet-tracer-pkt-format" / "pt9.py"

# Repeated-byte container key/IV of the .pkt/.pka format (pt9.py FORMATS).
_PKT_KEY_BYTE = 0x89
_PKT_IV_BYTE = 0x10


# ---------------------------------------------------------------------------
# Known-answer tests
# ---------------------------------------------------------------------------
# Twofish: Schneier, Kelsey, Whiting, Wagner, Hall, Ferguson, "The Twofish
# Encryption Algorithm: A 128-Bit Block Cipher" (1998) AES submission test
# vectors (``ecb_tbl.txt`` / ``ecb_ival.txt``), as shipped in Crypto++
# ``TestData/twofishv.dat`` and Botan ``block/twofish.vec``.
TWOFISH_KATS: list[tuple[str, str, str]] = [
    # key, plaintext, ciphertext (hex)
    ("00" * 16, "00" * 16, "9F589F5CF6122C32B6BFEC2F2AE8C35A"),
    ("00" * 24, "00" * 16, "EFA71F788965BD4453F860178FC19101"),
    ("00" * 32, "00" * 16, "57FF739D4DC92C1BD7FC01700CC8216F"),
    # AES-submission "Monte Carlo chain" vectors (twofishv.dat)
    (
        "9F589F5CF6122C32B6BFEC2F2AE8C35A",
        "D491DB16E7B1C39E86CB086B789F5419",
        "019F9809DE1711858FAAC3A3BA20FBC3",
    ),
    (
        "D491DB16E7B1C39E86CB086B789F5419",
        "019F9809DE1711858FAAC3A3BA20FBC3",
        "6363977DE839486297E661C6C9D668EB",
    ),
    (
        "EFA71F788965BD4453F860178FC191010000000000000000",
        "88B2B2706B105E36B446BB6D731A1E88",
        "39DA69D6BA4997D585B6DC073CA341B2",
    ),
    (
        "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
        "39DA69D6BA4997D585B6DC073CA341B2",
        "182B02D81497EA45F9DAACDC29193A65",
    ),
    (
        "3059D6D61753B958D92F4781C8640E586CB4561C40BF0A9705931CB6D408E7FA",
        "E69465770505D7F80EF68CA38AB3A3D6",
        "5AB67A5F8539A4A5FD9F0373BA463466",
    ),
    # single-bit-walk vectors (twofishv.dat / Botan twofish.vec)
    ("00" * 24, "80" + "00" * 15, "62EF193EDB7D399ACA50EC1CBE5398D8"),
    ("00" * 32, "80" + "00" * 15, "23A385F617F313DAC05BCB7EABD61807"),
]

# Serpent: AES submission / NESSIE test vectors, as shipped in Crypto++
# ``TestData/serpentv.dat`` (and the libgcrypt serpent self-test).
SERPENT_KATS: list[tuple[str, str, str]] = [
    (
        "80" + "00" * 15,
        "00" * 16,
        "264E5481EFF42A4606ABDA06C0BFDA3D",
    ),
    (
        "00" * 16,
        "D29D576FCEA3A3A7ED9099F29273D78E",
        "B2288B968AE8B08648D1CE9606FD992D",
    ),
    (
        "00" * 24,
        "D29D576FCEABA3A7ED9899F2927BD78E",
        "130E353E1037C22405E8FAEFB2C3C3E9",
    ),
    (
        "00" * 32,
        "D095576FCEA3E3A7ED98D9F29073D78E",
        "B90EE5862DE69168F2BDD5125B45472B",
    ),
    (
        "00" * 32,
        "00000000010000000200000003000000",
        "2061A42782BD52EC691EC383B03BA77C",
    ),
    (
        "FFEEDDCCBBAA99887766554433221100",
        "1032547698BADCFEEFCDAB8967452301",
        "D5BAA00A4BB9D8A7C981C8DC90D89D92",
    ),
]

# CAST-256: RFC 2612 appendix A (authoritative).
CAST256_KATS: list[tuple[str, str, str]] = [
    (
        "2342bb9efa38542c0af75647f29f615d",
        "00" * 16,
        "c842a08972b43d20836c91d1b7530f6b",
    ),
    (
        "2342bb9efa38542cbed0ac83940ac298bac77a7717942863",
        "00" * 16,
        "1b386c0210dcadcbdd0e41aa08a7a7e8",
    ),
    (
        "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
        "00" * 16,
        "4f6a2038286897b9c9870136553317fa",
    ),
]

# RFC 2612 appendix A intermediate values for the 128-bit KAT: the rotation
# and masking keys of quad-round 1 and the block after that quad-round.
CAST256_KAT128_KEY = "2342bb9efa38542c0af75647f29f615d"
CAST256_KAT128_R1_ROTK = (0x1C, 0x1D, 0x18, 0x06)
CAST256_KAT128_R1_MASK = (0xF364D7F9, 0x233500C0, 0x83CEE501, 0x01F857C6)
CAST256_KAT128_R1_OUT = "e2c604af966715811b377f12de19e459"


@pytest.mark.parametrize(
    ("key_hex", "pt_hex", "ct_hex"),
    TWOFISH_KATS,
    ids=[f"key{len(k) // 2}b-{i}" for i, (k, _, _) in enumerate(TWOFISH_KATS)],
)
def test_twofish_kat(key_hex: str, pt_hex: str, ct_hex: str) -> None:
    """Twofish matches the published AES-submission test vectors."""
    cipher = Twofish(bytes.fromhex(key_hex))
    assert cipher.encrypt_block(bytes.fromhex(pt_hex)) == bytes.fromhex(ct_hex)


@pytest.mark.parametrize(
    ("key_hex", "pt_hex", "ct_hex"),
    SERPENT_KATS,
    ids=[f"key{len(k) // 2}b-{i}" for i, (k, _, _) in enumerate(SERPENT_KATS)],
)
def test_serpent_kat(key_hex: str, pt_hex: str, ct_hex: str) -> None:
    """Serpent matches the published AES-submission / NESSIE test vectors."""
    cipher = Serpent(bytes.fromhex(key_hex))
    assert cipher.encrypt_block(bytes.fromhex(pt_hex)) == bytes.fromhex(ct_hex)


@pytest.mark.parametrize(
    ("key_hex", "pt_hex", "ct_hex"),
    CAST256_KATS,
    ids=["128", "192", "256"],
)
def test_cast256_rfc2612_kat(key_hex: str, pt_hex: str, ct_hex: str) -> None:
    """CAST-256 matches RFC 2612 appendix A for every published key size."""
    cipher = CAST256(bytes.fromhex(key_hex))
    assert cipher.encrypt_block(bytes.fromhex(pt_hex)) == bytes.fromhex(ct_hex)


def test_cast256_rfc2612_intermediate_values() -> None:
    """RFC 2612 appendix A intermediate key-schedule values (128-bit KAT).

    These pin the quad-round key ordering: Kr_(0) = 5LSB(A, C, E, G) and
    Km_(0) = (H, F, D, B) after the first two octaves of the key schedule.
    """
    cipher = CAST256(bytes.fromhex(CAST256_KAT128_KEY))
    assert cipher.kr[0] == CAST256_KAT128_R1_ROTK
    assert cipher.km[0] == CAST256_KAT128_R1_MASK
    state = cipher.quad_round((0, 0, 0, 0), 0, forward=True)
    expected = bytes.fromhex(CAST256_KAT128_R1_OUT)
    assert state == tuple(int.from_bytes(expected[i : i + 4], "big") for i in range(0, 16, 4))


def test_cast256_decrypt_matches_rfc_direction() -> None:
    """RFC 2612's decryption listing: reversed quad-round keys map CT -> PT."""
    for key_hex, pt_hex, ct_hex in CAST256_KATS:
        cipher = CAST256(bytes.fromhex(key_hex))
        assert cipher.decrypt_block(bytes.fromhex(ct_hex)) == bytes.fromhex(pt_hex)


def test_cast256_encrypt_decrypt_roundtrip() -> None:
    """CAST-256 decryption is the exact inverse of encryption on random data."""
    rng = random.Random(2612)
    for key_len in (16, 20, 24, 28, 32):
        cipher = CAST256(rng.randbytes(key_len))
        for _ in range(25):
            block = rng.randbytes(BLOCK_SIZE)
            assert cipher.decrypt_block(cipher.encrypt_block(block)) == block
            assert cipher.encrypt_block(cipher.decrypt_block(block)) == block


# ---------------------------------------------------------------------------
# registry / interface
# ---------------------------------------------------------------------------
def test_registry_names_match_pt9() -> None:
    """The registry names are exactly the ones pt9.py's _CIPHER_IDS uses."""
    assert set(CIPHERS) == {"twofish", "serpent128", "serpent192", "serpent256", "cast256"}
    assert CIPHERS["twofish"] is Twofish
    assert CIPHERS["serpent128"] is Serpent
    assert CIPHERS["serpent192"] is Serpent
    assert CIPHERS["serpent256"] is Serpent
    assert CIPHERS["cast256"] is CAST256
    assert KEY_SIZES["serpent128"] == (16,)
    assert KEY_SIZES["serpent192"] == (24,)
    assert KEY_SIZES["serpent256"] == (32,)


def test_registry_key_and_block_validation() -> None:
    """Wrong key sizes, block sizes and names are rejected with clear errors."""
    registry = CipherRegistry()
    assert registry.names() == tuple(CIPHERS)
    assert registry.key_sizes("twofish") == (16, 24, 32)
    with pytest.raises(KeyError):
        registry.key_sizes("nope")
    with pytest.raises(KeyError):
        registry.create("nope", b"\x00" * 16)
    with pytest.raises(ValueError):
        registry.create("serpent128", b"\x00" * 24)
    with pytest.raises(ValueError):
        Twofish(b"\x00" * 15)
    with pytest.raises(ValueError):
        Serpent(b"\x00" * 20)
    with pytest.raises(ValueError):
        CAST256(b"\x00" * 17)
    cipher = get_cipher("twofish", b"\x89" * 16)
    assert cipher.block_size == BLOCK_SIZE
    assert cipher.key_size == 16
    with pytest.raises(ValueError):
        cipher.encrypt_block(b"\x00" * 15)
    # one-shot helper agrees with the class
    assert encrypt_block("twofish", b"\x89" * 16, b"\x00" * 16) == Twofish(b"\x89" * 16).encrypt_block(
        b"\x00" * 16
    )


# ---------------------------------------------------------------------------
# libgcrypt cross-check
# ---------------------------------------------------------------------------
# Legacy static ids (pre-1.11 libgcrypt and pt9.py's _CIPHER_IDS); newer
# libgcrypt builds renumber the algorithms, so we resolve names dynamically
# and fall back to these.
_LEGACY_GCRY_IDS = {
    b"TWOFISH": 10,
    b"SERPENT128": 12,
    b"SERPENT192": 13,
    b"SERPENT256": 14,
}


class _Gcrypt:
    """Minimal ctypes wrapper around libgcrypt's ECB block encrypt."""

    def __init__(self) -> None:
        self.lib = ctypes.CDLL("libgcrypt.so.20")
        self.lib.gcry_check_version.restype = ctypes.c_char_p
        self.lib.gcry_check_version(None)
        self.lib.gcry_cipher_open.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        self.lib.gcry_cipher_setkey.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self.lib.gcry_cipher_encrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self.lib.gcry_cipher_map_name.argtypes = [ctypes.c_char_p]
        self.lib.gcry_cipher_map_name.restype = ctypes.c_int

    def algo_id(self, name: bytes) -> int:
        algo = self.lib.gcry_cipher_map_name(name)
        return algo if algo != 0 else _LEGACY_GCRY_IDS[name]

    def encrypt_block(self, name: bytes, key: bytes, block: bytes) -> bytes:
        handle = ctypes.c_void_p()
        assert self.lib.gcry_cipher_open(ctypes.byref(handle), self.algo_id(name), 1, 0) == 0
        try:
            assert self.lib.gcry_cipher_setkey(handle, key, len(key)) == 0
            out = ctypes.create_string_buffer(BLOCK_SIZE)
            assert self.lib.gcry_cipher_encrypt(handle, out, BLOCK_SIZE, block, BLOCK_SIZE) == 0
            return out.raw
        finally:
            self.lib.gcry_cipher_close(handle)


def _load_gcrypt() -> _Gcrypt | None:
    try:
        return _Gcrypt()
    except OSError:
        return None


def _libgcrypt_encrypts(name: bytes, key_len: int) -> bool:
    """Whether this libgcrypt build accepts the algorithm and key size."""
    gc = _load_gcrypt()
    if gc is None:
        return False
    try:
        gc.encrypt_block(name, b"\x00" * key_len, b"\x00" * BLOCK_SIZE)
    except (AssertionError, ValueError):
        return False
    return True


_GCRYPT_GRID_PARAMS = [
    pytest.param("twofish", b"TWOFISH", 16, id="twofish-128"),
    pytest.param("twofish", b"TWOFISH", 24, id="twofish-192"),
    pytest.param("twofish", b"TWOFISH", 32, id="twofish-256"),
    pytest.param("serpent128", b"SERPENT128", 16, id="serpent-128"),
    pytest.param("serpent192", b"SERPENT192", 24, id="serpent-192"),
    pytest.param("serpent256", b"SERPENT256", 32, id="serpent-256"),
]


@pytest.mark.parametrize(("cipher_name", "gcry_name", "key_len"), _GCRYPT_GRID_PARAMS)
def test_libgcrypt_random_grid(
    cipher_name: str, gcry_name: bytes, key_len: int
) -> None:
    """200 random key/plaintext pairs per key size match libgcrypt ECB.

    libgcrypt only implements Twofish with 16- and 32-byte keys (its
    ``gcry_cipher_setkey`` rejects 192-bit Twofish keys), so that cell of the
    grid is skipped and pinned by the KATs instead.
    """
    gc = _load_gcrypt()
    if gc is None:
        pytest.skip("libgcrypt is not available")
    if not _libgcrypt_encrypts(gcry_name, key_len):
        pytest.skip(
            f"this libgcrypt build does not accept {gcry_name.decode()} with a "
            f"{key_len}-byte key"
        )
    rng = random.Random(f"{cipher_name}/{key_len}")
    for _ in range(200):
        key = rng.randbytes(key_len)
        block = rng.randbytes(BLOCK_SIZE)
        mine = get_cipher(cipher_name, key).encrypt_block(block)
        theirs = gc.encrypt_block(gcry_name, key, block)
        assert mine == theirs, (
            f"mismatch for {cipher_name} key={key.hex()} block={block.hex()}: "
            f"{mine.hex()} != {theirs.hex()}"
        )


# ---------------------------------------------------------------------------
# end-to-end container equivalence against pt9.py
# ---------------------------------------------------------------------------
def _load_pt9() -> types.ModuleType | None:
    """Import packet-tracer-pkt-format/pt9.py (the libgcrypt reference)."""
    if not PT9_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("pt9_reference", PT9_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:  # pragma: no cover - pt9 raises without libgcrypt
        return None
    return module


def _layer_a(buf: bytes) -> bytes:
    """pt9.py layer A: file bytes -> AEAD ciphertext bytes."""
    n = len(buf)
    return bytes(buf[n - 1 - i] ^ ((n * (1 - i)) & 0xFF) for i in range(n))


def _layer_b(buf: bytes) -> bytes:
    """Util::deobfuscateBytes: self-inverse XOR with (len - i)."""
    return bytes(v ^ ((len(buf) - i) & 0xFF) for i, v in enumerate(buf))


def _pure_eax_decrypt(
    key: bytes, iv: bytes, data: bytes
) -> tuple[bytes, bytes, bytes]:
    """Crypto++-variant EAX open using pure-Python Twofish (as in pt9.py)."""
    cipher = Twofish(key)

    def enc(block: bytes) -> bytes:
        return cipher.encrypt_block(block)

    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(p ^ q for p, q in zip(a, b))

    def subkeys() -> tuple[bytes, bytes]:
        l = int.from_bytes(enc(b"\x00" * BLOCK_SIZE), "big")
        k1 = ((l << 1) ^ (0x87 if l >> 127 else 0)) & ((1 << 128) - 1)
        k1b = k1.to_bytes(16, "big")
        k2 = ((k1 << 1) ^ (0x87 if k1 >> 127 else 0)) & ((1 << 128) - 1)
        return k1b, k2.to_bytes(16, "big")

    def cmac(msg: bytes) -> bytes:
        k1, k2 = subkeys()
        n = max(1, (len(msg) + 15) // 16)
        complete = len(msg) > 0 and len(msg) % 16 == 0
        last = msg[(n - 1) * 16 :]
        if complete:
            last = xor(last, k1)
        else:
            last = xor(last + b"\x80" + b"\x00" * (15 - len(last)), k2)
        state = b"\x00" * BLOCK_SIZE
        for i in range(n - 1):
            state = enc(xor(state, msg[i * 16 : (i + 1) * 16]))
        return enc(xor(state, last))

    def ctr(nonce: bytes, payload: bytes) -> bytes:
        out = bytearray()
        counter = int.from_bytes(nonce, "big")
        for i in range(0, len(payload), 16):
            ks = enc((counter & ((1 << 128) - 1)).to_bytes(16, "big"))
            blk = payload[i : i + 16]
            out += xor(blk, ks[: len(blk)])
            counter += 1
        return bytes(out)

    body, tag = data[:-BLOCK_SIZE], data[-BLOCK_SIZE:]
    nonce = cmac(b"\x00" * BLOCK_SIZE + iv)
    plaintext = ctr(nonce, body)
    m1 = cmac(b"\x00" * 15 + b"\x02" + body)
    m2 = cmac(b"\x00" * 15 + b"\x01")
    computed = xor(xor(nonce, m1), m2)
    return plaintext, computed, tag


def _pure_decode_pkt(raw: bytes) -> bytes:
    """Decode a .pkt/.pka container with pure-Python Twofish only."""
    key = bytes([_PKT_KEY_BYTE]) * BLOCK_SIZE
    iv = bytes([_PKT_IV_BYTE]) * BLOCK_SIZE
    ct = _layer_a(raw)
    plaintext, computed, stored = _pure_eax_decrypt(key, iv, ct)
    assert computed == stored, "EAX tag mismatch"
    payload = _layer_b(plaintext)
    length = struct.unpack(">I", payload[:4])[0]
    xml = zlib.decompress(payload[4:])
    assert length == len(xml)
    return xml


def _ok_corpus_files() -> list[Path]:
    """First five corpus files whose CORPUS_INDEX.tsv decode_status is OK.

    The index is read with csv.DictReader (tab separated) because the
    filenames contain spaces and must never be shell-split.
    """
    if not CORPUS_INDEX.is_file():
        return []
    chosen: list[Path] = []
    with CORPUS_INDEX.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            if row.get("decode_status") != "OK":
                continue
            path = CORPUS_FILES_DIR / row["filename"]
            if path.is_file():
                chosen.append(path)
            if len(chosen) == 5:
                break
    return chosen


@pytest.mark.corpus
def test_container_end_to_end_equivalence() -> None:
    """Real .pkt files decode to byte-identical XML: pure-Python Twofish vs
    pt9.py (libgcrypt Twofish) — the strongest end-to-end proof.

    Prints per-file and total wall time so the corpus-wide test can be sized.
    """
    pt9 = _load_pt9()
    if pt9 is None:
        pytest.skip("pt9.py is unavailable or its libgcrypt backend failed to load")
    files = _ok_corpus_files()
    if len(files) < 5:
        pytest.skip("corpus index / files are unavailable")

    total = 0.0
    total_xml = 0
    for path in files:
        raw = path.read_bytes()
        start = time.perf_counter()
        mine = _pure_decode_pkt(raw)
        elapsed = time.perf_counter() - start
        total += elapsed
        total_xml += len(mine)
        reference = pt9.decode(path, "pkt")  # libgcrypt Twofish via EAX/CMAC/CTR
        assert mine == reference, (
            f"{path.name}: pure-Python Twofish decode diverges from pt9.py "
            f"({len(mine)} vs {len(reference)} XML bytes)"
        )
        print(
            f"[e2e] {path.name}: {len(raw)} file bytes -> {len(mine)} XML bytes "
            f"in {elapsed:.2f}s (pure-Python Twofish)"
        )
    print(
        f"[e2e] TOTAL: 5 files, {total_xml} XML bytes decoded in {total:.2f}s "
        f"({total / 5:.2f}s/file)"
    )
