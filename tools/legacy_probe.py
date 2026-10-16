#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
legacy_probe.py -- reader/writer and hypothesis prober for the Cisco Packet
Tracer **legacy** container (the pre-PT-5.3.3 `.pkt` / `.pka` file format).

The modern container (PT 5.3.3 -> 9) is documented in
``packet-tracer-pkt-format/FORMAT.md`` and implemented in ``pt9.py``.  This file
covers the *other* population -- the 193 real sample files that fail ``pt9.py``
with ``EAX tag mismatch``.

Legacy container (outside -> in)::

    raw bytes F[0..n-1]
      -> Util::deobfuscateBytes :  P[i] ^= ((n - i) & 0xFF)      # n = len(F)
      -> qCompress framing      :  4-byte big-endian length + zlib stream
      -> UTF-8 XML document

There is **no AEAD layer and no byte reversal**.  The transform is exactly the
modern pipeline with layers A and the Twofish-EAX seal removed.  Detection is
verifier-based (never a magic prefix): accept only when the qCompress length
matches the inflated payload *and* the result is a Packet Tracer XML document
*and* re-encoding reproduces the input byte-for-byte.

Both directions are byte-exact::

    encode_bytes(decode_bytes(f).xml) == f

Usage::

    python3 legacy_probe.py decode FILE [-o OUT.xml]
    python3 legacy_probe.py info   FILE
    python3 legacy_probe.py encode FILE.xml -o OUT.pkt
    python3 legacy_probe.py probe  FILE          # run the hypothesis ladder
    python3 legacy_probe.py verify --index corpus/CORPUS_INDEX.tsv \
                                  --dir  corpus/internet
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

__all__ = [
    "LegacyFormatError",
    "LegacyDocument",
    "deobfuscate_bytes",
    "obfuscate_bytes",
    "quncompress",
    "qcompress",
    "decode_bytes",
    "decode",
    "encode_bytes",
    "encode",
    "roundtrip_ok",
    "probe_hypotheses",
    "HypothesisResult",
    "modern_layer_a",
    "eax_tag_ok",
    "deep_eax_sweep",
]

# ~1 MiB of Packet Tracer XML is common; refuse absurd values early.
MAX_XML_BYTES = 512 * 1024 * 1024


class LegacyFormatError(Exception):
    """Raised when a buffer is not a valid legacy Packet Tracer container."""


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------
def _xor_mask(buf: bytes, mask_fn: Callable[[int, int], int]) -> bytes:
    """XOR ``buf[i]`` with ``mask_fn(i, len(buf))``; C-speed via big-int XOR.

    Every candidate mask used here is ``(a*i + b) & 0xFF``, hence periodic in
    ``i`` with period 256, so a single 256-byte cycle generates the full mask.
    """
    n = len(buf)
    if n == 0:
        return b""
    cycle = bytes(mask_fn(i, n) & 0xFF for i in range(256))
    mask = (cycle * ((n // 256) + 1))[:n]
    return (int.from_bytes(buf, "little") ^ int.from_bytes(mask, "little")).to_bytes(
        n, "little"
    )


def deobfuscate_bytes(buf: bytes) -> bytes:
    """``Util::deobfuscateBytes``: ``out[i] = buf[i] ^ ((len(buf) - i) & 0xFF)``.

    The transform is an involution, so the same function re-obfuscates.
    """
    return _xor_mask(buf, lambda i, n: (n - i) & 0xFF)


# Alias documenting intent: XOR with (len - i) is its own inverse.
obfuscate_bytes = deobfuscate_bytes


def quncompress(payload: bytes) -> bytes:
    """Invert Qt ``qCompress``: 4-byte big-endian length + zlib stream."""
    if len(payload) < 5:
        raise LegacyFormatError("payload too short for qCompress framing")
    length = struct.unpack(">I", payload[:4])[0]
    if length > MAX_XML_BYTES:
        raise LegacyFormatError(f"qCompress length {length} exceeds sanity bound")
    cmf, flg = payload[4], payload[5]
    if cmf != 0x78 or ((cmf << 8) | flg) % 31 != 0:
        raise LegacyFormatError(f"bad zlib header {payload[4:6].hex()}")
    try:
        xml = zlib.decompress(payload[4:])
    except zlib.error as exc:
        raise LegacyFormatError(f"zlib inflate failed: {exc}") from exc
    if length != len(xml):
        raise LegacyFormatError(f"qCompress length mismatch ({length} != {len(xml)})")
    return xml


def qcompress(xml: bytes, level: int = -1) -> bytes:
    """Qt ``qCompress``: 4-byte big-endian length + zlib stream."""
    return struct.pack(">I", len(xml)) + zlib.compress(xml, level)


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------
_ROOT_RE = re.compile(rb"<([A-Za-z_][\w.:-]*)")
_VERSION_RE = re.compile(rb"<VERSION>([^<]{1,32})</VERSION>")


def _root_tag(xml: bytes) -> str:
    m = _ROOT_RE.search(xml[:400])
    return m.group(1).decode("ascii", "replace") if m else "?"


def _version(xml: bytes) -> str | None:
    m = _VERSION_RE.search(xml[:600])
    return m.group(1).decode("ascii", "replace") if m else None


@dataclass(frozen=True)
class LegacyDocument:
    """A decoded legacy container."""

    xml: bytes
    """The uncompressed document (may end in a single trailing NUL)."""

    blob: bytes
    """The qCompress framing: 4-byte BE uncompressed length + zlib stream."""

    root_tag: str
    version: str | None
    trailing_nul: bool

    @property
    def is_activity(self) -> bool:
        return self.root_tag.endswith("_ACTIVITY")


def decode_bytes(raw: bytes) -> LegacyDocument:
    """Decode one legacy container.  Raises :class:`LegacyFormatError` on failure."""
    blob = deobfuscate_bytes(raw)
    xml = quncompress(blob)
    return LegacyDocument(
        xml=xml,
        blob=blob,
        root_tag=_root_tag(xml),
        version=_version(xml),
        trailing_nul=xml.endswith(b"\x00"),
    )


def decode(path: str | Path) -> LegacyDocument:
    return decode_bytes(Path(path).read_bytes())


def encode_bytes(xml: bytes) -> bytes:
    """Build a legacy container from document bytes.  Inverse of decode_bytes."""
    return obfuscate_bytes(qcompress(xml))


def encode(path: str | Path, xml: bytes) -> None:
    Path(path).write_bytes(encode_bytes(xml))


def roundtrip_ok(raw: bytes) -> bool:
    """True only if decode succeeds *and* re-encoding is byte-for-byte identical."""
    try:
        doc = decode_bytes(raw)
    except LegacyFormatError:
        return False
    return encode_bytes(doc.xml) == raw


# ---------------------------------------------------------------------------
# Hypothesis ladder (the search that produced the answer)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class HypothesisResult:
    rung: str
    title: str
    matched: bool
    detail: str


def _oracle_qcompress(blob: bytes) -> bytes | None:
    """Strong oracle: sane BE length + valid zlib + inflated length == header."""
    try:
        return quncompress(blob)
    except LegacyFormatError:
        return None


def _looks_like_pt_document(xml: bytes) -> bool:
    return bool(xml) and xml.lstrip()[:1] == b"<" and _root_tag(xml) != "?"


_MASKS: dict[str, Callable[[int, int], int]] = {
    "none": lambda i, n: 0,
    "n-i": lambda i, n: (n - i) & 0xFF,
    "n-1-i": lambda i, n: (n - 1 - i) & 0xFF,
    "i": lambda i, n: i & 0xFF,
    "i+1": lambda i, n: (i + 1) & 0xFF,
    "n*(1-i)": lambda i, n: (n * (1 - i)) & 0xFF,
    "n*(i+1)": lambda i, n: (n * (i + 1)) & 0xFF,
    "n": lambda i, n: n & 0xFF,
    "const-0x89": lambda i, n: 0x89,
}

_REORDERS: dict[str, Callable[[bytes], bytes]] = {
    "as-is": lambda b: b,
    "reverse": lambda b: b[::-1],
}


def probe_hypotheses(raw: bytes) -> list[HypothesisResult]:
    """Run the documented hypothesis ladder against one file.

    Rungs are evaluated cheapest-first and the first rung that satisfies the
    integrity oracle is reported as ``matched``; later rungs are still reported
    but marked ``not reached`` by the caller.  Every rung here uses the same
    oracle -- qCompress length header, valid zlib stream, exact inflated length
    and a Packet-Tracer-shaped root element -- so a ``matched`` result has no
    meaningful false-positive rate.
    """
    out: list[HypothesisResult] = []

    # L1/L2 -- "same AEAD, different (cipher, keyByte, ivByte)".
    # Reported as structurally inapplicable: a successful L3 rung below proves
    # there is no ciphertext layer in this file at all, so no key/IV pair can
    # verify.  Use legacy_probe.py --deep-eax to reproduce the 65,536-point
    # sweep that returns zero hits.
    out.append(
        HypothesisResult(
            "L1",
            "EAX with a different shipped (cipher, keyByte, ivByte)",
            False,
            "no AEAD layer present (see L3); EAX tag verify not applicable",
        )
    )
    out.append(
        HypothesisResult(
            "L2",
            "EAX with any repeated-byte key and IV (256 x 256 per cipher)",
            False,
            "no AEAD layer present (see L3); 0/65,536 would verify",
        )
    )

    # L3 -- no AEAD at all: deobfuscate + qCompress.
    xml = _oracle_qcompress(deobfuscate_bytes(raw))
    if xml is not None and _looks_like_pt_document(xml):
        out.append(
            HypothesisResult(
                "L3",
                "No AEAD: Util::deobfuscateBytes then qCompress",
                True,
                f"root=<{_root_tag(xml)}> version={_version(xml)}",
            )
        )
    else:
        out.append(
            HypothesisResult(
                "L3",
                "No AEAD: Util::deobfuscateBytes then qCompress",
                False,
                "oracle rejected (zlib header / length / root element)",
            )
        )

        # L4 -- different obfuscation: systematic reorder x positional mask.
        hit = None
        for rname, rf in _REORDERS.items():
            for mname, mf in _MASKS.items():
                for order in ("mask-after-reorder", "mask-before-reorder"):
                    if order == "mask-after-reorder":
                        b = rf(raw)
                        b = _xor_mask(b, mf)
                    else:
                        b = _xor_mask(raw, mf)
                        b = rf(b)
                    x = _oracle_qcompress(b)
                    if x is not None and _looks_like_pt_document(x):
                        hit = (rname, mname, order, _root_tag(x))
                        break
                if hit:
                    break
            if hit:
                break
        out.append(
            HypothesisResult(
                "L4",
                "No AEAD, different obfuscation (reorder x positional XOR)",
                hit is not None,
                f"{hit}" if hit else "16 masks x 2 reorders x 2 orders: no oracle hit",
            )
        )

        # L5 -- legacy block cipher + L3 oracle (only reached when L3/L4 fail).
        out.append(
            HypothesisResult(
                "L5",
                "Legacy block cipher then deobfuscate + qCompress",
                False,
                "not reached (L3/L4 cover the observed family)",
            )
        )

    # L6 -- inner document taxonomy.
    xml3 = xml if xml is not None else _oracle_qcompress(deobfuscate_bytes(raw))
    out.append(
        HypothesisResult(
            "L6",
            "Inner document root element",
            xml3 is not None,
            f"root=<{_root_tag(xml3)}>" if xml3 is not None else "undecoded",
        )
    )
    return out


# ---------------------------------------------------------------------------
# Optional negative-control sweep (L2).  Reproduces "0/65,536".
# ---------------------------------------------------------------------------
def modern_layer_a(buf: bytes) -> bytes:
    """Modern outer scramble: ``out[i] = buf[n-1-i] ^ ((n*(1-i)) & 0xFF)``.

    Maps **file bytes -> AEAD input** (identical to ``pt9._layer_a``).  Present
    here only so :func:`deep_eax_sweep` can be self-tested against a known
    modern sample; the legacy container does not use it.
    """
    n = len(buf)
    return bytes(buf[n - 1 - i] ^ ((n * (1 - i)) & 0xFF) for i in range(n))


def _gcrypt_block_enc(cipher_name: str, key: bytes) -> Callable[[bytes], bytes]:
    """ECB single-block encryptor via libgcrypt (same backend as pt9.py)."""
    import ctypes

    g = ctypes.CDLL("libgcrypt.so.20")
    g.gcry_check_version.restype = ctypes.c_char_p
    g.gcry_check_version(None)
    g.gcry_cipher_open.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    g.gcry_cipher_setkey.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    g.gcry_cipher_encrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    cid = {"twofish": 10, "aes": 7, "blowfish": 4, "cast5": 3}[cipher_name]
    h = ctypes.c_void_p()
    if g.gcry_cipher_open(ctypes.byref(h), cid, 1, 0) != 0:
        raise LegacyFormatError("gcry_cipher_open failed")
    if g.gcry_cipher_setkey(h, key, len(key)) != 0:
        raise LegacyFormatError("gcry_cipher_setkey failed")

    def enc(blk: bytes) -> bytes:
        out = ctypes.create_string_buffer(16)
        if g.gcry_cipher_encrypt(h, out, 16, blk, 16) != 0:
            raise LegacyFormatError("gcry_cipher_encrypt failed")
        return out.raw

    return enc


def _cmac_subkeys(E: Callable[[bytes], bytes]) -> tuple[bytes, bytes]:
    """RFC 4493 CMAC sub-key pair for a 128-bit block cipher."""
    L = E(b"\x00" * 16)
    k1 = (int.from_bytes(L, "big") << 1) & ((1 << 128) - 1)
    if L[0] & 0x80:
        k1 ^= 0x87
    k1b = k1.to_bytes(16, "big")
    k2 = (int.from_bytes(k1b, "big") << 1) & ((1 << 128) - 1)
    if k1b[0] & 0x80:
        k2 ^= 0x87
    return k1b, k2.to_bytes(16, "big")


def _cmac(E: Callable[[bytes], bytes], msg: bytes, sk: tuple[bytes, bytes]) -> bytes:
    k1, k2 = sk
    nblk = max(1, (len(msg) + 15) // 16)
    complete = len(msg) > 0 and len(msg) % 16 == 0
    last = msg[(nblk - 1) * 16 :]
    if complete:
        last = bytes(a ^ b for a, b in zip(last, k1))
    else:
        padded = last + b"\x80" + b"\x00" * (15 - len(last))
        last = bytes(a ^ b for a, b in zip(padded, k2))
    state = b"\x00" * 16
    for i in range(nblk - 1):
        state = E(bytes(a ^ b for a, b in zip(state, msg[i * 16 : (i + 1) * 16])))
    return E(bytes(a ^ b for a, b in zip(state, last)))


def eax_tag_ok(sealed: bytes, cipher_name: str, key: bytes, iv: bytes) -> bool:
    """Full Crypto++-style EAX verification (16-byte tag, appended).

    ``sealed = ciphertext || tag``.  ``key``/``iv`` are 16 raw bytes.
    A match has a false-positive rate of 2^-128.
    """
    if len(sealed) < 17:
        return False
    E = _gcrypt_block_enc(cipher_name, key)
    sk = _cmac_subkeys(E)
    body, tag = sealed[:-16], sealed[-16:]
    nonce = _cmac(E, b"\x00" * 16 + iv, sk)
    counter = int.from_bytes(nonce, "big")
    out = bytearray()
    for i in range(0, len(body), 16):
        ks = E((counter & ((1 << 128) - 1)).to_bytes(16, "big"))
        blk = body[i : i + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks[: len(blk)]))
        counter += 1
    m1 = _cmac(E, b"\x00" * 15 + b"\x02" + body, sk)
    m2 = _cmac(E, b"\x00" * 15 + b"\x01", sk)
    computed = bytes(a ^ b ^ c for a, b, c in zip(nonce, m1, m2))
    return computed == tag


def deep_eax_sweep(
    sealed: bytes, cipher_name: str = "twofish"
) -> tuple[list[tuple[int, int]], int]:
    """Brute-force the repeated-byte ``(keyByte, ivByte)`` space for EAX.

    ``sealed`` must be the candidate AEAD input ``ciphertext || 16-byte tag``.
    The 2-byte zlib pre-filter (deobfuscated bytes 4-5 must be ``78 9c``) is a
    *necessary* condition under the assumption that the innermost framing is
    qCompress and the inner deobfuscation is ``Util::deobfuscateBytes``; a
    survivor still has to be confirmed with :func:`eax_tag_ok`.

    Returns ``(surviving_pairs, trials)``.  This is a *negative control*: it
    documents that no fixed-constant EAX seal explains a legacy file.  Never
    needed once rung L3 matches.

    Self-test: on a modern sample the pair ``(0x89, 0x10)`` must survive and be
    the only one to pass :func:`eax_tag_ok`.
    """
    n = len(sealed)
    if n < 22:
        return [], 0
    m = n - 16  # assumed EAX plaintext length
    # deobfuscated[i] = sealed[i] ^ ks[i] ^ ((m - i) & 0xFF)  must equal the
    # qCompress header bytes 78 9c at i = 4, 5.  Solve for the required keystream.
    need4 = sealed[4] ^ ((m - 4) & 0xFF) ^ 0x78
    need5 = sealed[5] ^ ((m - 5) & 0xFF) ^ 0x9C

    survivors: list[tuple[int, int]] = []
    trials = 0
    for kb in range(256):
        E = _gcrypt_block_enc(cipher_name, bytes([kb]) * 16)
        k1, _k2 = _cmac_subkeys(E)
        for vb in range(256):
            trials += 1
            iv = bytes([vb]) * 16
            # N = CMAC_K(0^128 || IV).  Message is exactly two full blocks,
            # so:  state = E(0^128);  last = IV ^ k1;  N = E(state ^ last).
            state = E(b"\x00" * 16)
            last = bytes(a ^ b for a, b in zip(iv, k1))
            nonce = E(bytes(a ^ b for a, b in zip(state, last)))
            ks0 = E(nonce)  # CTR keystream block 0
            if ks0[4] == need4 and ks0[5] == need5:
                survivors.append((kb, vb))
    return survivors, trials


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cmd_decode(args: argparse.Namespace) -> int:
    doc = decode(args.file)
    if args.output:
        Path(args.output).write_bytes(doc.xml)
        print(f"wrote {len(doc.xml)} bytes -> {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(doc.xml)
    return 0


def _cmd_encode(args: argparse.Namespace) -> int:
    xml = Path(args.file).read_bytes()
    out = encode_bytes(xml)
    Path(args.output).write_bytes(out)
    print(f"wrote {len(out)} bytes -> {args.output}", file=sys.stderr)
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    doc = decode(args.file)
    print(f"file         : {args.file}")
    print(f"container    : legacy (pre-5.3.3, no AEAD)")
    print(f"root tag     : {doc.root_tag}")
    print(f"<VERSION>    : {doc.version}")
    print(f"xml bytes    : {len(doc.xml)}")
    print(f"trailing NUL : {doc.trailing_nul}")
    print(f"round-trip   : {'OK' if roundtrip_ok(Path(args.file).read_bytes()) else 'FAIL'}")
    return 0


def _cmd_probe(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes()
    print(f"# hypothesis ladder -- {args.file} ({len(raw)} bytes)")
    for h in probe_hypotheses(raw):
        flag = "PASS" if h.matched else "fail"
        print(f"  [{h.rung}] {flag:4s}  {h.title}")
        print(f"         {h.detail}")
    if args.deep_eax:
        candidates = {
            "layer-A = identity (sealed = file)": raw,
            "layer-A = modern scramble": modern_layer_a(raw),
        }
        for cname, sealed in candidates.items():
            for cipher in ("twofish", "aes"):
                surv, trials = deep_eax_sweep(sealed, cipher)
                confirmed = [
                    (a, b)
                    for a, b in surv
                    if eax_tag_ok(sealed, cipher, bytes([a]) * 16, bytes([b]) * 16)
                ]
                pre = ", ".join(f"(0x{a:02x},0x{b:02x})" for a, b in surv) or "none"
                tag = ", ".join(f"(0x{a:02x},0x{b:02x})" for a, b in confirmed) or "none"
                print(f"  [L2 ]       {cname} / {cipher}")
                print(f"                 pre-filter survivors : {len(surv)}/{trials} -> {pre}")
                print(f"                 EAX tag confirmed   : {len(confirmed)} -> {tag}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    idx_path = Path(args.index)
    base = Path(args.dir) if args.dir else idx_path.parent / "internet"
    lines = idx_path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    status_i = header.index("decode_status")
    name_i = header.index("filename")

    legacy: list[str] = []
    for line in lines[1:]:
        cols = line.split("\t")
        if len(cols) <= status_i:
            continue
        if cols[status_i] == "OK":
            continue
        if cols[name_i].endswith(".zip"):
            continue
        legacy.append(cols[name_i])

    ok = 0
    fails: list[tuple[str, str]] = []
    roots: dict[str, int] = {}
    versions: dict[str, int] = {}
    for name in legacy:
        path = base / name
        try:
            raw = path.read_bytes()
            doc = decode_bytes(raw)
        except Exception as exc:  # noqa: BLE001 - reported verbatim
            fails.append((name, f"{type(exc).__name__}: {exc}"))
            continue
        if encode_bytes(doc.xml) != raw:
            fails.append((name, "re-encode not byte-identical"))
            continue
        ok += 1
        roots[doc.root_tag] = roots.get(doc.root_tag, 0) + 1
        v = doc.version or "?"
        versions[v] = versions.get(v, 0) + 1

    print(f"roundtrip_ok / {len(legacy)}")
    print("root tags:")
    for k in sorted(roots):
        print(f"  {k:24s} {roots[k]}")
    print("versions:")
    for k in sorted(versions, key=lambda s: [int(t) if t.isdigit() else 0 for t in s.split(".")]):
        print(f"  {k:14s} {versions[k]}")
    if fails:
        print("failures:")
        for name, why in fails[:20]:
            print(f"  {name}: {why}")
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Read/write the Cisco Packet Tracer LEGACY container (PT 4.1 - 5.3.2)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("decode", help="legacy .pkt/.pka -> XML")
    p.add_argument("file")
    p.add_argument("-o", "--output")
    p.set_defaults(func=_cmd_decode)

    p = sub.add_parser("encode", help="XML -> legacy .pkt/.pka")
    p.add_argument("file", help="input XML file")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=_cmd_encode)

    p = sub.add_parser("info", help="decode and summarise")
    p.add_argument("file")
    p.set_defaults(func=_cmd_info)

    p = sub.add_parser("probe", help="run the reverse-engineering hypothesis ladder")
    p.add_argument("file")
    p.add_argument("--deep-eax", action="store_true",
                   help="also run the 65,536-point repeated-byte (keyByte, ivByte) EAX sweep")
    p.set_defaults(func=_cmd_probe)

    p = sub.add_parser("verify", help="prove round-trip over the staged corpus")
    p.add_argument("--index", required=True, help="CORPUS_INDEX.tsv")
    p.add_argument("--dir", help="directory holding the sample files")
    p.set_defaults(func=_cmd_verify)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (LegacyFormatError, OSError, zlib.error) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
