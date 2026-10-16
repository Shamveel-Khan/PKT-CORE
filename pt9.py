#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
pt9.py -- complete reader/writer for Cisco Packet Tracer 9 `.pkt` / `.pka` files.

Interoperability tool: read and re-create the files *your own* Packet Tracer
installation produces, as plain XML.

Reverse engineered from PacketTracer 9.0.1.0858 (x86-64).  The container is:

    file bytes
      |  decode layer A  : bytes[i] = file[n-1-i] ^ ((n*(1-i)) & 0xff)
      v
      AEAD ciphertext || 16-byte tag   (Crypto++ EAX)
      |  AEAD decrypt (Twofish/Serpent/CAST256, fixed key + IV)
      v
      |  Util::deobfuscateBytes : bytes[i] ^= ((len - i) & 0xff)
      v
      |  qCompress framing : 4-byte big-endian length + zlib stream
      v
    UTF-8 XML  ("<PACKETTRACER5>...</PACKETTRACER5>")

EAX details (Crypto++ variant):
    N        = CMAC_K(0^128 || IV)                  # CTR nonce
    keystream= CTR_N, big-endian full-block counter
    tag      = N ^ CMAC_K(0x02-block || ct) ^ CMAC_K(0x01-block)

Both directions are byte-exact: `encode(decode(f)) == f`.

Requires `libgcrypt` for the block cipher (Twofish/Serpent); on Debian/Ubuntu
`sudo apt install libgcrypt20`.  CAST256 (used by two internal formats) is not
in libgcrypt and is not supported yet.

Usage:
    python3 pt9.py info   FILE                 # decrypt + summarise
    python3 pt9.py decode FILE [-o OUT.xml]    # .pkt/.pka -> XML
    python3 pt9.py encode FILE (--format pkt)  # XML -> .pkt/.pka

Published for interoperability / format documentation.  Do not use it to
tamper with assessment or competition files.
"""
from __future__ import annotations

import argparse
import ctypes
import struct
import sys
import zlib

__all__ = [
    "FORMATS", "decode_bytes", "decode", "encode_bytes", "encode",
    "PacketTracerError",
]

BLOCK = 16


class PacketTracerError(Exception):
    pass


# --------------------------------------------------------------------------
# libgcrypt block-cipher backend
# --------------------------------------------------------------------------
try:
    _g = ctypes.CDLL("libgcrypt.so.20")
except OSError:  # pragma: no cover - platform dependent
    try:
        _g = ctypes.CDLL("libgcrypt.so")
    except OSError as exc:  # pragma: no cover
        raise PacketTracerError(
            "libgcrypt not found (install libgcrypt20 / libgcrypt)"
        ) from exc

_g.gcry_check_version.restype = ctypes.c_char_p
_g.gcry_check_version(None)
_g.gcry_cipher_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_int, ctypes.c_uint]
_g.gcry_cipher_setkey.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
_g.gcry_cipher_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]

# NOTE: libgcrypt 1.12 renumbered its static cipher ids (SERPENT128/192/256 are
# now 304/305/306, not 12/13/14; TWOFISH128 is 303).  Never hard-code them --
# resolve through gcry_cipher_map_name at runtime instead.
_g.gcry_cipher_map_name.restype = ctypes.c_int
_g.gcry_cipher_map_name.argtypes = [ctypes.c_char_p]

_GCRY_ECB = 1
_CIPHER_NAMES = ("twofish", "serpent128", "serpent192", "serpent256", "aes")


def _cipher_id(name):
    """Resolve a cipher name to this libgcrypt build's id (0 = unavailable)."""
    return int(_g.gcry_cipher_map_name(name.encode("ascii")))


def cipher_available(name):
    """True if this libgcrypt build can open the named block cipher."""
    cid = _cipher_id(name)
    if not cid:
        return False
    h = ctypes.c_void_p()
    return _g.gcry_cipher_open(ctypes.byref(h), cid, _GCRY_ECB, 0) == 0


def _block_cipher(name, key):
    cid = _cipher_id(name)
    if not cid:
        raise PacketTracerError(
            f"unsupported cipher {name!r} in this libgcrypt build"
        )
    h = ctypes.c_void_p()
    if _g.gcry_cipher_open(ctypes.byref(h), cid, _GCRY_ECB, 0) != 0:
        raise PacketTracerError("gcry_cipher_open failed")
    if _g.gcry_cipher_setkey(h, key, len(key)) != 0:
        raise PacketTracerError("gcry_cipher_setkey failed")

    def enc(block):
        out = ctypes.create_string_buffer(BLOCK)
        if _g.gcry_cipher_encrypt(h, out, BLOCK, block, BLOCK) != 0:
            raise PacketTracerError("gcry_cipher_encrypt failed")
        return out.raw
    return enc


def _xor(a, b):
    return bytes(p ^ q for p, q in zip(a, b))


# --------------------------------------------------------------------------
# CMAC (RFC 4493)
# --------------------------------------------------------------------------
def _subkeys(E):
    L = E(b"\x00" * BLOCK)
    k1 = (int.from_bytes(L, "big") << 1) & ((1 << 128) - 1)
    if L[0] & 0x80:
        k1 ^= 0x87
    k1 = k1.to_bytes(16, "big")
    k2 = (int.from_bytes(k1, "big") << 1) & ((1 << 128) - 1)
    if k1[0] & 0x80:
        k2 ^= 0x87
    return k1, k2.to_bytes(16, "big")


def _cmac(E, msg, subkeys):
    k1, k2 = subkeys
    n = max(1, (len(msg) + 15) // 16)
    complete = len(msg) > 0 and len(msg) % 16 == 0
    last = msg[(n - 1) * 16:]
    last = _xor(last, k1) if complete else _xor(last + b"\x80" + b"\x00" * (15 - len(last)), k2)
    state = b"\x00" * BLOCK
    for i in range(n - 1):
        state = E(_xor(state, msg[i * 16:(i + 1) * 16]))
    return E(_xor(state, last))


def _ctr(E, nonce, data):
    out = bytearray()
    counter = int.from_bytes(nonce, "big")
    for i in range(0, len(data), 16):
        ks = E((counter & ((1 << 128) - 1)).to_bytes(16, "big"))
        blk = data[i:i + 16]
        out += _xor(blk, ks[:len(blk)])
        counter += 1
    return bytes(out)


# --------------------------------------------------------------------------
# EAX (Crypto++ variant)
# --------------------------------------------------------------------------
def _eax_decrypt(cipher_name, key, iv, data):
    """data = ct || tag.  Returns (plaintext, computed_tag, stored_tag)."""
    E = _block_cipher(cipher_name, key)
    sk = _subkeys(E)
    body, tag = data[:-16], data[-16:]
    nonce = _cmac(E, b"\x00" * 16 + iv, sk)
    pt = _ctr(E, nonce, body)
    m1 = _cmac(E, b"\x00" * 15 + b"\x02" + body, sk)
    m2 = _cmac(E, b"\x00" * 15 + b"\x01", sk)
    return pt, _xor(_xor(nonce, m1), m2), tag


def _eax_encrypt(cipher_name, key, iv, pt):
    """Returns ct || tag."""
    E = _block_cipher(cipher_name, key)
    sk = _subkeys(E)
    nonce = _cmac(E, b"\x00" * 16 + iv, sk)
    ct = _ctr(E, nonce, pt)
    m1 = _cmac(E, b"\x00" * 15 + b"\x02" + ct, sk)
    m2 = _cmac(E, b"\x00" * 15 + b"\x01", sk)
    return ct + _xor(_xor(nonce, m1), m2)


# --------------------------------------------------------------------------
# Obfuscation layers (both are invertible; layer B is an involution)
# --------------------------------------------------------------------------
def _layer_a(buf):
    """file -> ciphertext:  out[i] = buf[n-1-i] ^ ((n*(1-i)) & 0xff)."""
    n = len(buf)
    return bytes(buf[n - 1 - i] ^ ((n * (1 - i)) & 0xFF) for i in range(n))


def _layer_a_inv(buf):
    """ciphertext -> file (inverse of _layer_a)."""
    n = len(buf)
    return bytes(buf[n - 1 - j] ^ ((n * (1 - (n - 1 - j))) & 0xFF) for j in range(n))


def _layer_b(buf):
    """Util::deobfuscateBytes:  buf[i] ^= ((len - i) & 0xff).  Self-inverse."""
    return bytes(v ^ ((len(buf) - i) & 0xFF) for i, v in enumerate(buf))


# --------------------------------------------------------------------------
# Format table: (cipher, key byte, iv byte) -- each repeated 16x
# --------------------------------------------------------------------------
FORMATS = {
    "pkt": ("twofish",    0x89, 0x10),  # Util::encrypt/decryptPTSave  (.pkt, .pka)
    "log": ("twofish",    0xba, 0xbe),  # Util::encrypt/decryptLog
    "pkc": ("serpent128", 0xab, 0x23),  # Util::encrypt/decryptPKCSave
    "pta": ("serpent128", 0xab, 0xcd),  # Util::encrypt/decryptPta
    # "sm" / "userapp" use CAST256 (0x12/0xfe, 0xf1/0x1f), not in libgcrypt
}


def _quncompress(payload):
    if len(payload) < 4:
        raise PacketTracerError("payload too short for qCompress header")
    length = struct.unpack(">I", payload[:4])[0]
    xml = zlib.decompress(payload[4:])
    if length != len(xml):
        raise PacketTracerError(f"qCompress length mismatch ({length} != {len(xml)})")
    return xml


def _qcompress(xml, level=-1):
    return struct.pack(">I", len(xml)) + zlib.compress(xml, level)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def decode_bytes(raw, fmt="pkt", verify_tag=True):
    """Decrypt a PT9 container and return the decompressed XML bytes."""
    cipher, kb, vb = FORMATS[fmt]
    ct = _layer_a(raw)
    pt, computed, stored = _eax_decrypt(cipher, bytes([kb]) * 16, bytes([vb]) * 16, ct)
    if verify_tag and computed != stored:
        raise PacketTracerError("EAX tag mismatch (wrong format or corrupted file)")
    return _quncompress(_layer_b(pt))


def decode(path, fmt="pkt", verify_tag=True):
    with open(path, "rb") as fh:
        return decode_bytes(fh.read(), fmt, verify_tag)


def encode_bytes(xml, fmt="pkt"):
    """Build a PT9 container from XML bytes."""
    cipher, kb, vb = FORMATS[fmt]
    payload = _layer_b(_qcompress(xml))
    sealed = _eax_encrypt(cipher, bytes([kb]) * 16, bytes([vb]) * 16, payload)
    return _layer_a_inv(sealed)


def encode(path, xml, fmt="pkt"):
    with open(path, "wb") as fh:
        fh.write(encode_bytes(xml, fmt))


def _root_tag(xml):
    s = xml[:400].decode("utf-8", "replace")
    start = s.find("<")
    end = s.find(">", start)
    return s[start + 1:end].split()[0] if start >= 0 and end > start else "?"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read/write Cisco Packet Tracer 9 .pkt/.pka files")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("decode", help=".pkt/.pka -> XML")
    p.add_argument("file")
    p.add_argument("-o", "--output")
    p.add_argument("--format", default="pkt", choices=sorted(FORMATS))
    p.add_argument("--no-verify", action="store_true")

    p = sub.add_parser("encode", help="XML -> .pkt/.pka")
    p.add_argument("file", help="input XML file")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--format", default="pkt", choices=sorted(FORMATS))

    p = sub.add_parser("info", help="decrypt and summarise")
    p.add_argument("file")
    p.add_argument("--format", default="pkt", choices=sorted(FORMATS))

    args = ap.parse_args(argv)
    try:
        if args.cmd == "encode":
            with open(args.file, "rb") as fh:
                data = fh.read()
            encode(args.output, data, args.format)
            print(f"wrote {len(data)} bytes of XML -> {args.output}", file=sys.stderr)
            return 0

        xml = decode(args.file, args.format, verify_tag=not getattr(args, "no_verify", False))
        if args.cmd == "info":
            print(f"file      : {args.file}")
            print(f"format    : {args.format}")
            print(f"root tag  : {_root_tag(xml)}")
            print(f"xml bytes : {len(xml)}")
        elif args.output:
            with open(args.output, "wb") as fh:
                fh.write(xml)
            print(f"wrote {len(xml)} bytes to {args.output}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(xml)
        return 0
    except (PacketTracerError, OSError, zlib.error) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
