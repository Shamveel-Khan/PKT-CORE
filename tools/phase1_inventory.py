#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
"""Phase 1 telemetry: hash, size, entropy, and header signature inventory.

Scans every candidate Packet Tracer container (``.pkt`` / ``.pka``) and emits a
machine-readable inventory plus a Markdown corpus report.

Usage:
    python3 tools/phase1_inventory.py --root ../filedrop --out ../filedrop/CORPUS_REPORT.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

SUFFIXES = {".pkt", ".pka", ".pkt.pka"}


@dataclass
class SampleRecord:
    path: str
    name: str
    suffix: str
    size: int
    sha256: str
    head_hex: str
    tail_hex: str
    entropy: float
    printable_ratio: float
    magic_guess: str
    notes: list[str] = field(default_factory=list)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D)) / len(data)


def guess_magic(data: bytes, suffix: str) -> str:
    """Classify the leading bytes of a candidate container.

    Entropy is used to gate the ASCII-magic heuristic: the modern Packet Tracer
    container is ciphertext and therefore entropy ~8.0, so any printable run it
    happens to contain is coincidence and must NOT be reported as a magic.
    """
    if not data:
        return "empty"
    head = data[:32]
    # --- deterministic structural signatures (checked before entropy) ---
    if head[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        return "zlib-stream"
    if len(data) > 5:
        qbe = int.from_bytes(head[:4], "big")
        if head[4:6] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda") and 0 < qbe < 512 * 1024 * 1024:
            return "qt-qcompress"
    if head[:2] == b"PK":
        return "zip-pkzip"
    if head[:4] == b"\x1f\x8b\x08\x00" or head[:3] == b"\x1f\x8b\x08":
        return "gzip"
    if head[:5] == b"<?xml" or head[:9] == b"<PACKETTR":
        return "raw-xml"
    if head[:3] == b"\x89PN":
        return "png"

    # --- entropy-gated textual heuristic ---
    ent = shannon_entropy(data[:65536])
    if ent >= 7.2:
        # Ciphertext: no readable magic is meaningful here.
        return "opaque-encrypted"

    ascii_prefix = bytes(b for b in head[:16] if 0x20 <= b < 0x7F)
    if len(ascii_prefix) >= 4:
        return f"ascii-magic:{ascii_prefix[:12].decode('ascii', 'replace')}"
    return "opaque-encrypted"


def record_for(path: Path) -> SampleRecord:
    try:
        data = path.read_bytes()
    except OSError as exc:
        # Record the failure rather than aborting the whole inventory run.
        return SampleRecord(
            path=str(path),
            name=path.name,
            suffix="".join(path.suffixes) if path.name.lower().endswith(".pkt.pka") else path.suffix,
            size=-1,
            sha256="",
            head_hex="",
            tail_hex="",
            entropy=0.0,
            printable_ratio=0.0,
            magic_guess="unreadable",
            notes=[f"read-failed:{exc.strerror or exc}"],
        )

    digest = hashlib.sha256(data).hexdigest()
    notes: list[str] = []

    tail = data[-16:]
    # Sanity notes
    if len(data) < 1024:
        notes.append("tiny-file")
    if shannon_entropy(data[:65536]) > 7.5:
        notes.append("high-entropy")
    if b"PACKETTRACER" in data[:4096]:
        notes.append("plaintext-root-visible")
    if data[:2] == b"\x78\x9c":
        notes.append("starts-as-zlib")

    return SampleRecord(
        path=str(path),
        name=path.name,
        suffix="".join(path.suffixes) if path.name.lower().endswith(".pkt.pka") else path.suffix,
        size=len(data),
        sha256=digest,
        head_hex=data[:32].hex(" "),
        tail_hex=tail.hex(" "),
        entropy=round(shannon_entropy(data[:65536]), 4),
        printable_ratio=round(printable_ratio(data[:65536]), 4),
        magic_guess=guess_magic(data, path.suffix),
        notes=notes,
    )


def iter_samples(roots: Iterable[Path]) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        if root.is_file():
            found.append(root)
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                low = fn.lower()
                if low.endswith(".pkt") or low.endswith(".pka"):
                    found.append(Path(dirpath) / fn)
    return sorted(set(found))


def render_markdown(records: list[SampleRecord], sources: list[str]) -> str:
    magic_counts = Counter(r.magic_guess for r in records)
    ext_counts = Counter(r.suffix.lower() for r in records)
    total_bytes = sum(max(r.size, 0) for r in records)
    unreadable = [r for r in records if r.magic_guess == "unreadable"]

    lines: list[str] = []
    lines.append("# Packet Tracer Corpus Report — Phase 1 Ingestion & Telemetry")
    lines.append("")
    lines.append("Generated by `tools/phase1_inventory.py`. Every sample is identified by "
                 "SHA-256; header signatures are reported as observed raw bytes (no guessing).")
    lines.append("")
    lines.append("## 1. Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"| --- | --- |")
    lines.append(f"| Sample files discovered | **{len(records)}** |")
    lines.append(f"| Total corpus bytes | {total_bytes:,} ({total_bytes / 1048576:.2f} MiB) |")
    lines.append(f"| Distinct extension signatures | {len(ext_counts)} |")
    lines.append(f"| Distinct header/magic classes | {len(magic_counts)} |")
    lines.append(f"| Unreadable (I/O error) | {len(unreadable)} |")
    lines.append("")
    lines.append("### Sources scanned")
    lines.append("")
    for s in sources:
        lines.append(f"- `{s}`")
    lines.append("")
    lines.append("## 2. Header / magic classification")
    lines.append("")
    lines.append("| Class | Count | Interpretation |")
    lines.append("| --- | --- | --- |")
    interp = {
        "opaque-encrypted": "Modern container — outer scramble + AEAD; no readable prefix. **PT 8/9 family.**",
        "zlib-stream": "Uncompressed-container variant or intermediate artifact.",
        "qt-qcompress": "Qt `qCompress` framing: 4-byte BE length + zlib. **Legacy PT 5/6/7 family.**",
        "raw-xml": "Unobfuscated XML payload — very old or stripped container.",
        "zip-pkzip": "ZIP archive (packaged activity bundle), not a raw container.",
        "gzip": "gzip-compressed artifact.",
        "png": "Image, not a container — should be excluded.",
        "empty": "Zero-length file.",
        "unreadable": "Host could not read the bytes (stale mount / I/O error). Excluded from hashing.",
    }
    for magic, count in magic_counts.most_common():
        note = interp.get(magic, "Unrecognized prefix — candidate legacy magic or byte-transposition variant.")
        lines.append(f"| `{magic}` | {count} | {note} |")
    lines.append("")
    lines.append("## 3. Extension breakdown")
    lines.append("")
    lines.append("| Extension | Count |")
    lines.append("| --- | --- |")
    for ext, count in ext_counts.most_common():
        lines.append(f"| `{ext}` | {count} |")
    lines.append("")
    lines.append("## 4. Content de-duplication")
    lines.append("")
    by_digest: dict[str, list[SampleRecord]] = {}
    for r in records:
        if r.sha256:
            by_digest.setdefault(r.sha256, []).append(r)
    unique = len(by_digest)
    dup_groups = {k: v for k, v in by_digest.items() if len(v) > 1}
    lines.append(f"| Metric | Value |")
    lines.append(f"| --- | --- |")
    lines.append(f"| Readable samples | {sum(1 for r in records if r.sha256)} |")
    lines.append(f"| **Distinct payloads (unique SHA-256)** | **{unique}** |")
    lines.append(f"| Digests appearing more than once | {len(dup_groups)} |")
    lines.append("")
    lines.append("> Corroboration is desirable for *format* coverage but not for *file* counts. "
                 "Where the same payload exists under several directory trees it is listed once here.")
    lines.append("")
    if dup_groups:
        lines.append("| SHA-256 (first 16) | Copies | Paths |")
        lines.append("| --- | --- | --- |")
        for digest, group in sorted(dup_groups.items(), key=lambda kv: -len(kv[1])):
            paths = "<br>".join(f"`{g.path}`" for g in group)
            lines.append(f"| `{digest[:16]}` | {len(group)} | {paths} |")
        lines.append("")
    lines.append("## 5. Entropy distribution")
    lines.append("")
    buckets = Counter()
    for r in records:
        buckets[round(r.entropy, 1)] += 1
    lines.append("| Shannon entropy (first 64 KiB) | Files |")
    lines.append("| --- | --- |")
    for b, c in sorted(buckets.items()):
        lines.append(f"| {b:.1f} | {c} |")
    lines.append("")
    lines.append("> Entropy ≈ 7.8–8.0 on the whole file is the signature of the modern "
                 "scramble+AEAD container (effectively random ciphertext). Entropy ≈ 6–7 with a "
                 "readable prefix indicates the legacy zlib/qCompress container.")
    lines.append("")
    lines.append("## 6. Full sample inventory")
    lines.append("")
    lines.append("| # | File | Size | Entropy | Magic class | SHA-256 (first 16) | Head bytes (first 8) |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for i, r in enumerate(records, 1):
        size_txt = f"{r.size:,}" if r.size >= 0 else "n/a"
        lines.append(
            f"| {i} | `{r.name}` | {size_txt} | {r.entropy:.2f} | `{r.magic_guess}` | "
            f"`{r.sha256[:16]}` | `{r.head_hex[:23]}` |"
        )
    lines.append("")
    lines.append("## 7. Complete SHA-256 manifest")
    lines.append("")
    lines.append("```")
    for r in records:
        if not r.sha256:
            continue
        lines.append(f"{r.sha256}  {r.path}")
    lines.append("```")
    lines.append("")
    lines.append("## 8. Observed anomalies / notes")
    lines.append("")
    noted = [r for r in records if r.notes]
    if not noted:
        lines.append("_None._")
    else:
        for r in noted:
            lines.append(f"- `{r.name}`: {', '.join(r.notes)}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", action="append", required=True, type=Path,
                    help="Directory or file to scan (repeatable).")
    ap.add_argument("--out", type=Path, required=True, help="Markdown report path.")
    ap.add_argument("--json", type=Path, help="Optional JSON inventory output path.")
    args = ap.parse_args(argv)

    paths = iter_samples(args.root)
    if not paths:
        print("No samples found.", file=sys.stderr)
        return 1

    records = [record_for(p) for p in paths]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_markdown(records, [str(r) for r in args.root]), encoding="utf-8")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8"
        )

    print(f"Scanned {len(records)} samples -> {args.out}")
    if args.json:
        print(f"JSON inventory -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
