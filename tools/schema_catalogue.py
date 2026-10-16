#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Derive the complete Packet Tracer XML schema from a corpus of documents.

Walks every decoded document and records, for each element name:

* occurrence count and document frequency
* the parent element(s) it appears under
* its attribute names and whether it carries text, element children or both
* its container family distribution (modern vs legacy)
* whether :mod:`pkt_core.models` already types it

The output is the machine-readable basis for the format specification.

    python3 tools/schema_catalogue.py --index corpus/CORPUS_INDEX.tsv \
        --dir corpus/internet --out docs/schema_catalogue.json
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from pkt_core import decode_bytes  # noqa: E402


class Node:
    __slots__ = ("name", "parents", "count", "docs", "attrs", "has_text", "has_cdata", "has_kids")

    def __init__(self, name: str) -> None:
        self.name = name
        self.parents: collections.Counter[str] = collections.Counter()
        self.count = 0
        self.docs: set[str] = set()
        self.attrs: collections.Counter[str] = collections.Counter()
        self.has_text = False
        self.has_cdata = False
        self.has_kids = False


def scan(data: bytes, doc_id: str, nodes: dict[str, Node], family: str) -> None:
    """Byte-level scan; tolerant of CDATA and control bytes by construction."""
    stack: list[str] = []
    i, n = 0, len(data)
    while i < n:
        lt = data.find(b"<", i)
        if lt < 0:
            break
        if data[lt : lt + 2] == b"</":
            end = data.find(b">", lt)
            if end < 0:
                break
            if stack:
                stack.pop()
            i = end + 1
            continue
        if data[lt : lt + 2] == b"<?":
            i = data.find(b"?>", lt)
            i = (i + 2) if i >= 0 else n
            continue
        if data[lt : lt + 9] == b"<![CDATA[":
            end = data.find(b"]]>", lt + 9)
            end = (end + 3) if end >= 0 else n
            if stack:
                nd = nodes.get(stack[-1])
                if nd:
                    nd.has_cdata = True
                    nd.has_text = True
            i = end
            continue
        if data[lt : lt + 4] == b"<!--":
            end = data.find(b"-->", lt + 4)
            i = (end + 3) if end >= 0 else n
            continue
        if data[lt : lt + 2] == b"<!":
            # DOCTYPE / other declaration: scan to '>' outside quotes
            j = lt + 2
            quote = None
            while j < n:
                b = data[j]
                if quote:
                    if b == quote:
                        quote = None
                elif b in (0x22, 0x27):
                    quote = b
                elif b == 0x3E:
                    break
                j += 1
            i = j + 1
            continue

        # start tag
        j = lt + 1
        while j < n and not data[j : j + 1].isspace() and data[j] not in (0x3E, 0x2F):
            j += 1
        name = data[lt + 1 : j].decode("utf-8", "replace")
        if not name:
            i = j + 1
            continue

        # attribute names
        k = j
        quote = None
        attrs: list[str] = []
        while k < n:
            b = data[k]
            if quote:
                if b == quote:
                    quote = None
            elif b in (0x22, 0x27):
                quote = b
            elif b == 0x3E:
                break
            elif b == 0x3D:
                # walk back for the name
                m = k - 1
                while m > lt and data[m : m + 1].isspace():
                    m -= 1
                e = m
                while e > lt and (data[e : e + 1].isalnum() or data[e] in (0x5F, 0x3A, 0x2D)):
                    e -= 1
                raw = data[e + 1 : m + 1]
                if raw:
                    attrs.append(raw.decode("utf-8", "replace"))
            k += 1

        # ordinary character data between this tag and the next is text too
        if stack and lt > i:
            prev = nodes.get(stack[-1])
            if prev and any(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data[i:lt]):
                prev.has_text = True

        self_closing = data[lt : k + 1].rstrip(b">").endswith(b"/")
        nd = nodes.get(name)
        if nd is None:
            nd = nodes[name] = Node(name)
        nd.count += 1
        nd.docs.add(doc_id)
        nd.docs  # keep reference
        for a in attrs:
            nd.attrs[a] += 1
        parent = stack[-1] if stack else "(root)"
        nd.parents[parent] += 1
        if stack:
            pnd = nodes.get(stack[-1])
            if pnd:
                pnd.has_kids = True

        if not self_closing:
            stack.append(name)
        i = k + 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--index", type=Path, required=True)
    ap.add_argument("--dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=0, help="0 = all rows")
    args = ap.parse_args(argv)

    rows = list(csv.DictReader(args.index.open(), delimiter="\t"))
    if args.limit:
        rows = rows[: args.limit]

    nodes: dict[str, Node] = {}
    scanned = skipped = 0
    families: collections.Counter[str] = collections.Counter()

    for row in rows:
        name = row["filename"]
        if name.lower().endswith(".zip"):
            continue
        path = args.dir / name
        if not path.exists():
            continue
        try:
            container = decode_bytes(path.read_bytes())
        except Exception:  # noqa: BLE001
            skipped += 1
            continue
        family = "legacy" if container.format_name == "legacy" else "modern"
        families[family] += 1
        scan(container.xml, name, nodes, family)
        scanned += 1

    # which names are typed by pkt_core.models?
    typed: set[str] = set()
    try:
        import pkt_core.models.lab as L
        import pkt_core.models.network as N
        import pkt_core.models.schema as S

        for cls in (L.Lab, L.Network, L.LabOptions, L.Cluster, L.RunningConfig,
                    N.Device, N.Module, N.Port, N.Workspace, N.Link, N.Cable,
                    S.PortConfig, S.WirelessConfig, S.DeviceDetails, S.FileEntry,
                    S.ScoringNode, S.EnvironmentOption, S.CanvasShape, S.ActivitySection):
            typed |= set(getattr(cls, "_claimed", frozenset()))
    except Exception:  # noqa: BLE001
        pass

    entries = []
    for nd in sorted(nodes.values(), key=lambda x: (-x.count, x.name)):
        entries.append({
            "name": nd.name,
            "occurrences": nd.count,
            "documents": len(nd.docs),
            "parents": dict(nd.parents.most_common(8)),
            "attributes": dict(nd.attrs.most_common(12)),
            "has_text": nd.has_text,
            "has_cdata": nd.has_cdata,
            "has_element_children": nd.has_kids,
            "modelled": nd.name in typed,
        })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "documents_scanned": scanned,
        "documents_skipped": skipped,
        "families": dict(families),
        "distinct_elements": len(entries),
        "modelled_elements": sum(1 for e in entries if e["modelled"]),
        "elements": entries,
    }, indent=2) + "\n", encoding="utf-8")

    print(f"documents scanned : {scanned}  (skipped {skipped})")
    print(f"families          : {dict(families)}")
    print(f"distinct elements : {len(entries)}")
    print(f"modelled          : {sum(1 for e in entries if e['modelled'])}")
    print(f"wrote             : {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
