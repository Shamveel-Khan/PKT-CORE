#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
harvest_merge.py -- build a big Packet Tracer canvas by harvesting one complete
device of every model from a set of existing `.pkt` files and merging them into
one network file (using the pt9 codec).

This demonstrates *writing* complex PT files from scratch: it composes device
XML harvested from real labs and re-encodes them into a valid `.pkt`.

Usage:
    python3 harvest_merge.py --seed base.pkt --saves /opt/pt/saves --out big.pkt
    python3 harvest_merge.py --seed base.pkt --saves ./labs --limit 40 --out big.pkt

Key finding (see docs/SCENE_GRAPH.md): every device carries a *physical scene*
placement. Merged devices must be remapped to a physical node that already
exists in the seed's <PHYSICALWORKSPACE>, and any `translate="true"` name-path
must be replaced by UUIDs, or Packet Tracer refuses the file with
"corrupted Physical Workspace data".
"""
import argparse
import glob
import os
import random
import re
import sys
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pt9  # noqa: E402


def harvest(saves_dir):
    """Return {model: <DEVICE> xml bytes} taking the first seen instance per model."""
    models = {}
    files = sorted(glob.glob(os.path.join(saves_dir, "**", "*.pkt"), recursive=True),
                   key=os.path.getsize)
    for f in files:
        try:
            xml = pt9.decode(f, "pkt", verify_tag=True)
        except Exception:
            continue
        for m in re.finditer(rb"<DEVICE>.*?</DEVICE>", xml, re.S):
            blk = m.group(0)
            mm = re.search(rb'<TYPE[^>]*model="([^"]*)"', blk)
            if mm and mm.group(1).decode() not in models:
                models[mm.group(1).decode()] = blk
    return models


def build(seed_pkt, models, out_pkt, limit=0):
    seed_bytes = open(seed_pkt, "rb").read()
    seed_xml = pt9.decode_bytes(seed_bytes, "pkt") if seed_pkt.lower().endswith(".pkt") else seed_bytes
    base = ET.fromstring(seed_xml)
    net = base.find("NETWORK")
    devs = net.find("DEVICES")

    d0 = devs.findall("DEVICE")[0]
    PH = d0.find("WORKSPACE/PHYSICAL").text.strip()
    PP = d0.find("WORKSPACE/PHYSICAL_CPUR/PARENT_PATH").text.strip()
    CID = d0.find("WORKSPACE/PHYSICAL_CPUR/CONTAINER_ID").text.strip()
    CPURX = d0.find("WORKSPACE/PHYSICAL_CPUR/X").text.strip()

    def prep(blk, idx, model):
        s = blk
        s = re.sub(r"save-ref-id:\d+", lambda m: "save-ref-id:%d" % (9_000_000_000_000_000_000 + idx), s)
        label = re.sub(r"[^A-Za-z0-9_.-]", "_", model)[:20] + "_%03d" % idx
        s = re.sub(r"<NAME[^>]*>.*?</NAME>", '<NAME translate="true">%s</NAME>' % label, s, count=1, flags=re.S)
        x, y = 60 + (idx % 24) * 150, 60 + (idx // 24) * 130
        s = re.sub(r"(<WORKSPACE>\s*<LOGICAL>\s*<X>)[^<]*(</X>\s*<Y>)[^<]*(</Y>)",
                   lambda m: m.group(1) + str(x) + m.group(2) + str(y) + m.group(3), s, count=1, flags=re.S)
        # remap physical placement onto the seed's existing node
        s = re.sub(r"<PHYSICAL[^>]*>[^<]*</PHYSICAL>", "<PHYSICAL>%s</PHYSICAL>" % PH, s)
        if "<PHYSICAL_CPUR>" in s:
            s = re.sub(r"<PARENT_PATH>[^<]*</PARENT_PATH>", "<PARENT_PATH>%s</PARENT_PATH>" % PP, s)
            s = re.sub(r"<CONTAINER_ID>[^<]*</CONTAINER_ID>", "<CONTAINER_ID>%s</CONTAINER_ID>" % CID, s)
            s = re.sub(r"(<PHYSICAL_CPUR>\s*<X_PN>[^<]*</X_PN>\s*<Y_PN>[^<]*</Y_PN>\s*<X>)[^<]*(</X>)",
                       lambda m: m.group(1) + CPURX + m.group(2), s, count=1, flags=re.S)
        s = re.sub(r"<ORIGINAL_DEVICE_UUID>[^<]*</ORIGINAL_DEVICE_UUID>",
                   lambda m: "<ORIGINAL_DEVICE_UUID>{%s}</ORIGINAL_DEVICE_UUID>" % uuid.uuid4(), s)
        return ET.fromstring(s)

    order = sorted(models, key=lambda m: (not re.match(r"^\d", m), m))
    if limit:
        order = order[:limit]
    n = 0
    for i, model in enumerate(order):
        try:
            devs.append(prep(models[model].decode("utf-8", "replace"), i, model))
            n += 1
        except ET.ParseError:
            pass

    xml = ET.tostring(base, encoding="unicode")
    pt9.encode(out_pkt, xml.encode("utf-8"), "pkt")
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", required=True, help="a valid .pkt to use as the skeleton")
    ap.add_argument("--saves", required=True, help="directory tree of .pkt files to harvest")
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    models = harvest(a.saves)
    n = build(a.seed, models, a.out, a.limit)
    print(f"harvested {len(models)} models, appended {n}, wrote {a.out} "
          f"({len(open(a.out,'rb').read())} bytes)")


if __name__ == "__main__":
    main()
