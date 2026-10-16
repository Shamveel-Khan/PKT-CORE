#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
build_wired_lab.py -- build a large, AUTO-WIRED Packet Tracer lab.

Harvests one complete device per model from a tree of existing `.pkt` files and
merges them into one canvas, then cables every ethernet-capable device to a
backbone of core switches.  Uses the `pt9` codec to write the result.

    python3 build_wired_lab.py --seed base.pkt --saves /opt/pt/saves --out big.pkt

Three things are required for the result to load in Packet Tracer (see
../docs/SCENE_GRAPH.md):

1. every device keeps a valid <PHYSICAL> scene placement (reuse the seed's);
2. every appended device has <ENGINE>/<SAVE_REF_ID> so links resolve;
3. a link's <PORT> name must come from the *same* device instance we ship
   (harvested per device, not guessed per model).
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

ETH = re.compile(r"^(FastEthernet|GigabitEthernet|Ethernet)\d")


def harvest(saves_dir):
    """Return (models: {model: <DEVICE> bytes}, ports: {model: port_name})."""
    models, ports = {}, {}
    ref_block, ref_model = {}, {}
    files = sorted(glob.glob(os.path.join(saves_dir, "**", "*.pkt"), recursive=True),
                   key=os.path.getsize)
    for f in files:
        try:
            xml = pt9.decode(f, "pkt", verify_tag=True)
        except Exception:
            continue
        ref_block.clear(); ref_model.clear()
        for m in re.finditer(rb"<DEVICE>.*?</DEVICE>", xml, re.S):
            blk = m.group(0)
            sid = re.search(rb"<SAVE_REF_ID>([^<]*)</SAVE_REF_ID>", blk)
            mod = re.search(rb'<TYPE[^>]*model="([^"]*)"', blk)
            if not mod:
                continue
            models.setdefault(mod.group(1).decode(), blk)
            if sid:
                ref_block[sid.group(1).decode()] = blk
                ref_model[sid.group(1).decode()] = mod.group(1).decode()
        for m in re.finditer(rb"<LINK>.*?</LINK>", xml, re.S):
            vals = re.findall(rb"<(?:FROM|TO|PORT)>([^<]*)</(?:FROM|TO|PORT)>", m.group(0))
            if len(vals) < 4:
                continue
            frm, p1, to, p2 = [v.decode() for v in vals[:4]]
            for ref, port in ((frm, p1), (to, p2)):
                mod = ref_model.get(ref)
                if mod and ETH.match(port or "") and mod not in ports:
                    ports[mod] = port
                    models[mod] = ref_block.get(ref, models.get(mod, b""))
    return models, ports


def build(seed_pkt, models, ports, out_pkt, core_model="2960-24TT"):
    seed = open(seed_pkt, "rb").read()
    seed_xml = pt9.decode_bytes(seed, "pkt") if seed_pkt.lower().endswith(".pkt") else seed
    base = ET.fromstring(seed_xml)
    net = base.find("NETWORK")
    devs = net.find("DEVICES")
    d0 = devs.findall("DEVICE")[0]
    PH = d0.find("WORKSPACE/PHYSICAL").text.strip()
    PP = d0.find("WORKSPACE/PHYSICAL_CPUR/PARENT_PATH").text.strip()
    CID = d0.find("WORKSPACE/PHYSICAL_CPUR/CONTAINER_ID").text.strip()
    CPX = d0.find("WORKSPACE/PHYSICAL_CPUR/X").text.strip()
    base_id = 9_100_000_000_000_000_000

    def prep(blk, idx, name):
        s = re.sub(r"save-ref-id:\d+", lambda m: "save-ref-id:%d" % (base_id + idx), blk)
        s = re.sub(r"<NAME[^>]*>.*?</NAME>", '<NAME translate="true">%s</NAME>' % name, s, count=1, flags=re.S)
        x, y = 60 + (idx % 26) * 150, 90 + (idx // 26) * 130
        s = re.sub(r"(<WORKSPACE>\s*<LOGICAL>\s*<X>)[^<]*(</X>\s*<Y>)[^<]*(</Y>)",
                   lambda m: m.group(1) + str(x) + m.group(2) + str(y) + m.group(3), s, count=1, flags=re.S)
        s = re.sub(r"<PHYSICAL[^>]*>[^<]*</PHYSICAL>", "<PHYSICAL>%s</PHYSICAL>" % PH, s)
        if "<PHYSICAL_CPUR>" in s:
            s = re.sub(r"<PARENT_PATH>[^<]*</PARENT_PATH>", "<PARENT_PATH>%s</PARENT_PATH>" % PP, s)
            s = re.sub(r"<CONTAINER_ID>[^<]*</CONTAINER_ID>", "<CONTAINER_ID>%s</CONTAINER_ID>" % CID, s)
            s = re.sub(r"(<PHYSICAL_CPUR>\s*<X_PN>[^<]*</X_PN>\s*<Y_PN>[^<]*</Y_PN>\s*<X>)[^<]*(</X>)",
                       lambda m: m.group(1) + CPX + m.group(2), s, count=1, flags=re.S)
        s = re.sub(r"<ORIGINAL_DEVICE_UUID>[^<]*</ORIGINAL_DEVICE_UUID>",
                   lambda m: "<ORIGINAL_DEVICE_UUID>{%s}</ORIGINAL_DEVICE_UUID>" % uuid.uuid4(), s)
        el = ET.fromstring(s)
        eng = el.find("ENGINE")
        for e in list(eng.findall("SAVE_REF_ID")):
            eng.remove(e)
        sid = ET.SubElement(eng, "SAVE_REF_ID"); sid.text = "save-ref-id:%d" % (base_id + idx)
        el.find("WORKSPACE/LOGICAL/MEM_ADDR").text = str(random.randint(10**8, 2**31))
        el.find("WORKSPACE/LOGICAL/DEV_ADDR").text = str(random.randint(10**8, 2**31))
        return el, sid.text, el.find("WORKSPACE/LOGICAL/DEV_ADDR").text

    order = sorted(models, key=lambda m: (not re.match(r"^\d", m), m))
    wired = []
    for i, model in enumerate(order):
        try:
            el, sid, da = prep(models[model].decode("utf-8", "replace"), i,
                               re.sub(r"[^A-Za-z0-9_.-]", "_", model)[:20] + "_%03d" % i)
        except ET.ParseError:
            continue
        devs.append(el)
        if model in ports:
            wired.append((sid, ports[model], da))

    # backbone
    cores = []
    ncore = (len(wired) + 21) // 22 if wired else 0
    if ncore:
        tmpl = models.get(core_model)
        if tmpl is None:
            raise SystemExit(f"core model {core_model!r} not found in harvested models")
        for k in range(ncore):
            el, sid, da = prep(tmpl.decode("utf-8", "replace"), 5000 + k, "CORE_%02d" % k)
            el.find("ENGINE/NAME").text = "CORE_%02d" % k
            el.find("WORKSPACE/LOGICAL/X").text = str(80 + k * 200)
            el.find("WORKSPACE/LOGICAL/Y").text = "20"
            devs.append(el)
            cores.append((sid, da))

    links = net.find("LINKS")
    def add_link(refA, portA, addrA, refB, portB, addrB):
        L = ET.SubElement(links, "LINK")
        ET.SubElement(L, "TYPE").text = "eCopper"
        cab = ET.SubElement(L, "CABLE")
        for tag, val in (("LENGTH", "1"), ("FUNCTIONAL", "true"),
                         ("FROM", refA), ("PORT", portA), ("TO", refB), ("PORT", portB),
                         ("FROM_DEVICE_MEM_ADDR", str(addrA)), ("TO_DEVICE_MEM_ADDR", str(addrB)),
                         ("FROM_PORT_MEM_ADDR", str(random.randint(10**11, 10**15))),
                         ("TO_PORT_MEM_ADDR", str(random.randint(10**11, 10**15))),
                         ("GEO_VIEW_COLOR", "#6ba72e"), ("IS_MANAGED_IN_RACK_VIEW", "false"),
                         ("TYPE", "eStraightThrough")):
            ET.SubElement(cab, tag).text = val

    for i, (ref, port, da) in enumerate(wired):
        c = i // 22
        add_link(ref, port, da, cores[c][0], "FastEthernet0/%d" % (2 + i % 22), cores[c][1])
    for k in range(ncore - 1):
        add_link(cores[k][0], "GigabitEthernet0/1", cores[k][1], cores[k + 1][0], "GigabitEthernet0/1", cores[k + 1][1])

    pt9.encode(out_pkt, ET.tostring(base, encoding="unicode").encode("utf-8"), "pkt")
    return len(devs.findall("DEVICE")), len(links.findall("LINK"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", required=True)
    ap.add_argument("--saves", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--core-model", default="2960-24TT")
    a = ap.parse_args()
    models, ports = harvest(a.saves)
    ndev, nlink = build(a.seed, models, ports, a.out, a.core_model)
    print(f"harvested {len(models)} models ({len(ports)} wireable); wrote {ndev} devices, "
          f"{nlink} links -> {a.out} ({len(open(a.out,'rb').read())} bytes)")


if __name__ == "__main__":
    main()
