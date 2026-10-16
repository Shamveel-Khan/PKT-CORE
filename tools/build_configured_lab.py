#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
build_configured_lab.py -- generate a full, *working*, configured topology:

    PC1 -- SW1 -- R1 ==== R2 -- SW2 -- PC2

with static IPs/gateways, static routes, and (optionally) a long running-config
on R1 made of many loopback interfaces.

    python3 build_configured_lab.py --seed base.pkt --saves /opt/pt/saves \
        --out lab.pkt --loopbacks 200

How configuration is stored (see ../docs/CONFIGURATION.md):

* IOS devices (routers/switches): `<ENGINE><RUNNINGCONFIG><LINE>cmd</LINE>…`
  — each CLI line is applied when Packet Tracer loads the file.
* End devices (PCs): the NIC `<PORT>` carries `<IP>`, `<SUBNET>`,
  `<PORT_GATEWAY>`, `<PORT_DHCP_ENABLE>`.

Requirements for the file to load (learned the hard way):
* each device needs a unique `<ENGINE>/<SAVE_REF_ID>`;
* unique `MACADDRESS`/`BIA` per port (cloning duplicates them otherwise);
* a valid `<PHYSICAL>` scene placement (reused from the seed).
"""
import argparse
import glob
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pt9  # noqa: E402


def harvest(saves, wanted):
    """Find one <DEVICE> block per requested model."""
    out = {}
    for f in sorted(glob.glob(os.path.join(saves, "**", "*.pkt"), recursive=True), key=os.path.getsize):
        if len(out) == len(wanted):
            break
        try:
            xml = pt9.decode(f, "pkt", verify_tag=False)
        except Exception:
            continue
        for m in re.finditer(rb"<DEVICE>.*?</DEVICE>", xml, re.S):
            mm = re.search(rb'<TYPE[^>]*model="([^"]*)"', m.group(0))
            if mm and mm.group(1).decode() in wanted and mm.group(1).decode() not in out:
                out[mm.group(1).decode()] = m.group(0)
    missing = wanted - set(out)
    if missing:
        raise SystemExit(f"could not harvest models: {missing}")
    return out


class Builder:
    def __init__(self, seed_pkt, blocks):
        seed = open(seed_pkt, "rb").read()
        self.base = ET.fromstring(pt9.decode_bytes(seed, "pkt") if seed_pkt.endswith(".pkt") else seed)
        self.net = self.base.find("NETWORK")
        self.devs = self.net.find("DEVICES")
        d0 = self.devs.findall("DEVICE")[0]
        self.PH = d0.find("WORKSPACE/PHYSICAL").text.strip()
        self.PP = d0.find("WORKSPACE/PHYSICAL_CPUR/PARENT_PATH").text.strip()
        self.CID = d0.find("WORKSPACE/PHYSICAL_CPUR/CONTAINER_ID").text.strip()
        self.CPX = d0.find("WORKSPACE/PHYSICAL_CPUR/X").text.strip()
        self.blocks = blocks
        self.n = 0
        self.mac = 0

    def device(self, model, name, x, y):
        s = self.blocks[model].decode("utf-8", "replace")
        i = self.n; self.n += 1
        s = re.sub(r"save-ref-id:\d+", lambda m: "save-ref-id:%d" % (9_400_000_000_000_000_000 + i), s)
        s = re.sub(r"<NAME[^>]*>.*?</NAME>", '<NAME translate="true">%s</NAME>' % name, s, count=1, flags=re.S)
        s = re.sub(r"(<WORKSPACE>\s*<LOGICAL>\s*<X>)[^<]*(</X>\s*<Y>)[^<]*(</Y>)",
                   lambda m: m.group(1) + str(x) + m.group(2) + str(y) + m.group(3), s, count=1, flags=re.S)
        s = re.sub(r"<PHYSICAL[^>]*>[^<]*</PHYSICAL>", "<PHYSICAL>%s</PHYSICAL>" % self.PH, s)
        if "<PHYSICAL_CPUR>" in s:
            s = re.sub(r"<PARENT_PATH>[^<]*</PARENT_PATH>", "<PARENT_PATH>%s</PARENT_PATH>" % self.PP, s)
            s = re.sub(r"<CONTAINER_ID>[^<]*</CONTAINER_ID>", "<CONTAINER_ID>%s</CONTAINER_ID>" % self.CID, s)
            s = re.sub(r"(<PHYSICAL_CPUR>\s*<X_PN>[^<]*</X_PN>\s*<Y_PN>[^<]*</Y_PN>\s*<X>)[^<]*(</X>)",
                       lambda m: m.group(1) + self.CPX + m.group(2), s, count=1, flags=re.S)
        s = re.sub(r"<ORIGINAL_DEVICE_UUID>[^<]*</ORIGINAL_DEVICE_UUID>",
                   lambda m: "<ORIGINAL_DEVICE_UUID>{%s}</ORIGINAL_DEVICE_UUID>" % uuid.uuid4(), s)
        el = ET.fromstring(s)
        for tag in ("MACADDRESS", "BIA"):
            for e in el.iter(tag):
                self.mac += 1
                e.text = "%04X.%04X.%04X" % (0x0212, (self.mac >> 16) & 0xFFFF, self.mac & 0xFFFF)
        eng = el.find("ENGINE")
        for e in list(eng.findall("SAVE_REF_ID")):
            eng.remove(e)
        sid = ET.SubElement(eng, "SAVE_REF_ID")
        sid.text = "save-ref-id:%d" % (9_400_000_000_000_000_000 + i)
        self.devs.append(el)
        return sid.text, el

    @staticmethod
    def run_config(el, lines):
        eng = el.find("ENGINE")
        for rc in list(eng.findall("RUNNINGCONFIG")):
            eng.remove(rc)
        rc = ET.SubElement(eng, "RUNNINGCONFIG")
        for L in lines:
            ET.SubElement(rc, "LINE").text = L

    @staticmethod
    def pc_ip(el, ip, mask, gw):
        port = el.find(".//PORT")
        for tag, val in (("IP", ip), ("SUBNET", mask), ("PORT_GATEWAY", gw), ("PORT_DHCP_ENABLE", "false")):
            e = port.find(tag)
            if e is None:
                e = ET.SubElement(port, tag)
            e.text = val

    def link(self, a, pa, b, pb):
        L = ET.SubElement(self.net.find("LINKS"), "LINK")
        ET.SubElement(L, "TYPE").text = "eCopper"
        cab = ET.SubElement(L, "CABLE")
        for t, v in (("LENGTH", "1"), ("FUNCTIONAL", "true"), ("FROM", a), ("PORT", pa),
                     ("TO", b), ("PORT", pb), ("FROM_DEVICE_MEM_ADDR", "1"), ("TO_DEVICE_MEM_ADDR", "2"),
                     ("FROM_PORT_MEM_ADDR", "3"), ("TO_PORT_MEM_ADDR", "4"),
                     ("GEO_VIEW_COLOR", "#6ba72e"), ("IS_MANAGED_IN_RACK_VIEW", "false"),
                     ("TYPE", "eStraightThrough")):
            ET.SubElement(cab, t).text = v

    def save(self, path):
        pt9.encode(path, ET.tostring(self.base, encoding="unicode").encode("utf-8"), "pkt")


def header(host):
    return ["!", "version 15.1", "no service timestamps log datetime msec",
            "no service timestamps debug datetime msec", "service password-encryption", "!",
            "hostname %s" % host, "!", "ip cef", "no ipv6 cef", "!"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", required=True)
    ap.add_argument("--saves", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--loopbacks", type=int, default=0, help="extra loopback interfaces on R1 (long config test)")
    a = ap.parse_args()

    blocks = harvest(a.saves, {"2911", "2960-24TT", "PC-PT"})
    b = Builder(a.seed, blocks)

    r1, r1e = b.device("2911", "R1", 200, 300)
    r2, r2e = b.device("2911", "R2", 620, 300)
    sw1, sw1e = b.device("2960-24TT", "SW1", 200, 470)
    sw2, sw2e = b.device("2960-24TT", "SW2", 620, 470)
    pc1, pc1e = b.device("PC-PT", "PC1", 200, 620)
    pc2, pc2e = b.device("PC-PT", "PC2", 620, 620)

    r1cfg = header("R1") + [
        "interface GigabitEthernet0/0", " ip address 10.0.0.1 255.255.255.252", " no shutdown", "!",
        "interface GigabitEthernet0/1", " ip address 192.168.1.1 255.255.255.0", " no shutdown", "!",
        "ip route 192.168.2.0 255.255.255.0 10.0.0.2", "!"]
    for i in range(a.loopbacks):
        r1cfg += ["interface Loopback%d" % i, " ip address 172.16.%d.1 255.255.255.0" % (i % 256), "!"]
    r1cfg += ["end"]
    r2cfg = header("R2") + [
        "interface GigabitEthernet0/0", " ip address 10.0.0.2 255.255.255.252", " no shutdown", "!",
        "interface GigabitEthernet0/1", " ip address 192.168.2.1 255.255.255.0", " no shutdown", "!",
        "ip route 192.168.1.0 255.255.255.0 10.0.0.1", "!", "end"]
    swcfg = header("SW") + ["interface Vlan1", " no shutdown", "!", "end"]

    b.run_config(r1e, r1cfg); b.run_config(r2e, r2cfg)
    b.run_config(sw1e, swcfg); b.run_config(sw2e, swcfg)
    b.pc_ip(pc1e, "192.168.1.10", "255.255.255.0", "192.168.1.1")
    b.pc_ip(pc2e, "192.168.2.10", "255.255.255.0", "192.168.2.1")

    b.link(r1, "GigabitEthernet0/0", r2, "GigabitEthernet0/0")
    b.link(r1, "GigabitEthernet0/1", sw1, "GigabitEthernet0/1")
    b.link(sw1, "FastEthernet0/1", pc1, "FastEthernet0")
    b.link(r2, "GigabitEthernet0/1", sw2, "GigabitEthernet0/1")
    b.link(sw2, "FastEthernet0/1", pc2, "FastEthernet0")

    b.save(a.out)
    print(f"wrote {a.out} ({len(open(a.out,'rb').read())} bytes); R1 config lines: {len(r1cfg)}")


if __name__ == "__main__":
    main()
