#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
export_plan.py -- read a generated .pkt and export the as-built documentation:

    docs/ADDRESS_PLAN.csv   every addressed interface (device, port, ip, mask, site)
    docs/SUBNETS.csv        every distinct subnet with its device count
    docs/VLANS.csv          the VLAN plan
    docs/SERVICES.md        DNS zone, DHCP pools and AAA clients actually written

Nothing here re-derives the design; it reads the file Packet Tracer will open,
so the documentation cannot drift from the artefact.
"""
from __future__ import annotations

import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def _find_toolkit() -> Path:
    """PKT_TOOLKIT if set, else search upward for tools/lab_api.py + src/pkt_core.

    Portability (problem 32): never hardcode an absolute checkout path -- it
    only works on the machine that built the lab.
    """
    env = __import__("os").environ.get("PKT_TOOLKIT")
    if env:
        return Path(env)
    for cand in Path(__file__).resolve().parent.parents:
        if (cand / "tools" / "lab_api.py").is_file() and (cand / "src" / "pkt_core").is_dir():
            return cand
    raise SystemExit("error: cannot find the pkt-core toolkit; set PKT_TOOLKIT")


TK = _find_toolkit()
sys.path.insert(0, str(TK))
import pt9                                    # noqa: E402
import xml.etree.ElementTree as ET            # noqa: E402

VLAN_NAMES = {1: "NATIVE/RADAR", 10: "OPS-TRACK", 20: "MISSION-SYS", 30: "VOICE",
              40: "MGMT", 50: "WIFI", 60: "SERVERS", 70: "TDL-DATALINK",
              80: "RADAR-SENSOR", 99: "BLACKHOLE"}


def main(src="out/JASDF_AEWC_JADGE.pkt", sfx=""):
    root = ET.fromstring(pt9.decode_bytes((ROOT / src).read_bytes(), "pkt",
                                          verify_tag=True))
    rows, subnets, pools, aaa, dns = [], Counter(), [], [], []

    for d in root.iter("DEVICE"):
        name = d.findtext("ENGINE/NAME") or "?"
        te = d.find("ENGINE/TYPE")
        model = (te.get("model") if te is not None else "") or "?"
        site = ""
        for line in (l.text or "" for l in d.findall("ENGINE/RUNNINGCONFIG/LINE")):
            m = re.match(r"^interface (\S+)$", line)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r"^\s+ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)",
                         line)
            if m and "cur" in dir():
                rows.append((name, model, cur, m.group(1), m.group(2), site))
        # end-device NIC
        for p in d.iter("PORT"):
            ip = (p.findtext("IP") or "").strip()
            if ip and ip != "0.0.0.0":
                rows.append((name, model, "NIC", ip,
                             (p.findtext("SUBNET") or "").strip(), site))

        eng = d.find("ENGINE")
        nd = eng.find("DNS_SERVER/NAMESERVER-DATABASE")
        if nd is not None:
            for r in nd.findall("RESOURCE-RECORD"):
                dns.append((name, r.findtext("NAME"), r.findtext("IPADDRESS")))
        for p in eng.findall("DHCP_SERVERS/ASSOCIATED_PORTS/ASSOCIATED_PORT/"
                             "DHCP_SERVER/POOLS/POOL"):
            pools.append((name, p.findtext("NAME"), p.findtext("NETWORK"),
                          p.findtext("MASK"), p.findtext("DEFAULT_ROUTER"),
                          p.findtext("START_IP"), p.findtext("END_IP")))
        acs = eng.find("ACS_SERVER")
        if acs is not None and acs.findtext("ENABLED") == "1":
            for c in acs.findall("ACS_CLIENTS/CLIENT"):
                aaa.append((c.findtext("HOST_IP"), c.findtext("DESCRIPTION"),
                            c.findtext("SERVER_TYPE")))

    def network(ip, mask):
        """True network address (mask the host bits)."""
        i = [int(x) for x in ip.split(".")]
        m = [int(x) for x in mask.split(".")] if mask else [255, 255, 255, 0]
        bits = sum(bin(x).count("1") for x in m)
        return ".".join(str(a & b) for a, b in zip(i, m)) + f"/{bits}"

    for _n, _m, _p, ip, mask, _s in rows:
        if ip and mask:
            subnets[network(ip, mask)] += 1

    (ROOT / "docs").mkdir(exist_ok=True)
    with (ROOT / "docs" / f"ADDRESS_PLAN{sfx}.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["device", "model", "interface", "ip", "mask"])
        for r in sorted(rows):
            w.writerow([r[0], r[1], r[2], r[3], r[4]])
    with (ROOT / "docs" / f"SUBNETS{sfx}.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["subnet", "addresses_in_use"])
        for s, n in sorted(subnets.items()):
            w.writerow([s, n])
    with (ROOT / "docs" / f"VLANS{sfx}.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["vlan", "name", "purpose"])
        for v, n in sorted(VLAN_NAMES.items()):
            w.writerow([v, n, {
                1: "IR1101 radar-site LAN + 3650/2960 default",
                10: "air-surveillance / weapons-control operator VLAN",
                20: "mission systems (radar processors, track servers)",
                30: "voice / intercom",
                40: "in-band management and loopbacks",
                50: "wireless (base and airborne tablets)",
                60: "server farm (JADGE data centre)",
                70: "tactical datalink / SATCOM transport",
                80: "radar sensor VLAN",
                99: "blackhole / unused",
            }[v]])

    lines = ["# As-built services", "",
             f"Generated from `{src}`. {len(dns)} DNS A-records, "
             f"{len(pools)} DHCP pools, {len(aaa)} AAA clients.", "",
             "## AAA (RADIUS) clients", ""]
    lines += [f"- `{ip}` - {desc}" for ip, desc, _t in sorted(aaa)]
    lines += ["", "## DHCP pools (first 60)", ""]
    lines += [f"- `{n}` -> {net}/{mask}, gw {gw}, range {a}-{b}"
              for _h, n, net, mask, gw, a, b in pools[:60]]
    lines += ["", "## DNS zone (first 80 A-records)", ""]
    lines += [f"- `{h}` -> {ip}" for _s, h, ip in sorted(set(dns))[:80]]
    (ROOT / "docs" / f"SERVICES{sfx}.md").write_text("\n".join(lines) + "\n")

    print(f"address rows : {len(rows)}")
    print(f"subnets      : {len(subnets)}")
    print(f"DNS records  : {len(set(dns))}")
    print(f"DHCP pools   : {len(pools)}")
    print(f"AAA clients  : {len(aaa)}")
    print("wrote docs/ADDRESS_PLAN.csv, docs/SUBNETS.csv, docs/VLANS.csv, "
          "docs/SERVICES.md")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out/JASDF_AEWC_JADGE.pkt",
         sys.argv[2] if len(sys.argv) > 2 else "")
