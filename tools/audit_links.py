#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""audit_links.py -- is every cable actually brought up by the configuration?

A cable and an interface are two different things.  ``lab_api.link()`` draws the
cable and sets the port's electrical properties; it does **not** give the
interface a state.  On a router, an interface that no ``no shutdown`` was ever
issued for sits administratively down with a cable plugged into it: the link
renders dead while every structural gate still passes.

Three defect classes, all measured on a real 386-device build:

``no-interface-block``
    The port is cabled and nothing configures it.  Caused by drawing a
    Layer-3-to-Layer-3 link with ``link()`` instead of ``rlink()``, so the
    generator's "routed interfaces" registry never learned about it and no
    ``interface`` block was ever emitted.  **87 ports** in one build, including
    a core router with *no* interface blocks for either of its uplinks.

``shutdown``
    The block exists but the port is administratively down.  A firewall config
    that ends with a blanket ``interface Ethernet0/0 / shutdown`` also shuts the
    *outside* port -- five firewalls shipped that way.

``routed-and-trunk``
    The same port configured twice, once as a routed port (``no switchport`` +
    ``ip address``) and once as a trunk.  The parser applies the later block, the
    port reverts to Layer 2, and the routed neighbour on the other end never
    comes up.  Declaring *all* 24 ports of a collapsed-core switch as trunks
    does this to every routed uplink on it.

``trunk-facing-access``
    One end is a trunk, the other an access port in a different VLAN.  The link
    comes up and forwards nothing.

The tool is deliberately independent of any generator: it reads the written
artefact and asks one question per cable -- *would this port come up?*  Use it as
a build gate; a generator that derives each port's role from the peer it is
cabled to cannot fail it.

    python3 tools/audit_links.py lab.pkt
    python3 tools/audit_links.py lab.pkt --json build/link_audit.json
    python3 tools/audit_links.py lab.pkt --quiet      # exit status only
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT), str(ROOT / "tools"), str(ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pkt_core import decode_bytes          # noqa: E402

__all__ = ["audit_xml", "audit_file", "main"]

IFACE_RE = re.compile(r"^interface\s+(\S+)\s*$")
IP_RE = re.compile(r"^ip address\s+\S+\s+\S+")

#: A router interface is never an "access port" -- it has no switchport state at
#: all, and comparing its mode against a switch's trunk reports a mismatch that
#: cannot exist.  The same holds for any interface carrying an address.
ROUTER_MODELS = frozenset({
    "2911", "2901", "1941", "1841", "2811", "2621XM", "2620XM",
    "ISR4331", "ISR4321", "IR1101", "IR8340", "CGR1240", "ISA-3000", "819HGW",
})


def model_of(dev: ET.Element) -> str:
    """The model string, from the ``TYPE`` element's *attribute*.

    ``<ENGINE><TYPE model="3650-24PS">MultiLayerSwitch</TYPE>`` -- the element
    text is the device *class*.  A reader that takes the text reports
    "MultiLayerSwitch", which no port table is keyed by, and every lookup
    silently misses.
    """
    t = dev.find("ENGINE/TYPE")
    if t is None:
        return ""
    return (t.get("model") or (t.text or "")).strip()


def parse_config(dev: ET.Element) -> dict[str, dict]:
    """``{interface: {shutdown, routed, trunk, access_vlan}}`` for one device."""
    rc = dev.find("ENGINE/RUNNINGCONFIG")
    out: dict[str, dict] = {}
    if rc is None:
        return out
    cur = None
    for line in rc.findall("LINE"):
        s = (line.text or "").strip()
        m = IFACE_RE.match(s)
        if m:
            cur = m.group(1)
            out[cur] = {"shutdown": False, "routed": False, "trunk": False,
                        "access_vlan": None, "has_ip": False, "no_switchport": False,
                        "lines": 0}
            continue
        if cur is None:
            continue
        out[cur]["lines"] += 1
        if s == "shutdown":
            out[cur]["shutdown"] = True
        elif s == "no shutdown":
            out[cur]["shutdown"] = False
        elif s == "no switchport":
            out[cur]["no_switchport"] = True
        elif IP_RE.match(s):
            out[cur]["has_ip"] = True
        elif s.startswith("switchport mode trunk"):
            out[cur]["trunk"] = True
        elif s.startswith("switchport access vlan"):
            try:
                out[cur]["access_vlan"] = int(s.split()[-1])
            except ValueError:
                pass
    for v in out.values():
        v["routed"] = bool(v["no_switchport"] or v["has_ip"])
    return out


def audit_xml(root: ET.Element) -> list[dict]:
    """Return every link endpoint whose configuration would not bring it up."""
    findings, _links = _audit(root)
    return findings


def audit_file(path: Path) -> tuple[list[dict], int]:
    raw = path.read_bytes()
    xml = raw if raw[:1] == b"<" else decode_bytes(raw).xml
    findings, links = _audit(ET.fromstring(xml))
    return findings, len(links)


def _audit(root: ET.Element) -> tuple[list[dict], list[dict]]:
    devs = {d.findtext("ENGINE/SAVE_REF_ID"): d for d in root.iter("DEVICE")}
    name_of = {sid: (d.findtext("ENGINE/NAME") or "?") for sid, d in devs.items()}
    model_attr = {sid: model_of(d) for sid, d in devs.items()}
    cfg = {sid: parse_config(d) for sid, d in devs.items()}

    findings: list[dict] = []
    links: list[dict] = []
    for lk in root.iter("LINK"):
        cab = lk.find("CABLE")
        if cab is None:
            continue
        ends = [cab.findtext("FROM"), cab.findtext("TO")]
        ports = [e.text for e in cab.findall("PORT")]
        if len(ports) < 2:
            continue
        row: dict[int, dict] = {}
        for i, sid in enumerate(ends):
            if sid not in devs:
                continue
            port = (ports[i] or "").strip()
            row[i] = dict(name=name_of[sid], model=model_attr[sid], port=port)
            if not cfg.get(sid):
                continue          # carries no running-config at all; see Rule 6
            ic = cfg[sid].get(port)
            peer = row.get(1 - i, {}).get("name", "?")
            if ic is None:
                findings.append(dict(kind="no-interface-block", device=name_of[sid],
                                     model=model_attr[sid], port=port, peer=peer))
                continue
            if ic["shutdown"]:
                findings.append(dict(kind="shutdown", device=name_of[sid],
                                     model=model_attr[sid], port=port, peer=peer))
            if ic["routed"] and ic["trunk"]:
                findings.append(dict(kind="routed-and-trunk", device=name_of[sid],
                                     model=model_attr[sid], port=port, peer=peer))
        links.append(row)

    # A trunk facing an access port in a different VLAN forwards nothing.
    by_name = {v: k for k, v in name_of.items()}
    for row in links:
        if len(row) < 2:
            continue
        (a, b) = (row[0], row[1])
        ia = cfg.get(by_name.get(a["name"], ""), {}).get(a["port"])
        ib = cfg.get(by_name.get(b["name"], ""), {}).get(b["port"])
        if not ia or not ib:
            continue
        if (a["model"] in ROUTER_MODELS or b["model"] in ROUTER_MODELS
                or ia["routed"] or ib["routed"]):
            continue
        if ia["trunk"] != ib["trunk"]:
            trk = a["name"] if ia["trunk"] else b["name"]
            acc = b if ia["trunk"] else a
            acc_ic = ib if ia["trunk"] else ia
            findings.append(dict(
                kind="trunk-facing-access", device=trk, model="", port="",
                peer=f"{acc['name']} (access vlan "
                     f"{acc_ic['access_vlan'] if acc_ic['access_vlan'] is not None else 1})"))
    return findings, links


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lab", type=Path)
    ap.add_argument("--json", type=Path, default=None,
                    help="write the findings as JSON")
    ap.add_argument("--quiet", action="store_true",
                    help="print nothing; use the exit status")
    a = ap.parse_args(argv)

    findings, n_links = audit_file(a.lab)
    counted = collections.Counter(f["kind"] for f in findings)
    if not a.quiet:
        print(f"lab     : {a.lab.name}")
        print(f"links   : {n_links}")
        print(f"findings: {dict(counted) or 'none'}")
        by_kind: dict[str, list[dict]] = collections.defaultdict(list)
        for f in findings:
            by_kind[f["kind"]].append(f)
        for kind, items in by_kind.items():
            print(f"\n-- {kind} ({len(items)}) --")
            for it in items[:12]:
                print(f"   {it['device']:26s} {it['model']:12s} "
                      f"{it['port']:24s} peer={it['peer']}")
            if len(items) > 12:
                print(f"   ... and {len(items) - 12} more")
        if findings:
            print("\nEvery cabled port must be brought up by the configuration "
                  "that ships with it.")
    if a.json:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        a.json.write_text(json.dumps(findings, indent=1, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
