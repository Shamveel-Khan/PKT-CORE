#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
draw_topology.py -- render a generated .pkt as a self-contained SVG (and PNG)
architecture diagram, colour-coded by operational tier.

    python3 tools/draw_topology.py out/JASDF_AEWC_JADGE.pkt docs/img/topology.svg

No external graph library is required: the generator emits SVG directly from the
device coordinates and <LINK> list already stored in the Packet Tracer file.
"""
from __future__ import annotations

import html
import sys
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

# tier -> (label, fill, stroke)
TIERS = [
    ("AIRBORNE",   "AEW&C airborne platforms",     "#dbeafe", "#1d4ed8"),
    ("DATALINK",   "Tactical datalink / SATCOM",   "#ede9fe", "#6d28d9"),
    ("BACKBONE",   "JADGE backbone transport",     "#fee2e2", "#b91c1c"),
    ("SECURITY",   "Security appliances (ASA)",    "#fecaca", "#991b1b"),
    ("DC",         "JADGE core data centre",       "#dcfce7", "#15803d"),
    ("HUB",        "Regional WAN aggregation",     "#e0f2fe", "#0369a1"),
    ("CRC",        "Control & Reporting Centers",  "#ccfbf1", "#0f766e"),
    ("RADAR",      "Fixed radar sites (J/FPS-x)",  "#fef3c7", "#b45309"),
    ("AIRBASE",    "Air bases",                    "#ecfccb", "#4d7c0f"),
    ("HQ",         "Air Defense Command HQ",       "#ffedd5", "#c2410c"),
    ("MGMT",       "NOSC management enclave",      "#f1f5f9", "#475569"),
    ("COALITION",  "Coalition / exercise partner", "#fae8ff", "#a21caf"),
    ("OTHER",      "Other",                        "#f8fafc", "#64748b"),
]


# the JADGE data-centre service farm (names carry the service, not the site)
DC_SERVERS = {
    "JADGE-C2-SVR", "TRACK-FUSION-SVR", "LINK16-GW-SVR", "RADAR-FUSION-SVR",
    "MISSION-PLAN-SVR", "AIR-TASKING-SVR", "COP-SERVER", "DNS-SVR", "DNS-SVR-02",
    "DHCP-SVR", "NTP-SVR", "SYSLOG-SVR", "AAA-SVR", "TFTP-SVR",
    "MISSION-WEB-SVR", "MAIL-SVR", "PKI-CA-SVR", "NETFLOW-SVR",
    "DATA-HISTORIAN", "BACKUP-SVR", "CYBER-OBS-SVR",
}


def tier_of(name: str) -> str:
    n = name.upper()
    if n.startswith(("E767-", "E2D-", "E2C-", "RC2-")):
        return "AIRBORNE"
    if n.startswith(("TDL-GW", "SATCOM-GW", "DATALINK-AGG")):
        return "DATALINK"
    if n.startswith(("CORE-RTR", "WAN-EDGE", "JADGE-BB")):
        return "BACKBONE"
    if n.startswith("FW-"):
        return "SECURITY"
    if n.startswith("JADGE-DC") or n in DC_SERVERS:
        return "DC"
    if n.startswith("REG-HUB"):
        return "HUB"
    if n.startswith("CRC-"):
        return "CRC"
    if n.startswith("RDR-"):
        return "RADAR"
    if n.startswith("AB-"):
        return "AIRBASE"
    if n.startswith("ADC-"):
        return "HQ"
    if n.startswith(("NOSC-", "MGMT-GW")):
        return "MGMT"
    if n.startswith(("COALITION", "PARTNER-")):
        return "COALITION"
    return "OTHER"


def main(src, dst):
    raw = Path(src).read_bytes()
    root = ET.fromstring(pt9.decode_bytes(raw, "pkt", verify_tag=True))

    devs, order = {}, []
    for d in root.iter("DEVICE"):
        sid = d.findtext("ENGINE/SAVE_REF_ID")
        nm = d.findtext("ENGINE/NAME") or "?"
        te = d.find("ENGINE/TYPE")
        mdl = (te.get("model") if te is not None else "") or "?"
        x = d.findtext("WORKSPACE/LOGICAL/X")
        y = d.findtext("WORKSPACE/LOGICAL/Y")
        try:
            x, y = float(x), float(y)
        except (TypeError, ValueError):
            x = y = 0.0
        devs[sid] = dict(name=nm, model=mdl, x=x, y=y, tier=tier_of(nm))
        order.append(sid)

    links = []
    for L in root.find("NETWORK/LINKS").findall("LINK"):
        c = L.find("CABLE")
        if c is None:
            continue
        fr, to = c.findtext("FROM"), c.findtext("TO")
        if fr in devs and to in devs:
            links.append((fr, to, L.findtext("TYPE")))

    # ---- geometry ------------------------------------------------------ #
    W = 160          # device box width
    H = 54
    PAD = 70
    xs = [d["x"] for d in devs.values()]
    ys = [d["y"] for d in devs.values()]
    minx, maxx = min(xs) - PAD, max(xs) + W + PAD
    miny, maxy = min(ys) - PAD, max(ys) + H + PAD
    sw, sh = maxx - minx, maxy - miny

    counts = {}
    for d in devs.values():
        counts[d["tier"]] = counts.get(d["tier"], 0) + 1

    o = []
    o.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{sw:.0f}" '
             f'height="{sh + 130:.0f}" viewBox="{minx:.0f} {-PAD - 130:.0f} '
             f'{sw:.0f} {sh + 130:.0f}" font-family="Helvetica,Arial,sans-serif">')
    o.append(f'<rect x="{minx:.0f}" y="{-PAD - 130:.0f}" width="{sw:.0f}" '
             f'height="{sh + 130:.0f}" fill="#ffffff"/>')

    # legend
    lx = minx + 18
    ly = -PAD - 112
    o.append(f'<text x="{lx}" y="{ly}" font-size="30" font-weight="bold" '
             f'fill="#0f172a">JASDF AEW&amp;C Enterprise - JADGE Network Model</text>')
    o.append(f'<text x="{lx}" y="{ly + 34}" font-size="19" fill="#334155">'
             f'{len(devs)} devices &#183; {len(links)} links &#183; Cisco Packet '
             f'Tracer 9.0.1 &#183; OSPF multi-area + iBGP AS65001</text>')
    for i, (t, label, fill, stroke) in enumerate(TIERS):
        if not counts.get(t):
            continue
        cx = lx + (i % 7) * 250
        cy = ly + 66 + (i // 7) * 30
        o.append(f'<rect x="{cx}" y="{cy - 14}" width="20" height="14" rx="3" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
        o.append(f'<text x="{cx + 28}" y="{cy}" font-size="16" fill="#334155">'
                 f'{html.escape(label)} ({counts[t]})</text>')

    # links first so boxes sit on top
    for fr, to, kind in links:
        a, b = devs[fr], devs[to]
        x1, y1 = a["x"] + W / 2, a["y"] + H / 2
        x2, y2 = b["x"] + W / 2, b["y"] + H / 2
        col = "#dc2626" if kind == "eSerial" else "#94a3b8"
        wdt = "2.6" if kind == "eSerial" else "1.5"
        dash = ' stroke-dasharray="11,7"' if kind == "eSerial" else ""
        o.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                 f'stroke="{col}" stroke-width="{wdt}"{dash} opacity="0.85"/>')

    for sid in order:
        d = devs[sid]
        _, _, fill, stroke = next(t for t in TIERS if t[0] == d["tier"])
        o.append(f'<rect x="{d["x"]:.0f}" y="{d["y"]:.0f}" width="{W}" height="{H}" '
                 f'rx="7" fill="{fill}" stroke="{stroke}" stroke-width="2.2"/>')
        o.append(f'<text x="{d["x"] + W/2:.0f}" y="{d["y"] + 22:.0f}" font-size="14.5" '
                 f'font-weight="bold" text-anchor="middle" fill="#0f172a">'
                 f'{html.escape(d["name"][:22])}</text>')
        o.append(f'<text x="{d["x"] + W/2:.0f}" y="{d["y"] + 41:.0f}" font-size="12.5" '
                 f'text-anchor="middle" fill="#475569">'
                 f'{html.escape(d["model"])}</text>')

    o.append('</svg>')
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text("\n".join(o), encoding="utf-8")
    print(f"wrote {dst}  ({sw:.0f}x{sh + 130:.0f})  devices={len(devs)} links={len(links)}")
    for t, label, _f, _s in TIERS:
        if counts.get(t):
            print(f"   {label:34s} {counts[t]:3d}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ROOT / "out" / "JASDF_AEWC_JADGE.pkt",
         sys.argv[2] if len(sys.argv) > 2 else ROOT / "docs" / "img" / "topology.svg")
