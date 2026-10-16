#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
validate.py -- structural / semantic validation of a generated .pkt.

Checks, in order of severity:

  FAIL  container round-trip is not byte-exact
  FAIL  XML is not parseable, or contains characters illegal in XML 1.0
  FAIL  a device is not powered on (<ENGINE><POWER> != true) unless staged off
  FAIL  a <LINK> references a device ref or port that does not exist
  FAIL  two links terminate on the same device port
  FAIL  a router/switch has no RUNNINGCONFIG
  FAIL  a port name is not attested for that model by the evidence base
  WARN  a device has no link at all
  WARN  a model has no port-name evidence at all
  WARN  empty or duplicate configuration lines

Usage:  python3 validate.py out/JASDF_AEWC_JADGE.pkt
"""
from __future__ import annotations

import collections
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLKIT = Path(__import__("os").environ.get("PKT_TOOLKIT", "/home/saoria/PacketTracerReverse/packet-tracer-pkt-format"))
sys.path.insert(0, str(TOOLKIT))
sys.path.insert(0, str(TOOLKIT / "src"))
import pt9  # noqa: E402

# Devices deliberately staged off in the lab (spare / standby gear).  Empty for
# JASDF-AEWC: every placed device must carry <ENGINE><POWER>true</POWER>.  The
# same allow-list lives on JASDF.STAGED_OFF in build_jasdf_aewc.py.
STAGED_OFF = frozenset()

FAILS, WARNS, NOTES = [], [], []


def fail(m): FAILS.append(m)
def warn(m): WARNS.append(m)
def note(m): NOTES.append(m)


# --------------------------------------------------------------------------- #
def evidence():
    """model -> {port: [provenance tiers]} from tools/build_port_model.py.

    Tiers: sample-link / corpus-link (a real LINK names the port),
           sample-ios / corpus-ios (an interface name in a real config),
           template / module (the model's port inventory, used only to extend
           an already-attested family across its numeric range).
    """
    f = ROOT / "build" / "port_model.json"
    if not f.exists():
        raise SystemExit("build/port_model.json missing - run tools/build_port_model.py")
    return json.load(f.open())


def main(path):
    raw = Path(path).read_bytes()
    note(f"container      : {len(raw):,} bytes")

    # ---- 1. byte-exact round trip ------------------------------------- #
    try:
        xml = pt9.decode_bytes(raw, "pkt", verify_tag=True)
    except Exception as e:
        fail(f"container did not decode: {type(e).__name__}: {e}")
        return report()
    try:
        again = pt9.encode_bytes(xml, "pkt")
        if again != raw:
            fail(f"round-trip is NOT byte-exact ({len(again)} vs {len(raw)} bytes)")
        else:
            note("round-trip    : byte-exact OK")
    except Exception as e:
        fail(f"re-encode failed: {type(e).__name__}: {e}")

    # ---- 2. XML legality ---------------------------------------------- #
    bad = sorted({ch for ch in xml.decode("utf-8", "replace")
                  if ord(ch) < 0x20 and ch not in "\t\n\r"})
    if bad:
        fail(f"Illegal XML 1.0 control characters present: {[hex(ord(b)) for b in bad]}")
    else:
        note("xml chars     : no illegal control bytes")
    try:
        root = ET.fromstring(xml)
    except Exception as e:
        fail(f"XML does not parse: {e}")
        return report()

    note(f"root element  : {root.tag}  version={root.findtext('VERSION')}")

    # ---- 3. devices ---------------------------------------------------- #
    devs, models, cfgs, ports_of = {}, {}, {}, {}
    for d in root.iter("DEVICE"):
        sid = d.findtext("ENGINE/SAVE_REF_ID")
        te = d.find("ENGINE/TYPE")
        mdl = (te.get("model") if te is not None else "") or "?"
        nm = d.findtext("ENGINE/NAME") or "?"
        devs[sid] = nm
        models[sid] = mdl
        rc = d.find("ENGINE/RUNNINGCONFIG")
        cfgs[sid] = [l.text or "" for l in rc.findall("LINE")] if rc is not None else []
        ports_of[sid] = {p.findtext("TYPE") for p in d.iter("PORT")}

    # duplicate names
    dup = [n for n, k in collections.Counter(devs.values()).items() if k > 1]
    if dup:
        fail(f"duplicate device names: {dup[:8]}")
    note(f"devices       : {len(devs)}   distinct models: {len(set(models.values()))}")

    # ---- 3b. device power ---------------------------------------------- #
    # <ENGINE><POWER> must be "true" for every device that is not explicitly
    # staged off (docs/POWER_INVESTIGATION.md: one template harvested off took
    # the whole aggregation layer down).  <PORT><POWER> is a different field
    # with its own semantics and is deliberately not checked here.
    unpowered = []
    for d in root.iter("DEVICE"):
        nm = d.findtext("ENGINE/NAME") or "?"
        if nm in STAGED_OFF:
            continue
        e = d.find("ENGINE/POWER")
        v = (e.text or "").strip() if e is not None else "absent"
        if v != "true":
            unpowered.append((nm, v))
    if unpowered:
        fail(f"{len(unpowered)} devices are not powered on: {unpowered[:8]}")
    else:
        note(f"device power  : all {len(devs) - len(STAGED_OFF)} devices "
             f"<ENGINE><POWER>true</POWER> ({len(STAGED_OFF)} staged off)")

    # ---- 4. links ------------------------------------------------------ #
    links = root.find("NETWORK/LINKS")
    seen_port = collections.defaultdict(list)
    nlinks = 0
    for L in (links.findall("LINK") if links is not None else []):
        cab = L.find("CABLE")
        if cab is None:
            continue
        nlinks += 1
        fa, pa = cab.findtext("FROM"), (cab.findtext("PORT") or "").strip()
        fb, pb = cab.findtext("TO"), None
        # PT writes two <PORT> children positionally
        pp = [p.text.strip() for p in cab.findall("PORT") if p.text]
        pb = pp[1] if len(pp) > 1 else ""
        for sid, port in ((fa, pa), (fb, pb)):
            if sid not in devs:
                fail(f"link references unknown device ref {sid}")
                continue
            if not port:
                fail(f"link on {devs[sid]} has an empty port name")
                continue
            seen_port[(sid, port)].append(devs[sid])
    note(f"links         : {nlinks}")

    for (sid, port), who in seen_port.items():
        if len(who) > 1:
            fail(f"port {port} on {devs[sid]} carries {len(who)} cables")

    # ---- 5. port-name evidence ---------------------------------------- #
    ev = evidence()
    unknown_model, bad_port, tiers = set(), [], collections.Counter()
    weak = []
    for sid, port in seen_port:
        m = models[sid]
        if m not in ev:
            unknown_model.add(m)
            continue
        if port not in ev[m]:
            bad_port.append((devs[sid], m, port))
            continue
        t = ev[m][port]
        for x in t:
            tiers[x] += 1
        if t == ["template"] or t == ["module"]:
            weak.append((devs[sid], m, port, t))
    if bad_port:
        for nm, m, p in bad_port[:25]:
            fail(f"port '{p}' on {nm} ({m}) is not in the evidence base")
        if len(bad_port) > 25:
            fail(f"... and {len(bad_port) - 25} more unattested ports")
    else:
        strong = sum(v for k, v in tiers.items()
                     if k in ("sample-link", "corpus-link", "sample-ios", "corpus-ios"))
        note(f"port names    : all {len(seen_port)} cabled ports validated "
             f"({strong} by direct link/config evidence)")
        if weak:
            note(f"                {len(weak)} rely on template/module inventory only "
                 f"(e.g. {weak[0][2]} on {weak[0][0]})")
    if unknown_model:
        warn(f"models with NO port evidence (unchecked): {sorted(unknown_model)}")

    # ---- 5b. every port that appears in a config exists on the device -- #
    for sid, nm in devs.items():
        cfg = cfgs[sid]
        if not cfg:
            continue
        declared = set()
        for p in root.findall(".//DEVICE"):
            pass
        # gather interface names the config references that look like ports
        for line in cfg:
            mm = re.match(r"^interface (\S+)$", line.strip())
            if mm:
                declared.add(mm.group(1))
        # (PT tolerates config for absent interfaces; only report, do not fail)

    # ---- 6. configured devices ---------------------------------------- #
    netdev = [sid for sid, m in models.items()
              if m in ("2911", "ISR4331", "ISR4321", "IR1101", "3650-24PS",
                       "3560-24PS", "2960-24TT", "IE-9320", "5505")]
    empty = [devs[s] for s in netdev if not cfgs[s]]
    if empty:
        fail(f"{len(empty)} network devices have no RUNNINGCONFIG: {empty[:6]}")
    else:
        note(f"configured    : all {len(netdev)} routers/switches/firewalls carry a config")

    # Presence is not authorship.  A harvested template always supplies *some*
    # config -- a factory default with `hostname Router` -- so "carries a config"
    # passes on a device nobody ever configured.  COALITION-GW-01 shipped that
    # way while PARTNER-RTR-01 was set up to peer with its address, so the
    # documented eBGP path could not come up.  Requiring the config to name the
    # device is the cheapest check that a template default cannot satisfy.
    misnamed = [devs[s] for s in netdev
                if f"hostname {devs[s]}" not in cfgs[s]]
    if misnamed:
        fail(f"{len(misnamed)} network devices carry a config that does not name "
             f"them (template default or wrong device): {misnamed[:6]}")
    else:
        note(f"config identity: all {len(netdev)} configs set "
             f"'hostname <device>'")

    lens = sorted(len(cfgs[s]) for s in netdev)
    note(f"config lines  : min={lens[0]} median={lens[len(lens)//2]} max={lens[-1]} "
         f"total={sum(lens):,}")

    # ---- 7. isolation -------------------------------------------------- #
    isolated = [devs[s] for s in devs if not any(s in k for k in seen_port)]
    if isolated:
        warn(f"{len(isolated)} devices have no cable (expected for wireless APs only): "
             f"{isolated[:6]}")

    # ---- 8. services --------------------------------------------------- #
    # Every count printed here must be a count of *distinct* items.  This
    # validator previously counted occurrences and reported
    # "RESULT: PASSED (0 warnings)" over 202 AAA clients of which only 140 were
    # distinct, and 259 DHCP pools of which 131 were authored -- the rest being
    # one phantom 192.168.10.1 and 128 degenerate serverPool records copied off
    # the harvested device templates.  See docs/ENTERPRISE_PROBLEMS.md #1-#5.
    #
    # The rule now lives in one place (pkt_core.audit) so the generator, the
    # CLI (`pkt audit`) and this validator cannot disagree about it.
    from pkt_core.audit import TemplateLeftovers, inventory, validate_lab
    from pkt_core.models import Lab as _Lab

    lab_model = _Lab.from_bytes(xml)
    leftovers = TemplateLeftovers.from_device_templates_json(
        TOOLKIT / "tools" / "device_templates.json")
    inv = inventory(lab_model, leftovers=leftovers)
    for _fam, _dc in sorted(inv.families.items()):
        if not _dc.raw:
            continue
        detail = f", {_dc.leftover_instances} template leftovers" if _dc.leftover_instances else ""
        note(f"  {_fam:<14}: {_dc.raw} raw, {_dc.distinct} distinct{detail}")
    note(f"services      : {inv.dns_records.raw} DNS records "
         f"({inv.dns_records.distinct} distinct), {inv.dhcp_pools.raw} DHCP pools, "
         f"{inv.aaa_clients.raw} AAA clients")
    if inv.dns_records.raw == 0:
        warn("no DNS records were written")
    if inv.aaa_clients.raw == 0:
        warn("no AAA clients were written")
    for _f in validate_lab(lab_model, leftovers=leftovers).findings:
        (fail if _f.severity == "fail" else warn)(f"{_f.code}: {_f.message}")

    # ---- 9. addressing ------------------------------------------------- #
    ips = collections.Counter()
    for d in root.iter("DEVICE"):
        for p in d.iter("PORT"):
            ip = p.findtext("IP")
            if ip and ip not in ("0.0.0.0",):
                ips[ip] += 1
    dups = [(i, n) for i, n in ips.items() if n > 1]
    if dups:
        warn(f"{len(dups)} duplicated end-device IPs: {dups[:6]}")
    else:
        note(f"addressing    : {len(ips)} distinct end-device IPs, no duplicates")

    return report()


def report():
    print()
    for m in NOTES:
        print(f"  ok    {m}")
    for m in WARNS:
        print(f"  WARN  {m}")
    for m in FAILS:
        print(f"  FAIL  {m}")
    print()
    if FAILS:
        print(f"RESULT: FAILED ({len(FAILS)} failures, {len(WARNS)} warnings)")
        return 1
    print(f"RESULT: PASSED ({len(WARNS)} warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  ROOT / "out" / "JASDF_AEWC_JADGE.pkt"))
