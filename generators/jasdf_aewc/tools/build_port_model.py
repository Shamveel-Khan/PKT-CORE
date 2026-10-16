#!/usr/bin/env python3
"""Build build/port_model.json -- the set of port names each Packet Tracer
model is allowed to expose, with provenance.

Evidence tiers
--------------
  sample-link  : Cisco's own PT 9.0.1 sample labs (a LINK names the port)
  corpus-link  : 1,058-file community reference corpus (a LINK names the port)
  sample-ios   : interface names inside a RUNNINGCONFIG shipped by Cisco
  corpus-ios   : interface names inside a community RUNNINGCONFIG
  template     : the port inventory in tools/device_templates.json (how many
                 ports of each media type the model has), used only to extend
                 an *attested* family across its full numeric range
  module       : serial bays implied by the installed module (HWIC-2T/NIM-2T)
"""
import json, re, collections, sys
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
sys.path.insert(0, str(TK)); sys.path.insert(0, str(TK / 'tools'))
import lab_api
import xml.etree.ElementTree as ET

FAMILY = {
    'eCopperFastEthernet': 'FastEthernet',
    'eCopperGigabitEthernet': 'GigabitEthernet',
    'eFiberGigabitEthernet': 'GigabitEthernet',
    'eCopperEthernet': 'Ethernet',
    'eSmartSerial': 'Serial',
}

prov = collections.defaultdict(lambda: collections.defaultdict(set))

def add(model, port, tier):
    if model and port:
        prov[model][port.strip()].add(tier)

# ---- tier 1/2: link evidence ----------------------------------------- #
for f, tier in ((ROOT / 'build' / 'pt_saves_ports.json', 'sample-link'),
                (ROOT / 'build' / 'port_names.json', 'corpus-link')):
    if f.exists():
        for m, ports in json.load(f.open())['ports'].items():
            for p in ports:
                add(m, p, tier)

# ---- tier 3/4: running-config interface names ------------------------ #
for f, tier in ((ROOT / 'build' / 'pt_saves_ios.json', 'sample-ios'),
                (ROOT / 'build' / 'ios_samples.json', 'corpus-ios')):
    if f.exists():
        for m, samples in json.load(f.open()).items():
            for s in samples:
                for line in s.get('lines', []):
                    mm = re.match(r'^interface ((?:Gigabit|Fast|TenGigabit)Ethernet[\d/\.]+)$',
                                  line.strip())
                    if mm:
                        add(m, mm.group(1), tier)

# ---- tier 5/6: template inventory + module bays ---------------------- #
models, modules = lab_api.load_templates(str(TK / 'tools' / 'device_templates.json'))
counts = {}
for m, blob in models.items():
    el = ET.fromstring(blob.decode('utf-8', 'replace'))
    c = collections.Counter()
    for p in el.iter('PORT'):
        fam = FAMILY.get(p.findtext('TYPE'))
        if fam:
            c[fam] += 1
    bays = len([s for s in el.iter('SLOT')
                if s.findtext('TYPE') == 'eInterfaceCard' and s.find('MODULE') is None])
    counts[m] = (c, bays)

allowed = {}
for m, ports in prov.items():
    c, bays = counts.get(m, (collections.Counter(), 0))
    # a port name is only credible for this model if its media family exists on
    # the model at all -- this discards mis-attributed names from the corpus
    # (e.g. FastEthernet0/1 recorded against a 3650-24PS, which has no FE ports)
    ok_families = set(c)
    ports = {p: t for p, t in ports.items()
             if not re.match(r'^(Gigabit|Fast|TenGigabit)Ethernet', p)
             or any(p.startswith(f) for f in ok_families)}
    out = {}
    groups = collections.defaultdict(set)
    for p in ports:
        mm = re.match(r'^(.*?)(\d+)$', p)
        if mm:
            groups[mm.group(1)].append if False else groups[mm.group(1)].add(int(mm.group(2)))
        else:
            out[p] = sorted(ports[p])
    for prefix, idxs in groups.items():
        fam = None
        for f in ('GigabitEthernet', 'FastEthernet', 'Ethernet', 'Serial'):
            if prefix.startswith(f):
                fam = f
        tiers = set()
        for i in idxs:
            tiers |= ports.get(f'{prefix}{i}', set())
        lo, hi = min(idxs), max(idxs)
        if fam == 'Serial':
            # HWIC-2T / NIM-2T carry two eSmartSerial ports per bay
            n = max(2 * max(bays, 1), hi + 1)
            idxs = set(range(0, min(n, 8)))
        else:
            n = c.get(fam, 0)
            if n and lo >= 1:
                idxs = set(range(1, n + 1))
            elif n:
                idxs = set(range(0, n))
            else:
                idxs = set(range(lo, hi + 1))
        for i in idxs:
            out[f'{prefix}{i}'] = sorted(tiers | {'template' if fam != 'Serial' else 'module'})
    allowed[m] = out

json.dump(allowed, (ROOT / 'build' / 'port_model.json').open('w'), indent=1, sort_keys=True)
print(f'models modelled: {len(allowed)}')
for m in ('2911', 'ISR4331', 'ISR4321', 'IR1101', 'IE-9320', '3650-24PS',
          '3560-24PS', '2960-24TT', '5505', 'Server-PT', 'PC-PT',
          'AccessPoint-PT', 'Sniffer', 'CyberObserver'):
    ps = allowed.get(m, {})
    print(f'  {m:16s} {len(ps):3d} ports  e.g. {sorted(ps)[:6]}')
