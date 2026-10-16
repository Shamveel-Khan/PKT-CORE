#!/usr/bin/env python3
"""Mine the reference corpus for authoritative PT facts:
   (1) model -> port names actually used in real LINKs
   (2) real XML shape of a configured DNS server (RESOURCE-RECORD)
   (3) ASA 5505 / WLC / IR1101 / IE-9320 usage samples
"""
import sys, re, json, glob, collections, os
from pathlib import Path

def _find_toolkit() -> Path:
    """PKT_TOOLKIT if set, else search upward for tools/lab_api.py + src/pkt_core.

    Portability (problem 32): never hardcode an absolute checkout path -- it
    only works on the machine that built the lab.
    """
    env = os.environ.get("PKT_TOOLKIT")
    if env:
        return Path(env)
    for cand in Path(__file__).resolve().parent.parents:
        if (cand / "tools" / "lab_api.py").is_file() and (cand / "src" / "pkt_core").is_dir():
            return cand
    raise SystemExit("error: cannot find the pkt-core toolkit; set PKT_TOOLKIT")


TK = _find_toolkit()
sys.path.insert(0, str(TK))
sys.path.insert(0, str(TK / 'tools'))
import pt9
import xml.etree.ElementTree as ET

CORPUS = os.environ.get('PT_CORPUS', str(TK / 'corpus' / 'files'))
files = sorted(glob.glob(os.path.join(CORPUS, '**', '*.pkt'), recursive=True)) + \
        sorted(glob.glob(os.path.join(CORPUS, '**', '*.pka'), recursive=True))
print(f'scanning {len(files)} files')

portmap = collections.defaultdict(collections.Counter)
dns_samples = []
asa_samples = []
wlc_samples = []
ir_samples = []
ios_samples = collections.defaultdict(list)
ok = fail = 0

for f in files:
    try:
        xml = pt9.decode(f, 'pkt', verify_tag=False)
        root = ET.fromstring(xml)
    except Exception:
        fail += 1; continue
    ok += 1
    for net in root.iter('NETWORK'):
        devs = {}
        for d in net.iter('DEVICE'):
            sid = d.findtext('ENGINE/SAVE_REF_ID')
            t = d.findtext('ENGINE/TYPE') or ''
            mm = re.search(r'model="([^"]*)"', t)
            mdl = mm.group(1) if mm else t
            if sid: devs[sid] = mdl
            # capture real RUNNINGCONFIG per model
            rc = d.find('ENGINE/RUNNINGCONFIG')
            if rc is not None and mdl in ('5505','WLC-2504','WLC-3504','IR1101','IE-9320','ISR4331','3560-24PS','3650-24PS'):
                if len(ios_samples[mdl]) < 4:
                    ios_samples[mdl].append((os.path.basename(f), [l.text or '' for l in rc.findall('LINE')]))
            eng = d.find('ENGINE')
            if eng is not None:
                nd = eng.find('DNS_SERVER/NAMESERVER-DATABASE')
                if nd is not None and len(list(nd)):
                    if len(dns_samples) < 3:
                        dns_samples.append((os.path.basename(f), ET.tostring(nd, encoding='unicode')[:1800]))
                if mdl == '5505' and len(asa_samples) < 2:
                    asa_samples.append((os.path.basename(f), d.findtext('ENGINE/RUNNINGCONFIG') and
                                        '\n'.join((l.text or '') for l in d.findall('ENGINE/RUNNINGCONFIG/LINE'))))
        for L in net.iter('LINK'):
            c = L.find('CABLE')
            if c is None: continue
            fa, pa = c.findtext('FROM'), c.findtext('PORT')
            fb, pb = c.findtext('TO'), c.findtext('PORT')
            if fa in devs and pa: portmap[devs[fa]][pa.strip()] += 1
            if fb in devs and pb: portmap[devs[fb]][pb.strip()] += 1

print(f'decoded {ok}, failed {fail}')
out = {}
for mdl in sorted(portmap):
    ports = portmap[mdl]
    out[mdl] = dict(ports)
    top = ports.most_common(30)
    print(f'\n{mdl}  ({len(ports)} distinct port names)')
    print('   ', ', '.join(f'{p}×{n}' for p, n in top))

json.dump({'ports': out,
           'counts': {k: len(v) for k, v in portmap.items()}},
          open('build/port_names.json', 'w'), indent=1)

print('\n\n=========== DNS NAMESERVER-DATABASE samples ===========')
for name, s in dns_samples:
    print('---', name); print(s)

print('\n\n=========== ASA 5505 running-config samples ===========')
for name, s in asa_samples[:2]:
    print('---', name); print((s or '')[:2500])

json.dump({k: v for k, v in ios_samples.items()}, open('build/ios_samples.json','w'), indent=1)
