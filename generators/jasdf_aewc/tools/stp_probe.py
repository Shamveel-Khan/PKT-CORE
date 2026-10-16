#!/usr/bin/env python3
"""Which STP/portfast option leaves 2960 access ports non-forwarding in PT?"""
import sys
from pathlib import Path

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
sys.path.insert(0, str(TK)); sys.path.insert(0, str(TK / 'tools')); sys.path.insert(0, str(Path(__file__).parent.parent))
import lab_api, jasdf_kit as K

VARIANTS = {
 "full":  ["spanning-tree mode rapid-pvst", "spanning-tree extend system-id",
           "spanning-tree portfast default", "spanning-tree portfast bpduguard default",
           "spanning-tree loopguard default", "spanning-tree vlan 10 root primary"],
 "nobpdu":["spanning-tree mode rapid-pvst", "spanning-tree extend system-id",
           "spanning-tree portfast default", "spanning-tree loopguard default"],
 "noloop":["spanning-tree mode rapid-pvst", "spanning-tree extend system-id",
           "spanning-tree portfast default", "spanning-tree portfast bpduguard default"],
 "plain": ["spanning-tree mode pvst", "spanning-tree extend system-id"],
}

def build(out, variant, portfast_iface):
    models, modules = lab_api.load_templates(str(TK / 'tools' / 'device_templates.json'))
    lab = lab_api.Lab(str(TK / 'tools' / 'network_seed.xml'), models, modules)
    lab.prune_seed_devices()
    stp = VARIANTS[variant]
    if portfast_iface:
        stp = stp + ["interface FastEthernet0/1", " spanning-tree portfast",
                     "interface FastEthernet0/2", " spanning-tree portfast",
                     "interface FastEthernet0/3", " spanning-tree portfast"]
    scfg = ["!", "hostname SW-T", "!", "spanning-tree mode rapid-pvst"] + stp + [
        "!", "vlan 10", " name OPS", "!",
        "interface FastEthernet0/1", " switchport mode access", " switchport access vlan 10", " no shutdown",
        "interface FastEthernet0/2", " switchport mode access", " switchport access vlan 10", " no shutdown",
        "interface FastEthernet0/3", " switchport mode access", " switchport access vlan 10", " no shutdown",
        "interface Vlan10", " ip address 10.9.9.1 255.255.255.0", " no shutdown", "!",
        "interface GigabitEthernet0/1", " switchport mode trunk", " no shutdown", "!", "end"]
    sw = lab.add_device("2960-24TT", "SW-T", 400, 300, ios_config=scfg)
    for i, nm in enumerate(("PC-1", "PC-2", "PC-3")):
        pc = lab.add_device("PC-PT", nm, 250 + i * 150, 550,
                            pc_ip=(f"10.9.9.{10+i}", "255.255.255.0", "10.9.9.1"))
        lab.link(sw, f"FastEthernet0/{i+1}", pc, "FastEthernet0")
    lab.save(str(out)); print("wrote", out)

if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2], sys.argv[3] == "iface")
