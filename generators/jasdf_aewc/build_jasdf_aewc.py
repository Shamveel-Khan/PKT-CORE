#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
build_jasdf_aewc.py -- generate a large, fully-configured Cisco Packet Tracer
model of a Japan Air Self-Defense Force (JASDF) Airborne Early Warning &
Control (AEW&C / AWACS) enterprise.

    python3 build_jasdf_aewc.py --profile enterprise --out out/JASDF_AEWC_JADGE.pkt

Architecture modelled (mirrors the real JASDF air-defence system):

    Air Defense Command (ADC) HQ ......... Yokota AB
    Air Surveillance & Control Gp (ASCG) . Iruma AB  -- JADGE core data centre
    Control & Reporting Centers (CRC) .... Misawa / Iruma / Kasuga / Naha
    Fixed radar sites (J/FPS-x) .......... 16 named sites, Wakkanai -> Yonaguni
    AEW&C platforms ...................... E-767 / E-2D / E-2C / RC-2
    Air bases ............................ 10 bases
    Datalink & SATCOM ground entry ....... TDL-GW / SATCOM-GW serial concentrators
    Transport ............................ OSPF multi-area + iBGP AS65001
    Coalition boundary ................... eBGP AS65002 + IPsec

Tiers:  backbone L3 core  ->  core routers  ->  regional WAN aggregation hubs
        ->  site routers (router-on-a-stick + HSRP)  ->  access  ->  end systems,
plus a parallel firewalled tactical-datalink tier feeding the airborne segment.

Everything is generated: placement, modules, cabling, complete IOS and ASA
running-configurations, server services (DNS/DHCP/AAA/NTP/Syslog/HTTP/FTP),
and end-device addressing.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLKIT = Path(__import__("os").environ.get("PKT_TOOLKIT", "/home/saoria/PacketTracerReverse/packet-tracer-pkt-format"))
sys.path.insert(0, str(TOOLKIT))
sys.path.insert(0, str(TOOLKIT / "tools"))
sys.path.insert(0, str(ROOT))

import lab_api                       # noqa: E402
import jasdf_kit as K                # noqa: E402
import xml.etree.ElementTree as ET   # noqa: E402

M24 = "255.255.255.0"
M30 = "255.255.255.252"

PROFILES = {
    "smoke": dict(awacs=1, e2d=1, e2c=1, rc2=0, radar=4, airbases=3,
                  consoles=1, onboard_ap=False, base_wlan=False),
    "standard": dict(awacs=2, e2d=3, e2c=2, rc2=1, radar=10, airbases=6,
                     consoles=2, onboard_ap=False, base_wlan=True),
    "enterprise": dict(awacs=4, e2d=6, e2c=4, rc2=2, radar=16, airbases=10,
                       consoles=3, onboard_ap=True, base_wlan=True),
}

SITE_YOKOTA, SITE_IRUMA, SITE_TDL, SITE_MGMT = 10, 11, 50, 200
SITE_CRC = {"NORTH": 12, "CENTRAL": 36, "WEST": 13, "SW": 14}
SITE_BASE = {"HAMAMATSU": 26, "MISAWA": 27, "KOMAKI": 28, "IRUMA": 29,
             "NAHA": 30, "KASUGA": 31, "CHITOSE": 32, "HYAKURI": 33,
             "KOMATSU": 34, "NYUTABARU": 35, "GIFU": 37, "TSUIKI": 38,
             "ASHIYA": 39, "MATSUSHIMA": 40}
SITE_RADAR0 = 41

V_OPS, V_MISSION, V_VOICE, V_MGMT, V_WIFI, V_SRV, V_TDL, V_RADAR = 10, 20, 30, 40, 50, 60, 70, 80
SITE_VLANS = [V_OPS, V_MISSION, V_VOICE, V_MGMT, V_WIFI, V_SRV]
SRV_GW = f"10.{SITE_IRUMA}.{V_SRV}.1"

net = lambda s, v: f"10.{s}.{v}.0"           # noqa: E731
gw = lambda s, v: f"10.{s}.{v}.1"            # noqa: E731
host = lambda s, v, h: f"10.{s}.{v}.{h}"     # noqa: E731

SRV = {  # every JADGE data-centre service address (VLAN 60 @ Iruma)
    "dns": host(SITE_IRUMA, V_SRV, 17), "dns2": host(SITE_IRUMA, V_SRV, 18),
    "dhcp": host(SITE_IRUMA, V_SRV, 19), "ntp": host(SITE_IRUMA, V_SRV, 14),
    "syslog": host(SITE_IRUMA, V_SRV, 15), "aaa": host(SITE_IRUMA, V_SRV, 16),
    "tftp": host(SITE_IRUMA, V_SRV, 28), "web": host(SITE_IRUMA, V_SRV, 29),
}

RADAR_SITES = [
    ("NORTH",   "WAKKANAI",   "J/FPS-3",    "Wakkanai, Hokkaido - northern approach"),
    ("NORTH",   "NEMURO",     "J/FPS-3",    "Nemuro, Hokkaido - Nemuro Strait"),
    ("NORTH",   "SHIBETSU",   "J/FPS-3",    "Shibetsu, Hokkaido"),
    ("NORTH",   "OKUSHIRI",   "J/FPS-3",    "Okushiri Island, Sea of Japan"),
    ("NORTH",   "TOBETSU",    "J/FPS-3",    "Tobetsu, Hokkaido"),
    ("NORTH",   "OMINATO",    "J/FPS-3",    "Ominato, Aomori - Tsugaru Strait"),
    ("CENTRAL", "SADO",       "J/FPS-3",    "Sado Island, Niigata"),
    ("CENTRAL", "WAJIMA",     "J/FPS-5",    "Wajima, Noto Peninsula - mobile J/FPS-5"),
    ("CENTRAL", "OMAEZAKI",   "J/FPS-3",    "Omaezaki, Shizuoka - Pacific approach"),
    ("WEST",    "TSUSHIMA",   "J/FPS-3",    "Tsushima, Nagasaki - Korea Strait"),
    ("WEST",    "IKI",        "J/FPS-3",    "Iki Island, Nagasaki"),
    ("WEST",    "SEFURI",     "J/FPS-3",    "Sefuri-san, Fukuoka - Kyushu"),
    ("SW",      "KUMEJIMA",   "J/FPS-5",    "Kumejima, Okinawa"),
    ("SW",      "MIYAKO",     "J/FPS-3Kai", "Miyakojima, Okinawa - East China Sea gap"),
    ("SW",      "YONAGUNI",   "J/FPS-7",    "Yonaguni, Okinawa - south-western tip"),
    ("SW",      "OKINOERABU", "J/FPS-5",    "Okinoerabujima, Kagoshima"),
]
REGIONS = ["NORTH", "CENTRAL", "WEST", "SW"]
AIRBASES = ["HAMAMATSU", "MISAWA", "KOMAKI", "IRUMA", "NAHA",
            "KASUGA", "CHITOSE", "HYAKURI", "KOMATSU", "NYUTABARU"]
BASE_REGION = {"HAMAMATSU": "CENTRAL", "IRUMA": "CENTRAL", "KOMAKI": "CENTRAL",
               "KOMATSU": "CENTRAL", "GIFU": "CENTRAL",
               "MISAWA": "NORTH", "CHITOSE": "NORTH", "HYAKURI": "NORTH",
               "MATSUSHIMA": "NORTH",
               "KASUGA": "WEST", "NYUTABARU": "WEST", "TSUIKI": "WEST",
               "ASHIYA": "WEST",
               "NAHA": "SW"}

GE = lambda i: f"GigabitEthernet1/0/{i}"     # noqa: E731  (3650-24PS)
FE = lambda i: f"FastEthernet0/{i}"          # noqa: E731  (3560-24PS / 2960-24TT)


class P2P:
    def __init__(self): self.i = 0

    def next(self):
        i = self.i; self.i += 1
        return (f"10.0.{i // 64}.{(i % 64) * 4 + 1}",
                f"10.0.{i // 64}.{(i % 64) * 4 + 2}", M30)


class JASDF:
    # PT-attested NIC names for the monitoring appliances
    MON_PORT = {"jump": "FastEthernet0", "nms": "FastEthernet0",
                "cobs": "GigabitEthernet0", "tap": "Ethernet1"}

    # Devices this lab deliberately stages off (spare / standby gear that must
    # come up powered-down).  Empty for JASDF-AEWC: every placed device is part
    # of the live defence network and must power on at load.  See
    # power_all_devices() and the same allow-list in validate.py.
    STAGED_OFF = frozenset()

    def __init__(self, profile):
        self.p = PROFILES[profile]
        self.profile = profile
        self.models, self.modules = lab_api.load_templates(
            str(TOOLKIT / "tools" / "device_templates.json"))
        self.lab = lab_api.Lab(str(TOOLKIT / "tools" / "network_seed.xml"),
                               self.models, self.modules)
        self.seed_removed = self.lab.prune_seed_devices()
        # Placement is owned by lab_api.Layout (label-inclusive boxes, greedy
        # row-major packing per semantic tier, 80-unit centre floor, canvas
        # wrap).  Kept alongside the lab so every add() goes through it.
        self.layout = lab_api.Layout()
        self.sid, self.meta = {}, {}
        self.has_nic_ip = set()
        self.routed = []                 # (dev, port, ip, mask)
        self.links = []
        self.dns, self.wlans = [], []
        self.p2p = P2P()
        self.servers = []
        self.aircraft = []
        self.serial_meta = []

    # -- primitives ------------------------------------------------------ #
    def add(self, key, model, name, x=None, y=None, *, group=None, role="",
            site="", ip=None, cfg=None, pc_ip=None, modules=None, dns=True):
        """Add a device.  Placement is owned by lab_api.Layout.

        x/y are legacy band-anchor *hints* from the old hand-typed grids (the
        310-unit airframe pitch, 175x130 server grid, 400-unit CRC columns,
        ...): they no longer position anything literally.  Passing them is
        harmless and keeps old call sites compiling; omitting them is equally
        fine.  Devices are packed row-major inside their semantic tier band
        (see lab_api.tier_for_name) with label-inclusive boxes and the 80-unit
        centre floor, so no two devices -- or their captions -- can collide."""
        grp = group or lab_api.tier_for_name(name)
        p = self.layout.place(name, model, group=grp)
        sid = self.lab.add_device(model, name, p.x, p.y,
                                  ios_config=cfg, pc_ip=pc_ip)
        # Fill bays in order.  Omitting the bay means "the next empty one";
        # install_module no longer accepts bay=N for N > 0, because that indexes
        # the currently-empty slots and silently skips a bay as they fill
        # (a different N now means the absolute bay index).
        for mod in (modules or []):
            self.lab.install_module(sid, mod)
        self.sid[key] = sid
        self.meta[key] = dict(name=name, model=model, role=role, site=site, ip=ip)
        if pc_ip:
            self.has_nic_ip.add(key)
        if dns and ip:
            self.dns.append((name.lower(), ip))
        return sid

    def link(self, a, ap, b, bp, kind="copper", dce=None, clock=2_000_000):
        self.lab.link(self.sid[a], ap, self.sid[b], bp, kind=kind,
                      dce=self.sid[dce] if dce else None, clock=clock)
        self.links.append((a, ap, b, bp, kind, dce))

    def rlink(self, a, ap, b, bp):
        ia, ib, m = self.p2p.next()
        self.routed += [(a, ap, ia, m), (b, bp, ib, m)]
        self.link(a, ap, b, bp)
        return ia, ib

    def slink(self, a, ap, b, bp, dce, clock=2_000_000):
        """Point-to-point serial bearer: allocates a /30, registers both ends as
        routed interfaces (so router_config emits address + no shutdown +
        clock rate on the DCE), and cables them."""
        ia, ib, m = self.p2p.next()
        self.routed += [(a, ap, ia, m), (b, bp, ib, m)]
        self.link(a, ap, b, bp, kind="serial", dce=dce, clock=clock)
        self.serial_meta.append((a, ap, b, bp, dce, clock))
        return ia, ib

    def ifaces(self, key):
        return [(p, ip, m) for (d, p, ip, m) in self.routed if d == key]

    def wans(self, key, area=0):
        out = []
        for _p, ip, m in self.ifaces(key):
            o = ip.split(".")
            out.append((f"{o[0]}.{o[1]}.{o[2]}.0",
                        "0.0.0.3" if m == M30 else "0.0.0.255", area))
        return out

    def set_cfg(self, key, cfg):
        eng = self.lab._els[self.sid[key]].find("ENGINE")
        for rc in list(eng.findall("RUNNINGCONFIG")):
            eng.remove(rc)
        rc = ET.SubElement(eng, "RUNNINGCONFIG")
        for line in cfg:
            ET.SubElement(rc, "LINE").text = line

    def wireless(self, key, ssid):
        self.lab.set_wireless(self.sid[key], ssid=ssid, auth_type=5,
                              encrypt_type=5, password="jasdf-wlan-9f3c")
        self.wlans.append((self.meta[key]["name"], ssid))

    def svis(self, key):
        """Router-on-a-stick subinterfaces + HSRP for a site router."""
        return [p for p, _i, _m in self.ifaces(key)
                if p.startswith("GigabitEthernet") and "." in p]

    # ================================================================== #
    def build_backbone(self):
        self.add("bb1", "3650-24PS", "JADGE-BB-SW-01", 900, 900, ip="10.255.0.11",
                 role="JADGE backbone L3 core switch A (OSPF area 0, iBGP edge)")
        self.add("bb2", "3650-24PS", "JADGE-BB-SW-02", 1400, 900, ip="10.255.0.12",
                 role="JADGE backbone L3 core switch B (OSPF area 0, iBGP edge)")
        self.add("cr1", "ISR4331", "CORE-RTR-01", 900, 620, ip="10.255.0.1",
                 role="JADGE core router / OSPF ABR / iBGP speaker")
        self.add("cr2", "ISR4331", "CORE-RTR-02", 1400, 620, ip="10.255.0.2",
                 role="JADGE core router / OSPF ABR / iBGP speaker")
        self.add("we1", "2911", "WAN-EDGE-01", 600, 380, ip="10.255.0.3",
                 role="JASDF wide-area transport edge (primary)", modules=["HWIC-2T"])
        self.add("we2", "2911", "WAN-EDGE-02", 900, 380, ip="10.255.0.4",
                 role="JASDF wide-area transport edge (backup)", modules=["HWIC-2T"])

        for i, r in enumerate(REGIONS):
            self.add(f"hub{r}", "3650-24PS", f"REG-HUB-{r}", 250 + i * 400, 1550,
                     ip=f"10.255.2.{i + 1}",
                     role=f"{r} regional WAN aggregation hub (L3), JADGE area hub")

        self.add("agg1", "3650-24PS", "DATALINK-AGG-01", 2100, 1550, ip="10.255.3.1",
                 role="Tactical datalink aggregation A (Link-16 / SATCOM ground entry)")
        self.add("agg2", "3650-24PS", "DATALINK-AGG-02", 2550, 1550, ip="10.255.3.2",
                 role="Tactical datalink aggregation B (Link-16 / SATCOM ground entry)")

        for i in range(1, 5):
            self.add(f"tdl{i}", "2911", f"TDL-GW-{i:02d}", 2050 + (i - 1) * 130, 1150,
                     ip=f"10.255.5.{i}", modules=["HWIC-2T"] * 4,
                     role=f"Link-16 / TADIL-J ground entry, channel group {i}")
            self.add(f"sat{i}", "2911", f"SATCOM-GW-{i:02d}", 2050 + (i - 1) * 130, 950,
                     ip=f"10.255.6.{i}", modules=["HWIC-2T"] * 4,
                     role=f"X/Ku-band SATCOM ground entry, terminal group {i}")

        self.add("cgw", "ISR4331", "COALITION-GW-01", 3100, 620, ip="10.255.0.7",
                 role="Coalition / exercise boundary gateway (eBGP AS65002)")
        self.add("mgw", "ISR4331", "MGMT-GW-01", 1700, 620, ip="10.255.0.8",
                 role="Out-of-band management gateway / NOSC edge")

    # ------------------------------------------------------------------ #
    def build_jadge_dc(self):
        s = SITE_IRUMA
        self.add("dcc1", "3650-24PS", "JADGE-DC-CORE-01", 200, 1230, site="IRUMA",
                 ip=host(s, V_SRV, 11), role="JADGE data-centre core switch A (L2/SVI)")
        self.add("dcc2", "3650-24PS", "JADGE-DC-CORE-02", 560, 1230, site="IRUMA",
                 ip=host(s, V_SRV, 12), role="JADGE data-centre core switch B (L2/SVI)")
        self.add("dca1", "2960-24TT", "JADGE-DC-ACC-01", 200, 1480, site="IRUMA",
                 ip=host(s, V_SRV, 13), role="JADGE DC server access switch A")
        self.add("dca2", "2960-24TT", "JADGE-DC-ACC-02", 560, 1480, site="IRUMA",
                 ip=host(s, V_SRV, 14), role="JADGE DC server access switch B")

        self.servers = [
            ("s_jadge",  "JADGE-C2-SVR",     21, "JADGE air-defence C2 processor"),
            ("s_fusion", "TRACK-FUSION-SVR", 22, "Multi-sensor track fusion engine"),
            ("s_l16",    "LINK16-GW-SVR",    23, "Link-16 / TADIL-J gateway and translation"),
            ("s_radar",  "RADAR-FUSION-SVR", 24, "Radar plot extraction and fusion"),
            ("s_plan",   "MISSION-PLAN-SVR", 25, "ATO / ACO mission planning"),
            ("s_ato",    "AIR-TASKING-SVR",  26, "Air tasking order distribution"),
            ("s_cop",    "COP-SERVER",       27, "Common operational picture service"),
            ("s_dns",    "DNS-SVR",          17, "Authoritative DNS - jasdf.mod.go.jp"),
            ("s_dns2",   "DNS-SVR-02",       18, "Secondary / forwarding DNS"),
            ("s_dhcp",   "DHCP-SVR",         19, "Enterprise DHCP"),
            ("s_ntp",    "NTP-SVR",          14, "Stratum-2 NTP, GPS disciplined"),
            ("s_syslog", "SYSLOG-SVR",       15, "Central syslog / SIEM collector"),
            ("s_aaa",    "AAA-SVR",          16, "RADIUS + TACACS+ (Cisco ACS)"),
            ("s_tftp",   "TFTP-SVR",         28, "Configuration and image archive"),
            ("s_web",    "MISSION-WEB-SVR",  29, "Mission portal (HTTPS)"),
            ("s_mail",   "MAIL-SVR",         30, "Official mail relay"),
            ("s_ca",     "PKI-CA-SVR",       31, "JASDF internal certificate authority"),
            ("s_flow",   "NETFLOW-SVR",      32, "NetFlow / IPFIX collector"),
            ("s_hist",   "DATA-HISTORIAN",   33, "Track and mission data historian"),
            ("s_backup", "BACKUP-SVR",       34, "Nightly configuration backup"),
            ("s_ids",    "CYBER-OBS-SVR",    35, "Behavioural anomaly detection"),
        ]
        for i, (key, name, h, desc) in enumerate(self.servers):
            self.add(key, "Server-PT", name, 130 + (i % 5) * 175,
                     1650 + (i // 5) * 130, site="IRUMA", role=desc,
                     ip=host(s, V_SRV, h), cfg=["!", f"! {desc}", "!", "end"],
                     pc_ip=(host(s, V_SRV, h), M24, SRV_GW))

        self.add("fwj", "5505", "FW-JADGE-CORE", 60, 900, site="IRUMA",
                 ip="10.99.1.2", role="JADGE core enclave firewall (outside/inside)")
        self.add("fwt", "5505", "FW-TDL-DMZ", 2550, 1230, site="IRUMA",
                 ip="10.99.3.2", role="Tactical datalink / SATCOM DMZ firewall")
        self.add("fwc", "5505", "FW-COALITION", 3100, 400, site="IRUMA",
                 ip="10.99.6.2", role="Coalition cross-domain boundary firewall")
        self.add("fwm", "5505", "FW-MGMT", 2000, 620, site="MGMT",
                 ip="10.99.8.2", role="Management enclave firewall")

    # ------------------------------------------------------------------ #
    def build_hq(self):
        s = SITE_YOKOTA
        self.add("hq1", "ISR4331", "ADC-HQ-RTR-01", 1000, 1230, site="YOKOTA",
                 ip=host(s, V_MGMT, 2), role="ADC HQ WAN router (active) / site ABR")
        self.add("hq2", "ISR4331", "ADC-HQ-RTR-02", 1350, 1230, site="YOKOTA",
                 ip=host(s, V_MGMT, 3), role="ADC HQ WAN router (standby) / site ABR")
        self.add("hqd", "3560-24PS", "ADC-HQ-DSW", 1000, 1480, site="YOKOTA",
                 ip=host(s, V_MGMT, 4), role="ADC HQ distribution switch (L2/SVI)")
        self.add("hqa", "2960-24TT", "ADC-HQ-ASW", 1350, 1480, site="YOKOTA",
                 ip=host(s, V_MGMT, 6), role="ADC HQ access switch")
        for key, name, x, role, h in [
                ("hq_cdr", "ADC-CDR-PC", 900, "Air Defense Commander console", 20),
                ("hq_ops", "ADC-OPS-PC", 1060, "ADC operations officer console", 21),
                ("hq_int", "ADC-INTEL-PC", 1220, "ADC intelligence fusion console", 22),
                ("hq_lia", "ADC-LIAISON-PC", 1380, "Coalition liaison console", 23)]:
            self.add(key, "PC-PT", name, x, 1700, site="YOKOTA", role=role,
                     ip=host(s, V_OPS, h),
                     pc_ip=(host(s, V_OPS, h), M24, gw(s, V_OPS)))
        self.add("hq_cop", "Server-PT", "ADC-COP-SVR", 1550, 1480, site="YOKOTA",
                 ip=host(s, V_SRV, 20), role="ADC strategic COP display server",
                 cfg=["!", "! strategic common operational picture server", "!", "end"],
                 pc_ip=(host(s, V_SRV, 20), M24, gw(s, V_SRV)))

        m = SITE_MGMT
        self.add("msw", "2960-24TT", "NOSC-SW-01", 2000, 900, site="MGMT",
                 ip=host(m, V_MGMT, 6), role="NOSC management access switch")
        self.add("jump", "Server-PT", "NOSC-JUMP-SVR", 1850, 1120, site="MGMT",
                 ip=host(m, V_MGMT, 20), role="Privileged-access jump host",
                 pc_ip=(host(m, V_MGMT, 20), M24, gw(m, V_MGMT)))
        self.add("nms", "Server-PT", "NOSC-NMS-SVR", 2000, 1120, site="MGMT",
                 ip=host(m, V_MGMT, 21), role="SNMP / fault management",
                 pc_ip=(host(m, V_MGMT, 21), M24, gw(m, V_MGMT)))
        self.add("cobs", "CyberObserver", "NOSC-CYBER-OBS", 2150, 1120, site="MGMT",
                 ip=host(m, V_MGMT, 22), role="Cyber Observer behavioural IDS",
                 pc_ip=(host(m, V_MGMT, 22), M24, gw(m, V_MGMT)))
        self.add("tap", "Sniffer", "NOSC-TAP-SNIFFER", 2300, 1120, site="MGMT",
                 ip=host(m, V_MGMT, 23), role="Packet capture / monitoring tap",
                 pc_ip=(host(m, V_MGMT, 23), M24, gw(m, V_MGMT)))

    # ------------------------------------------------------------------ #
    def build_crcs(self):
        self.crcs = []
        for i, region in enumerate(REGIONS):
            s, tag, k = SITE_CRC[region], f"CRC-{region}", f"crc{region}"
            x = 250 + i * 400
            self.add(f"{k}r1", "ISR4331", f"{tag}-RTR-01", x, 1880, site=tag,
                     ip=host(s, V_MGMT, 2),
                     role=f"{tag} C2 router (HSRP active) / site ABR")
            self.add(f"{k}r2", "ISR4331", f"{tag}-RTR-02", x + 190, 1880, site=tag,
                     ip=host(s, V_MGMT, 3),
                     role=f"{tag} C2 router (HSRP standby) / site ABR")
            self.add(f"{k}d", "3560-24PS", f"{tag}-DSW", x + 95, 2100, site=tag,
                     ip=host(s, V_MGMT, 4), role=f"{tag} distribution switch (L2)")
            self.add(f"{k}t", "Server-PT", f"{tag}-TRACK-SVR", x, 2320, site=tag,
                     ip=host(s, V_SRV, 20), role=f"{tag} track server / display processor",
                     cfg=["!", "! track server / display processor", "!", "end"],
                     pc_ip=(host(s, V_SRV, 20), M24, gw(s, V_SRV)))
            self.add(f"{k}p", "Server-PT", f"{tag}-DISPLAY-SVR", x + 190, 2320, site=tag,
                     ip=host(s, V_SRV, 21), role=f"{tag} operator display / HMI server",
                     cfg=["!", "! operator display server", "!", "end"],
                     pc_ip=(host(s, V_SRV, 21), M24, gw(s, V_SRV)))
            for j, (sfx, role, h) in enumerate(
                    [("ASO", "Air Surveillance Officer", 20),
                     ("WC", "Weapons Controller", 21),
                     ("SDO", "Senior Duty Officer", 22)][:self.p["consoles"]]):
                self.add(f"{k}{sfx.lower()}", "PC-PT", f"{tag}-{sfx}-PC",
                         x - 60 + j * 130, 2500, site=tag, role=f"{role} console",
                         ip=host(s, V_OPS, h),
                         pc_ip=(host(s, V_OPS, h), M24, gw(s, V_OPS)))
            self.crcs.append(dict(region=region, tag=tag, key=k, site=s))

    # ------------------------------------------------------------------ #
    def build_radars(self):
        self.radars = []
        for idx, (region, name, sysname, desc) in enumerate(RADAR_SITES[:self.p["radar"]]):
            s = SITE_RADAR0 + idx
            bx, by = 120 + (idx % 8) * 310, 2800 + (idx // 8) * 620
            self.add(f"rdr{idx}r", "IR1101", f"RDR-{name}-RTR", bx, by, site=name,
                     ip=host(s, V_MGMT, 2),
                     role=f"{sysname} radar site router - {desc}")
            self.add(f"rdr{idx}s", "IE-9320", f"RDR-{name}-SW", bx, by + 180, site=name,
                     ip=host(s, V_RADAR, 3),
                     role=f"{sysname} radar site industrial switch")
            self.add(f"rdr{idx}p", "Server-PT", f"RDR-{name}-RSP", bx + 10, by + 360,
                     site=name, ip=host(s, V_RADAR, 20),
                     role=f"{sysname} radar signal processor",
                     cfg=["!", f"! {sysname} radar signal processor", "!", "end"],
                     pc_ip=(host(s, V_RADAR, 20), M24, gw(s, V_RADAR)))
            if idx < 8:
                self.add(f"rdr{idx}o", "PC-PT", f"RDR-{name}-OPS", bx + 190, by + 360,
                         site=name, ip=host(s, V_RADAR, 21),
                         role=f"{sysname} radar site operator console",
                         pc_ip=(host(s, V_RADAR, 21), M24, gw(s, V_RADAR)))
            self.radars.append(dict(idx=idx, region=region, name=name, sys=sysname, site=s))

    # ------------------------------------------------------------------ #
    def build_airbases(self):
        self.bases = []
        for idx, name in enumerate(AIRBASES[:self.p["airbases"]]):
            s, region = SITE_BASE[name], BASE_REGION[name]
            bx, by = 120 + (idx % 5) * 430, 4200 + (idx // 5) * 560
            self.add(f"ab{idx}r", "ISR4321", f"AB-{name}-RTR", bx, by, site=name,
                     ip=host(s, V_MGMT, 2), role=f"{name} Air Base WAN router / site ABR")
            self.add(f"ab{idx}d", "3560-24PS", f"AB-{name}-DSW", bx + 200, by, site=name,
                     ip=host(s, V_MGMT, 3), role=f"{name} Air Base distribution switch (L2)")
            self.add(f"ab{idx}a", "2960-24TT", f"AB-{name}-ASW", bx + 200, by + 190,
                     site=name, ip=host(s, V_MGMT, 4),
                     role=f"{name} Air Base access switch")
            self.add(f"ab{idx}o", "PC-PT", f"AB-{name}-OPS-PC", bx, by + 380, site=name,
                     ip=host(s, V_OPS, 20), role=f"{name} base operations console",
                     pc_ip=(host(s, V_OPS, 20), M24, gw(s, V_OPS)))
            self.add(f"ab{idx}m", "PC-PT", f"AB-{name}-MAINT-PC", bx + 200, by + 380,
                     site=name, ip=host(s, V_MISSION, 20),
                     role=f"{name} avionics maintenance console",
                     pc_ip=(host(s, V_MISSION, 20), M24, gw(s, V_MISSION)))
            if self.p["base_wlan"]:
                self.add(f"ab{idx}ap", "AccessPoint-PT", f"AB-{name}-WLAN-AP",
                         bx + 400, by + 190, site=name, dns=False,
                         role=f"{name} base WLAN access point")
                self.wireless(f"ab{idx}ap", f"JASDF-{name}-OPS")
            self.bases.append(dict(idx=idx, name=name, site=s, region=region))

    # ------------------------------------------------------------------ #
    def build_airborne(self):
        fleet = [("E767", "E-767 AWACS", "AN/APY-2", self.p["awacs"], True),
                 ("E2D", "E-2D Advanced Hawkeye", "AN/APY-9", self.p["e2d"], True),
                 ("E2C", "E-2C Hawkeye", "AN/APS-145", self.p["e2c"], False),
                 ("RC2", "RC-2 ELINT", "ELINT suite", self.p["rc2"], False)]
        ac = 0
        for typ, label, sensor, count, has_wc in fleet:
            for i in range(1, count + 1):
                ac += 1
                tag = f"{typ}-{i:02d}"
                s = 60 + ac                       # dedicated site id per airframe
                bx, by = 200 + ((ac - 1) % 6) * 310, 130 + ((ac - 1) // 6) * 270
                self.add(f"ac{ac}m", "2911", f"{tag}-MR", bx, by, site=tag,
                         ip=host(s, V_MGMT, 1), modules=["HWIC-2T"],
                         role=f"{label} mission router / airborne LAN gateway")
                self.add(f"ac{ac}s", "2960-24TT", f"{tag}-SW", bx + 175, by, site=tag,
                         ip=host(s, V_MGMT, 2), dns=False,
                         role=f"{label} onboard mission LAN switch")
                self.add(f"ac{ac}c", "Server-PT", f"{tag}-MC", bx + 175, by + 175,
                         site=tag, ip=host(s, V_MISSION, 10),
                         role=f"{label} mission computer - {sensor} signal processor",
                         cfg=["!", f"! mission computer - {sensor}", "!", "end"],
                         pc_ip=(host(s, V_MISSION, 10), M24, gw(s, V_MISSION)))
                if self.p["onboard_ap"]:
                    self.add(f"ac{ac}w", "AccessPoint-PT", f"{tag}-WLAN-AP", bx,
                             by + 175, site=tag, dns=False,
                             role=f"{label} onboard wireless access point")
                    self.wireless(f"ac{ac}w", f"JASDF-ABN-{tag}")
                if has_wc:
                    self.add(f"ac{ac}o", "PC-PT", f"{tag}-WC-PC", bx + 350, by + 175,
                             site=tag, ip=host(s, V_OPS, 20),
                             role=f"{label} airborne weapons controller console",
                             pc_ip=(host(s, V_OPS, 20), M24, gw(s, V_OPS)))
                self.aircraft.append(dict(idx=ac, tag=tag, type=typ, label=label,
                                          has_wc=has_wc))

    # ------------------------------------------------------------------ #
    def build_coalition(self):
        self.add("ptr", "ISR4331", "PARTNER-RTR-01", 3500, 400, ip="10.254.0.2",
                 role="Allied coalition partner edge router (eBGP AS65002)")
        self.add("psw", "2960-24TT", "PARTNER-SW-01", 3500, 200, ip="10.254.0.3",
                 role="Coalition partner LAN switch")
        self.add("ppc", "PC-PT", "PARTNER-LIAISON-PC", 3700, 200, ip="10.254.0.20",
                 role="Coalition liaison officer workstation",
                 pc_ip=("10.254.0.20", M24, "10.254.0.1"))

    # ================================================================== #
    def cable(self):
        # ---- backbone ----
        self.rlink("bb1", GE(1), "bb2", GE(1))
        self.link("bb1", GE(2), "cr1", "GigabitEthernet0/0/0")
        self.link("bb2", GE(2), "cr2", "GigabitEthernet0/0/0")
        self.link("bb1", GE(3), "cr2", "GigabitEthernet0/0/1")
        self.link("bb2", GE(3), "cr1", "GigabitEthernet0/0/1")
        self.rlink("cr2", "GigabitEthernet0/0/2", "we1", "GigabitEthernet0/0")
        self.rlink("cr1", "GigabitEthernet0/0/2", "we2", "GigabitEthernet0/0")
        self.slink("we1", "Serial0/0/0", "we2", "Serial0/0/0", dce="we1",
                   clock=4_000_000)

        # ---- regional hubs (dual-homed to both backbone switches) ----
        for i, r in enumerate(REGIONS):
            # GE(23)/GE(24) are reserved for the backbone uplinks; site-facing
            # routed ports start at GE(1) and run upward.
            self.link("bb1", GE(5 + i), f"hub{r}", GE(23))
            self.link("bb2", GE(5 + i), f"hub{r}", GE(24))

        # ---- JADGE data centre ----
        self.rlink("bb1", GE(9), "fwj", "Ethernet0/0")
        self.link("fwj", "Ethernet0/1", "dcc1", "GigabitEthernet1/0/1")
        self.link("dcc1", "GigabitEthernet1/0/2", "dcc2", "GigabitEthernet1/0/2")
        self.link("dcc1", "GigabitEthernet1/0/3", "dca1", "GigabitEthernet0/1")
        self.link("dcc2", "GigabitEthernet1/0/3", "dca2", "GigabitEthernet0/1")
        for i, (key, *_r) in enumerate(self.servers):
            sw = "dca1" if i < 11 else "dca2"
            self.link(sw, FE(1 + (i % 11)), key, "FastEthernet0")

        # ---- tactical datalink DMZ ----
        self.rlink("bb2", GE(9), "fwt", "Ethernet0/0")
        self.rlink("fwt", "Ethernet0/1", "agg1", "GigabitEthernet1/0/21")
        self.rlink("fwt", "Ethernet0/2", "agg2", "GigabitEthernet1/0/21")
        for i in range(1, 5):
            self.link(f"tdl{i}", "GigabitEthernet0/0", "agg1", GE(i))
            self.link(f"tdl{i}", "GigabitEthernet0/1", "agg2", GE(i))
            self.link(f"sat{i}", "GigabitEthernet0/0", "agg1", GE(4 + i))
            self.link(f"sat{i}", "GigabitEthernet0/1", "agg2", GE(4 + i))
        self.link("agg1", GE(22), "agg2", GE(22))

        # ---- ADC HQ ----
        self.rlink("bb1", GE(10), "hq1", "GigabitEthernet0/0/0")
        self.rlink("bb2", GE(10), "hq2", "GigabitEthernet0/0/0")
        self.link("hq1", "GigabitEthernet0/0/1", "hqd", "GigabitEthernet0/1")
        self.link("hq2", "GigabitEthernet0/0/1", "hqd", "GigabitEthernet0/2")
        self.link("hqd", FE(1), "hqa", "GigabitEthernet0/1")
        for i, k in enumerate(["hq_cdr", "hq_ops", "hq_int", "hq_lia"]):
            self.link("hqa", FE(1 + i), k, "FastEthernet0")
        self.link("hqd", FE(2), "hq_cop", "FastEthernet0")

        # ---- management enclave ----
        self.rlink("bb2", GE(11), "mgw", "GigabitEthernet0/0/0")
        self.rlink("mgw", "GigabitEthernet0/0/1", "fwm", "Ethernet0/0")
        self.link("fwm", "Ethernet0/1", "msw", "GigabitEthernet0/1")
        for i, k in enumerate(["jump", "nms", "cobs", "tap"]):
            self.link("msw", FE(1 + i), k, self.MON_PORT[k])

        # ---- CRCs ----
        for c in self.crcs:
            r, k = c["region"], c["key"]
            self.rlink(f"hub{r}", GE(1), f"{k}r1", "GigabitEthernet0/0/0")
            self.rlink(f"hub{r}", GE(2), f"{k}r2", "GigabitEthernet0/0/0")
            self.link(f"{k}r1", "GigabitEthernet0/0/1", f"{k}d", "GigabitEthernet0/1")
            self.link(f"{k}r2", "GigabitEthernet0/0/1", f"{k}d", "GigabitEthernet0/2")
            self.link(f"{k}d", FE(1), f"{k}t", "FastEthernet0")
            self.link(f"{k}d", FE(2), f"{k}p", "FastEthernet0")
            for j, sfx in enumerate(["aso", "wc", "sdo"][:self.p["consoles"]]):
                self.link(f"{k}d", FE(3 + j), f"{k}{sfx}", "FastEthernet0")

        # ---- radar sites ----
        used = {}
        for r in self.radars:
            reg = r["region"]
            used[reg] = used.get(reg, 2) + 1
            self.rlink(f"hub{reg}", GE(used[reg]), f"rdr{r['idx']}r",
                       "GigabitEthernet0/0/0")
            self.link(f"rdr{r['idx']}r", "FastEthernet0/0/1", f"rdr{r['idx']}s",
                      "GigabitEthernet1/0/1")
            self.link(f"rdr{r['idx']}s", "GigabitEthernet1/0/2", f"rdr{r['idx']}p",
                      "FastEthernet0")
            if f"rdr{r['idx']}o" in self.sid:
                self.link(f"rdr{r['idx']}s", "GigabitEthernet1/0/3", f"rdr{r['idx']}o",
                          "FastEthernet0")

        # ---- air bases ----
        used = {}
        for b in self.bases:
            reg = b["region"]
            used[reg] = used.get(reg, 11) + 1
            self.rlink(f"hub{reg}", GE(used[reg]), f"ab{b['idx']}r", "GigabitEthernet0/0/0")
            self.link(f"ab{b['idx']}r", "GigabitEthernet0/0/1", f"ab{b['idx']}d",
                      "GigabitEthernet0/1")
            self.link(f"ab{b['idx']}d", FE(1), f"ab{b['idx']}a", "GigabitEthernet0/1")
            self.link(f"ab{b['idx']}a", FE(1), f"ab{b['idx']}o", "FastEthernet0")
            self.link(f"ab{b['idx']}a", FE(2), f"ab{b['idx']}m", "FastEthernet0")
            if f"ab{b['idx']}ap" in self.sid:
                self.link(f"ab{b['idx']}a", FE(3), f"ab{b['idx']}ap", "Port 0")

        # ---- airborne ----
        for a in self.aircraft:
            i = a["idx"]
            g, slot = (i - 1) % 4 + 1, (i - 1) // 4
            self.slink(f"ac{i}m", "Serial0/0/0", f"tdl{g}", f"Serial0/{slot}/0",
                       dce=f"tdl{g}", clock=2_000_000)
            self.slink(f"ac{i}m", "Serial0/0/1", f"sat{g}", f"Serial0/{slot}/1",
                       dce=f"sat{g}", clock=1_544_000)
            self.link(f"ac{i}m", "GigabitEthernet0/0", f"ac{i}s", "GigabitEthernet0/1")
            self.link(f"ac{i}s", FE(1), f"ac{i}c", "FastEthernet0")
            if f"ac{i}w" in self.sid:
                self.link(f"ac{i}s", FE(2), f"ac{i}w", "Port 0")
            if f"ac{i}o" in self.sid:
                self.link(f"ac{i}s", FE(3), f"ac{i}o", "FastEthernet0")

        # ---- coalition ----
        self.rlink("bb2", GE(12), "cgw", "GigabitEthernet0/0/0")
        self.rlink("cgw", "GigabitEthernet0/0/1", "fwc", "Ethernet0/0")
        self.rlink("fwc", "Ethernet0/1", "ptr", "GigabitEthernet0/0/0")
        self.link("ptr", "GigabitEthernet0/0/1", "psw", "GigabitEthernet0/1")
        self.link("psw", FE(1), "ppc", "FastEthernet0")

    # ================================================================== #
    def configure(self):
        self._backbone()
        self._hubs()
        self._dc()
        self._hq()
        self._mgmt()
        self._crcs()
        self._radars()
        self._bases()
        self._datalink()
        self._airborne()
        self._coalition()
        self._firewalls()

    # --- router-on-a-stick helper -------------------------------------- #
    def _ros(self, site, vlans, hsrp=None, trunk="GigabitEthernet0/0/1"):
        """Subinterface block + optional HSRP for a site router."""
        out = []
        for v in vlans:
            out += [f"interface {trunk}.{v}",
                    f" description {K.VLAN_NAMES.get(v, v)} - router-on-a-stick",
                    f" encapsulation dot1Q {v}",
                    f" ip address {gw(site, v)} {M24}"]
            if hsrp:
                grp, vip, prio = hsrp[v]
                out += [f" standby {grp} ip {vip}",
                        f" standby {grp} priority {prio}",
                        f" standby {grp} preempt",
                        f" standby {grp} authentication md5 key-string JASDF-HSRP",
                        f" standby {grp} track 1 decrement 20"]
            out += [" no shutdown", "!"]
        return out

    def _site_router(self, key, site, vlans, hsrp=None, ntp=None):
        cfg = K.router_config(
            self.meta[key]["name"], self.meta[key]["role"], self.ifaces(key),
            loopback=self.meta[key]["ip"],
            ospf=self.wans(key, area=0) + [(net(site, v), "0.0.0.255", site) for v in vlans],
            area=0, ospf_active=[p for p, _i, _m in self.ifaces(key)],
            extra=["!", "! --- LAN: router-on-a-stick with 802.1Q ---",
                   "interface GigabitEthernet0/0/1",
                   " description 802.1Q trunk to site distribution switch",
                   " no ip address", " no shutdown", "!"]
                  + self._ros(site, vlans, hsrp)
                  + ["track 1 interface GigabitEthernet0/0/1 line-protocol", "!"])
        self.set_cfg(key, cfg)

    def _l2_site_switch(self, key, name, role, vlans, mgmt, trunk_port,
                        access_ports, uplink_ports=None):
        cfg = K.l2_switch_config(name, role, vlans,
                                 mgmt=mgmt, mgmt_vlan=V_MGMT,
                                 uplinks=uplink_ports or [],
                                 access_ports=access_ports,
                                 stp_root=vlans)
        # the L3 gateway lives on the site routers, so no default-gateway is needed
        cfg = [l for l in cfg if not l.startswith("ip default-gateway")]
        self.set_cfg(key, cfg)

    # ------------------------------------------------------------------ #
    def _backbone(self):
        for k in ("cr1", "cr2"):
            lo = self.meta[k]["ip"]
            self.set_cfg(k, K.router_config(
                self.meta[k]["name"], self.meta[k]["role"], self.ifaces(k),
                loopback=lo, ospf=self.wans(k), area=0,
                ospf_active=[p for p, _i, _m in self.ifaces(k)],
                bgp=dict(router_id=lo, primary_net="10.0.0.0", primary_mask="255.0.0.0",
                         neighbors=self._ibgp(k))))

        for k, lo in (("we1", "10.255.0.3"), ("we2", "10.255.0.4")):
            ifs = self.ifaces(k)
            self.set_cfg(k, K.router_config(
                self.meta[k]["name"], self.meta[k]["role"], ifs, loopback=lo,
                ospf=self.wans(k), area=0,
                ospf_active=[p for p, _i, _m in ifs], qos=True,
                serial_clock={p: 4_000_000 for p, _i, _m in ifs
                              if p.startswith("Serial")},
                bgp=dict(router_id=lo, primary_net="10.254.0.0", primary_mask="255.255.0.0",
                         neighbors=self._ibgp(k)),
                extra=["!", "! wide-area bearer to the JASDF transport network",
                       "interface Serial0/0/0", " service-policy output PM-JADGE-WAN",
                       "!"]))

        for k, lo in (("bb1", "10.255.0.11"), ("bb2", "10.255.0.12")):
            rp = [(p, ip, m) for p, ip, m in self.ifaces(k)]
            self.set_cfg(k, K.l3_switch_config(
                self.meta[k]["name"], self.meta[k]["role"], SITE_VLANS, svis={},
                loopback=lo, ospf=self.wans(k), area=0,
                ospf_active=[p for p, _i, _m in rp], routed_ports=rp))

    def _ibgp(self, key):
        speakers = {"cr1": "10.255.0.1", "cr2": "10.255.0.2",
                    "we1": "10.255.0.3", "we2": "10.255.0.4",
                    "hq1": host(SITE_YOKOTA, V_MGMT, 2)}
        out = [(ip, K.BGP_ASN, f"iBGP JADGE peer {k}")
               for k, ip in speakers.items() if k != key]
        out.append(("10.255.0.7", K.COALITION_ASN, "eBGP coalition partner"))
        return out

    # ------------------------------------------------------------------ #
    def _hubs(self):
        for i, r in enumerate(REGIONS):
            rp = [(p, ip, m) for p, ip, m in self.ifaces(f"hub{r}")]
            self.set_cfg(f"hub{r}", K.l3_switch_config(
                f"REG-HUB-{r}", f"{r} regional WAN aggregation hub (L3)", SITE_VLANS,
                svis={}, loopback=f"10.255.2.{i + 1}",
                ospf=self.wans(f"hub{r}"), area=0,
                ospf_active=[p for p, _i, _m in rp], routed_ports=rp))

    def _dc(self):
        # DC core/access are L2; the firewall is the default gateway for VLAN 60
        self._l2_site_switch("dcc1", "JADGE-DC-CORE-01",
                             "JADGE data-centre core switch A (L2)",
                             [V_SRV, V_MGMT], (self.meta["dcc1"]["ip"], M24),
                             None,
                             {GE(2): V_SRV, GE(3): V_SRV, GE(4): V_SRV},
                             uplink_ports=[GE(1)])
        self._l2_site_switch("dcc2", "JADGE-DC-CORE-02",
                             "JADGE data-centre core switch B (L2)",
                             [V_SRV, V_MGMT], (self.meta["dcc2"]["ip"], M24),
                             None, {GE(2): V_SRV, GE(3): V_SRV},
                             uplink_ports=[GE(1)])
        self._l2_site_switch("dca1", "JADGE-DC-ACC-01",
                             "JADGE DC server access switch A", [V_SRV, V_MGMT],
                             (self.meta["dca1"]["ip"], M24), None,
                             {FE(i): V_SRV for i in range(1, 12)},
                             uplink_ports=[FE(24)])
        self._l2_site_switch("dca2", "JADGE-DC-ACC-02",
                             "JADGE DC server access switch B", [V_SRV, V_MGMT],
                             (self.meta["dca2"]["ip"], M24), None,
                             {FE(i): V_SRV for i in range(1, 12)},
                             uplink_ports=[FE(24)])

    def _hq(self):
        s = SITE_YOKOTA
        for k in ("hq1", "hq2"):
            self._site_router(k, s, SITE_VLANS,
                              hsrp={v: (v, gw(s, v), 110 if k == "hq1" else 100)
                                    for v in SITE_VLANS})
        self._l2_site_switch("hqd", "ADC-HQ-DSW", "ADC HQ distribution switch (L2)",
                             SITE_VLANS, (self.meta["hqd"]["ip"], M24), None,
                             {FE(i): v for i, v in zip(range(3, 9), SITE_VLANS)},
                             uplink_ports=["GigabitEthernet0/1", "GigabitEthernet0/2"])
        self._l2_site_switch("hqa", "ADC-HQ-ASW", "ADC HQ access switch",
                             SITE_VLANS, (self.meta["hqa"]["ip"], M24), None,
                             {FE(i): V_OPS for i in range(1, 5)} | {FE(5): V_SRV},
                             uplink_ports=["GigabitEthernet0/1"])

    def _mgmt(self):
        m = SITE_MGMT
        self.set_cfg("mgw", K.router_config(
            self.meta["mgw"]["name"], self.meta["mgw"]["role"], self.ifaces("mgw"),
            loopback="10.255.0.8", ospf=self.wans("mgw"), area=0,
            ospf_active=[p for p, _i, _m in self.ifaces("mgw")], qos=False))
        self._l2_site_switch("msw", "NOSC-SW-01", "NOSC management access switch",
                             [V_MGMT, V_SRV], (self.meta["msw"]["ip"], M24), None,
                             {FE(i): V_MGMT for i in range(1, 5)},
                             uplink_ports=["GigabitEthernet0/1"])

    def _crcs(self):
        for c in self.crcs:
            s, k = c["site"], c["key"]
            self._site_router(f"{k}r1", s, SITE_VLANS,
                              hsrp={v: (v, gw(s, v), 110) for v in SITE_VLANS})
            self._site_router(f"{k}r2", s, SITE_VLANS,
                              hsrp={v: (v, gw(s, v), 100) for v in SITE_VLANS})
            self._l2_site_switch(f"{k}d", f"{c['tag']}-DSW",
                                 f"{c['tag']} distribution switch (L2)", SITE_VLANS,
                                 (self.meta[f"{k}d"]["ip"], M24), None,
                                 {FE(1): V_SRV, FE(2): V_SRV,
                                  **{FE(3 + j): V_OPS for j in range(self.p["consoles"])}},
                                 uplink_ports=["GigabitEthernet0/1", "GigabitEthernet0/2"])

    def _radars(self):
        for r in self.radars:
            s, k = r["site"], f"rdr{r['idx']}"
            ifs = self.ifaces(f"{k}r")
            self.set_cfg(f"{k}r", K.router_config(
                f"RDR-{r['name']}-RTR", f"{r['sys']} radar site router - {r['name']}",
                ifs, loopback=self.meta[f"{k}r"]["ip"],
                ospf=self.wans(f"{k}r", area=0) + [(net(s, V_RADAR), "0.0.0.255", s)],
                area=0, ospf_active=[p for p, _i, _m in ifs],
                statics=[("0.0.0.0", "0.0.0.0", "10.0.0.1")],
                extra=["!", "! radar site LAN: IR1101 built-in 4-port switch",
                       "interface Vlan1",
                       f" description {r['sys']} radar sensor VLAN",
                       f" ip address {gw(s, V_RADAR)} {M24}",
                       " no shutdown", "!",
                       "interface FastEthernet0/0/1",
                       " description uplink to IE-9320 radar LAN switch",
                       " switchport mode access",
                       " switchport access vlan 1",
                       " no shutdown", "!",
                       "! radar video distribution (multicast)",
                       "ip multicast-routing",
                       f"ip pim rp-address {gw(s, V_RADAR)}", "!"]))
            self._l2_site_switch(f"{k}s", f"RDR-{r['name']}-SW",
                                 f"{r['sys']} radar site industrial switch",
                                 [1, V_MGMT], (self.meta[f"{k}s"]["ip"], M24), None,
                                 {GE(2): 1, GE(3): 1},
                                 uplink_ports=[GE(1)])

    def _bases(self):
        for b in self.bases:
            s, k = b["site"], f"ab{b['idx']}"
            self._site_router(f"{k}r", s, SITE_VLANS)
            self._l2_site_switch(f"{k}d", f"AB-{b['name']}-DSW",
                                 f"{b['name']} Air Base distribution switch (L2)",
                                 SITE_VLANS, (self.meta[f"{k}d"]["ip"], M24), None,
                                 {FE(i): v for i, v in zip(range(2, 8), SITE_VLANS)},
                                 uplink_ports=["GigabitEthernet0/1"])
            self._l2_site_switch(f"{k}a", f"AB-{b['name']}-ASW",
                                 f"{b['name']} Air Base access switch", SITE_VLANS,
                                 (self.meta[f"{k}a"]["ip"], M24), None,
                                 {FE(1): V_OPS, FE(2): V_MISSION, FE(3): V_WIFI},
                                 uplink_ports=["GigabitEthernet0/1"])

    def _datalink(self):
        for i in range(1, 5):
            for pre, label in (("tdl", "Link-16 / TADIL-J ground entry"),
                               ("sat", "SATCOM ground entry")):
                k = f"{pre}{i}"
                ifs = self.ifaces(k)
                cfg = K.router_config(
                    self.meta[k]["name"], f"{label} {i} - serial bearer concentrator",
                    ifs, loopback=self.meta[k]["ip"],
                    ospf=self.wans(k), area=0,
                    ospf_active=[p for p, _i, _m in ifs], qos=False,
                    serial_clock={p: 2_000_000 for p, _i, _m in ifs
                                  if p.startswith("Serial")},
                    extra=["!", "! airborne bearers terminate on this concentrator",
                           "! each Serial0/x/y is one AEW&C platform datalink", "!"])
                self.set_cfg(k, cfg)
        for k in ("agg1", "agg2"):
            rp = [(p, ip, m) for p, ip, m in self.ifaces(k)]
            for i in range(1, 5):
                rp += [(GE(i), f"unused", "")]
            rp = [x for x in rp if x[2]]
            self.set_cfg(k, K.l3_switch_config(
                self.meta[k]["name"], self.meta[k]["role"], [V_TDL, V_MGMT], svis={},
                loopback=self.meta[k]["ip"], ospf=self.wans(k), area=0,
                ospf_active=[p for p, _i, _m in rp], routed_ports=rp))

    def _airborne(self):
        for a in self.aircraft:
            i, tag = a["idx"], a["tag"]
            s = 60 + i
            ifs = self.ifaces(f"ac{i}m")
            self.set_cfg(f"ac{i}m", K.router_config(
                f"{tag}-MR", f"{a['label']} mission router / airborne LAN gateway",
                ifs, loopback=host(s, V_MGMT, 1),
                ospf=self.wans(f"ac{i}m", area=0)
                     + [(net(s, v), "0.0.0.255", s) for v in
                        (V_OPS, V_MISSION, V_WIFI, V_MGMT)],
                area=0, ospf_active=[p for p, _i, _m in ifs], qos=True,
                serial_clock={},
                statics=[("0.0.0.0", "0.0.0.0", "10.254.254.1")],
                extra=["!",
                       "! airborne platform: dual bearer (Link-16 primary, SATCOM backup)",
                       "interface GigabitEthernet0/0",
                       " description onboard mission LAN 802.1Q trunk",
                       " no ip address", " no shutdown", "!"]
                      + self._ros(s, [V_OPS, V_MISSION, V_WIFI, V_MGMT],
                                  hsrp=None, trunk="GigabitEthernet0/0")
                      + ["interface Serial0/0/0",
                         " description Link-16 / TADIL-J bearer to TDL-GW",
                         " service-policy output PM-JADGE-WAN", "!",
                         "interface Serial0/0/1",
                         " description SATCOM backup bearer to SATCOM-GW",
                         " service-policy output PM-JADGE-WAN", "!",
                         "router ospf 1", " default-information originate", "!"]))
            self._l2_site_switch(f"ac{i}s", f"{tag}-SW",
                                 f"{a['label']} onboard mission LAN switch",
                                 [V_OPS, V_MISSION, V_WIFI, V_MGMT],
                                 (host(s, V_MGMT, 2), M24), None,
                                 {FE(1): V_MISSION, FE(2): V_WIFI, FE(3): V_OPS},
                                 uplink_ports=["GigabitEthernet0/1"])

    def _coalition(self):
        # COALITION-GW-01 is the JASDF side of the cross-domain boundary.  It
        # was added and cabled but never configured, so it shipped the harvested
        # template's factory default (`hostname Router`, no addresses, nothing
        # up) while PARTNER-RTR-01 was configured to peer with 10.255.0.7 -- an
        # address that existed only in the design document.  The eBGP session
        # could not form.  Presence-based validation missed it because a
        # template default is still "a config".
        #
        # The link to FW-COALITION is the design's 10.99.6.0/30 (firewall .2),
        # so re-point the address rlink allocated from the generic /30 pool.
        self.routed = [
            (d, p, "10.99.6.1" if (d == "cgw" and p == "GigabitEthernet0/0/1") else ip,
             M30 if (d == "cgw" and p == "GigabitEthernet0/0/1") else m)
            for (d, p, ip, m) in self.routed
        ]
        self.set_cfg("cgw", K.router_config(
            "COALITION-GW-01", "JASDF coalition boundary gateway (AS65001 edge)",
            self.ifaces("cgw"), loopback="10.255.0.7",
            ospf=self.wans("cgw"), qos=False,
            # reach the partner LAN across the firewall; no default route here,
            # WAN-EDGE-01 owns the internet exit
            statics=[("10.254.0.0", "255.255.255.0", "10.99.6.2")],
            extra=["!", "router bgp 65001", " bgp router-id 10.255.0.7",
                   " bgp log-neighbor-changes",
                   " network 10.99.6.0 mask 255.255.255.252",
                   " neighbor 10.254.0.2 remote-as 65002",
                   " neighbor 10.254.0.2 description PARTNER-RTR-01 (allied)",
                   " neighbor 10.254.0.2 ebgp-multihop 2", "!"]))
        self.set_cfg("ptr", K.router_config(
            "PARTNER-RTR-01", "Allied coalition partner edge router (AS65002)",
            self.ifaces("ptr"), loopback="10.254.0.2", ospf=None,
            statics=[("0.0.0.0", "0.0.0.0", "10.99.7.2")], qos=False,
            extra=["!", "router bgp 65002", " bgp router-id 10.254.0.2",
                   " bgp log-neighbor-changes",
                   " network 10.254.0.0 mask 255.255.255.0",
                   " neighbor 10.255.0.7 remote-as 65001",
                   " neighbor 10.255.0.7 description JASDF COALITION-GW-01",
                   " neighbor 10.255.0.7 ebgp-multihop 2", "!"]))
        self._l2_site_switch("psw", "PARTNER-SW-01", "Coalition partner LAN switch",
                             [V_MGMT], ("10.254.0.3", M24), None,
                             {FE(1): V_MGMT}, uplink_ports=["GigabitEthernet0/1"])

    # ------------------------------------------------------------------ #
    def _firewalls(self):
        # FW-JADGE-CORE: outside /30 to bb1, inside 10.11.60.1/24 = DC gateway
        self.set_cfg("fwj", K.asa_config(
            "FW-JADGE-CORE", "JADGE core enclave firewall", zones=[
                dict(vlan=2, nameif="outside", sec=0, ip="10.99.1.2", mask=M30,
                     ports=["Ethernet0/0"]),
                dict(vlan=1, nameif="inside", sec=100, ip=SRV_GW, mask=M24,
                     ports=[f"Ethernet0/{i}" for i in range(1, 8)]),
            ],
            acls=[
                "access-list OUTSIDE-IN extended permit tcp any host "
                f"{SRV['web']} eq 443",
                "access-list OUTSIDE-IN extended permit tcp any host "
                f"{SRV['dhcp']} eq 8443",
                "access-list OUTSIDE-IN extended permit udp any any range 4000 4010",
                "access-list OUTSIDE-IN extended permit icmp any any echo-reply",
                "access-list OUTSIDE-IN extended deny ip any any log",
                "access-group OUTSIDE-IN in interface outside",
                "!",
                "object network JADGE-DC-NET",
                " subnet 10.11.60.0 255.255.255.0",
                " nat (inside,outside) dynamic interface",
                "!",
                f"route outside 0.0.0.0 0.0.0.0 {self._peer_ip('fwj', 'Ethernet0/0')} 1",
            ]))
        self.set_cfg("fwt", K.asa_config(
            "FW-TDL-DMZ", "Tactical datalink / SATCOM DMZ firewall", zones=[
                dict(vlan=2, nameif="outside", sec=0, ip="10.99.3.2", mask=M30,
                     ports=["Ethernet0/0"]),
                dict(vlan=1, nameif="inside", sec=100, ip="10.99.4.2", mask=M30,
                     ports=["Ethernet0/1"]),
                dict(vlan=3, nameif="dmz", sec=50, ip="10.99.5.2", mask=M30,
                     ports=["Ethernet0/2"]),
            ],
            acls=[
                "access-list OUTSIDE-IN extended permit udp any any range 4000 4010",
                "access-list OUTSIDE-IN extended permit tcp any any eq 8443",
                "access-list OUTSIDE-IN extended deny ip any any log",
                "access-group OUTSIDE-IN in interface outside",
                "access-list DMZ-IN extended permit udp any any range 4000 4010",
                "access-list DMZ-IN extended permit tcp any any eq 4200",
                "access-list DMZ-IN extended deny ip any any log",
                "access-group DMZ-IN in interface dmz",
                f"route outside 0.0.0.0 0.0.0.0 {self._peer_ip('fwt', 'Ethernet0/0')} 1",
            ]))
        self.set_cfg("fwc", K.asa_config(
            "FW-COALITION", "Coalition cross-domain boundary firewall", zones=[
                dict(vlan=2, nameif="outside", sec=0, ip="10.99.6.2", mask=M30,
                     ports=["Ethernet0/0"]),
                dict(vlan=1, nameif="inside", sec=100, ip="10.99.7.2", mask=M30,
                     ports=[f"Ethernet0/{i}" for i in range(1, 8)]),
            ],
            acls=[
                "access-list INSIDE-OUT extended permit tcp host 10.254.0.20 "
                f"host {SRV['web']} eq 443",
                "access-list INSIDE-OUT extended permit udp any any range 4000 4010",
                "access-list INSIDE-OUT extended deny ip any any log",
                "access-group INSIDE-OUT in interface inside",
                "access-list ACL-VPN-COALITION extended permit ip "
                "10.11.0.0 255.255.0.0 10.254.0.0 255.255.255.0",
                f"route outside 0.0.0.0 0.0.0.0 {self._peer_ip('fwc', 'Ethernet0/0')} 1",
            ]))
        self.set_cfg("fwm", K.asa_config(
            "FW-MGMT", "Management enclave firewall", zones=[
                dict(vlan=2, nameif="outside", sec=0, ip="10.99.8.2", mask=M30,
                     ports=["Ethernet0/0"]),
                dict(vlan=1, nameif="inside", sec=100,
                     ip=gw(SITE_MGMT, V_MGMT), mask=M24,
                     ports=[f"Ethernet0/{i}" for i in range(1, 8)]),
            ],
            acls=[
                "access-list OUTSIDE-IN extended permit tcp any host "
                f"{host(SITE_MGMT, V_MGMT, 20)} eq 22",
                "access-list OUTSIDE-IN extended permit tcp any host "
                f"{host(SITE_MGMT, V_MGMT, 21)} eq 161",
                "access-list OUTSIDE-IN extended deny ip any any log",
                "access-group OUTSIDE-IN in interface outside",
                f"route outside 0.0.0.0 0.0.0.0 {self._peer_ip('fwm', 'Ethernet0/0')} 1",
            ]))

    def _peer_ip(self, key, port):
        for (a, ap, ip, m) in self.routed:
            if a == key and ap == port:
                return ip
        return "10.0.0.1"

    # ================================================================== #
    def services(self):
        records = sorted(set(self.dns))
        for key in ("s_dns", "s_dns2"):
            K.configure_server(self.lab._els[self.sid[key]], dns_records=records,
                               http=True, http_user="jasdf-web", http_pass="W3b-P0rt4l")

        pools = []
        # Site 11 is the JADGE data centre at Iruma AB and site 29 is air base
        # AB-IRUMA.  Both used to be labelled "IRUMA", so both derived the pool
        # name "IRUMA-VLAN10" for *different* subnets.  Packet Tracer pools are
        # name-keyed, so one silently shadows the other.  Each now uses the same
        # prefix its devices already carry: JADGE-DC- for site 11, AB-IRUMA- for
        # site 29.  Keep this in step with pool_renames.json, which migrates
        # files built by the older generator.
        base_label = {"IRUMA": "AB-IRUMA"}
        for name, s in [("YOKOTA", SITE_YOKOTA), ("JADGE-DC", SITE_IRUMA),
                        ("MGMT", SITE_MGMT)] + \
                       [(f"CRC-{r}", SITE_CRC[r]) for r in REGIONS] + \
                       [(base_label.get(b, b), SITE_BASE[b])
                        for b in AIRBASES[:self.p["airbases"]]] + \
                       [(r[1], SITE_RADAR0 + i) for i, r in
                        enumerate(RADAR_SITES[:self.p["radar"]])]:
            for v in (V_OPS, V_MISSION, V_WIFI):
                pools.append(dict(name=f"{name}-VLAN{v}", network=net(s, v), mask=M24,
                                  router=gw(s, v), start=host(s, v, 100),
                                  end=host(s, v, 190), dns=SRV["dns"], max=90))
        for a in self.aircraft:
            s = 60 + a["idx"]
            for v in (V_OPS, V_WIFI):
                pools.append(dict(name=f"ABN-{a['tag']}-V{v}", network=net(s, v),
                                  mask=M24, router=gw(s, v), start=host(s, v, 100),
                                  end=host(s, v, 150), dns=SRV["dns"], max=50))

        # Prove the names are distinct before handing them to Packet Tracer:
        # a printed count is only meaningful if the counted things differ.
        seen = collections.Counter(p["name"] for p in pools)
        clashes = {n: c for n, c in seen.items() if c > 1}
        if clashes:
            raise SystemExit(
                "DHCP pool names collide (PT pools are name-keyed, so one would "
                f"shadow the other): {clashes}. Qualify the site label used to "
                "build the name so it is unique across sites."
            )
        K.configure_server(self.lab._els[self.sid["s_dhcp"]], dhcp_pools=pools, syslog=True)

        K.configure_server(self.lab._els[self.sid["s_ntp"]], ntp=True)
        K.configure_server(self.lab._els[self.sid["s_syslog"]], syslog=True)

        clients = [(n["ip"], K.AAA_KEY, n["name"]) for n in self.meta.values()
                   if n["model"] in ("2911", "ISR4331", "ISR4321", "IR1101",
                                     "3650-24PS", "3560-24PS", "2960-24TT", "IE-9320")
                   and n["ip"]]
        K.configure_server(self.lab._els[self.sid["s_aaa"]],
                           aaa_users=[("jasdf-admin", "Adm1n-J4DGE-9f3c"),
                                      ("jasdf-ops", "0ps-J4DGE-1a7e")],
                           aaa_clients=clients)
        for key, kw in (("s_tftp", dict(ftp_user="jasdf-cfg", ftp_pass="Tftp-J4DGE")),
                        ("s_web", dict(http=True, http_user="jasdf-web",
                                       http_pass="W3b-P0rt4l", https=True)),
                        ("s_mail", dict(email_domain=K.DOMAIN)),
                        ("s_ca", dict(https=True)),
                        ("s_flow", dict(syslog=True)),
                        ("s_backup", dict(ftp_user="backup", ftp_pass="B4ckup-J4DGE")),
                        ("s_hist", dict(syslog=True)),
                        ("s_ids", dict(syslog=True))):
            K.configure_server(self.lab._els[self.sid[key]], **kw)
        for c in self.crcs:
            for sfx in ("t", "p"):
                K.configure_server(self.lab._els[self.sid[f"{c['key']}{sfx}"]], syslog=True)
        for r in self.radars:
            K.configure_server(self.lab._els[self.sid[f"rdr{r['idx']}p"]], syslog=True)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _serial_slot_idx(port_name):
        """Serial0/<slot>/<idx> -> index among a device's eSmartSerial ports
        (every bay used here carries a 2-port HWIC-2T, in bay order)."""
        try:
            slot, idx = (int(x) for x in port_name.split("/")[-2:])
        except ValueError:
            return 0
        return slot * 2 + idx

    def _set_port(self, key, port_name, clock, is_dce):
        el = self.lab._els[self.sid[key]]
        ports = [p for p in el.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"]
        i = self._serial_slot_idx(port_name)
        if i >= len(ports):
            return False
        p = ports[i]
        for tag, val in (("POWER", "true"),
                         ("CLOCKRATE", str(clock) if is_dce else "0"),
                         ("CLOCKRATEFLAG", "true" if is_dce else "false")):
            e = p.find(tag)
            if e is None:
                e = ET.SubElement(p, tag)
            e.text = val
        return True

    def fix_serial(self):
        """Set the physical serial-port fields PT needs for a line to come up:
        POWER=true on both ends, and clocking only on the DCE end."""
        n = 0
        for (a, ap, b, bp, dce, clock) in self.serial_meta:
            dce_key, dce_port = (a, ap) if dce == a else (b, bp)
            dte_key, dte_port = (b, bp) if dce == a else (a, ap)
            n += self._set_port(dce_key, dce_port, clock, True)
            n += self._set_port(dte_key, dte_port, clock, False)
        return n

    def sanitize(self):
        """The harvested device templates carry leftover <IP>/<SUBNET>/<PORT_GATEWAY>
        values from whatever lab they were taken from (e.g. every ISR4321 ships
        with 2.1.1.2 on GigabitEthernet0/0/0).  Routed IOS devices take their
        addresses from RUNNINGCONFIG, so those NIC fields are cleared for every
        device whose address we did not set explicitly."""
        cleared = 0
        for key, sid in self.sid.items():
            if key in self.has_nic_ip:
                continue
            el = self.lab._els[sid]
            for port in el.iter("PORT"):
                if port.find("IP") is None:
                    continue
                for tag in ("IP", "SUBNET", "PORT_GATEWAY", "PORT_DNS"):
                    e = port.find(tag)
                    if e is not None and (e.text or "").strip():
                        e.text = ""
                        cleared += 1
                dh = port.find("PORT_DHCP_ENABLE")
                if dh is not None:
                    dh.text = "false"
        return cleared

    def strip_template_leftovers(self):
        """Remove the service records that came from the device templates.

        ``sanitize()`` above clears stale per-port NIC fields, but the templates
        also carry whole **service blocks** captured from whatever lab they were
        harvested out of: AAA clients, AAA users, FTP accounts, DHCP pools and
        their port bindings.  Those are example data, not a blank form, and
        copying them onto every device inflated every published figure -- the
        audit found 202 "AAA clients" of which only 140 were distinct (63 copies
        of one phantom 192.168.10.1) and 259 "DHCP pools" of which only 131 were
        distinct (128 copies of a serverPool 0.0.0.0/0.0.0.0).

        ``sanitize_template_leftovers`` removes only records whose identity the
        device's own template carries, so authored records survive.  DNS zone
        entries are deliberately left alone: two servers holding the same 248
        records is correct, not duplication.

        Returns the number of records removed.
        """
        src = str(TOOLKIT / "src")
        if src not in sys.path:
            sys.path.insert(0, src)          # pkt_core lives under src/
        from pkt_core.audit import (         # noqa: PLC0415
            SanitizeReport,
            TemplateLeftovers,
            sanitize_template_leftovers,
        )

        leftovers = TemplateLeftovers.from_device_templates_json(
            TOOLKIT / "tools" / "device_templates.json")
        # Per DEVICE, not on the document: the helper resolves DEVICE/ENGINE and
        # returns an empty report for anything else, so handing it the root
        # would look like a clean sweep while removing nothing.
        report = SanitizeReport()
        for dev in self.lab.devs.findall("DEVICE"):
            report = report.merge(
                sanitize_template_leftovers(dev, leftovers=leftovers))
        self.leftover_report = report.as_dict()
        return sum(self.leftover_report.values())

    def clear_template_startup_config(self):
        """Drop the factory-default ``STARTUPCONFIG`` the templates carry.

        The harvested templates store a complete default configuration that
        Packet Tracer writes on a factory-fresh device.  Copying it into a
        generated device produces a file whose **startup** config belongs to a
        different lab, and it is not cosmetic:

        * 16 ``IR1101`` radar routers shipped ``enable secret 5
          $1$mERr$A0KmwwybwYdjSTcVdJ15p0`` -- the MD5 of the publicly known
          default ``cisco`` -- while their *running* configs carried the
          intended secret.  A device whose startup and running secrets disagree
          is a device nobody can secure by reading the file.
        * the same 16 said ``hostname Router`` and the 4 ASA 5505s said
          ``hostname ciscoasa``: the device's own name was nowhere in its
          startup config.

        The residue is cleared rather than rewritten to mirror ``RUNNINGCONFIG``,
        because that is what real labs do: across 4,729 devices in 1,014 corpus
        files, 60% have no ``STARTUPCONFIG`` element at all and 23% have an empty
        one, so 83% carry no startup config.  Of the 17% that do, the content is
        that lab's own configuration.  Packet Tracer loads these files from
        ``RUNNINGCONFIG`` -- 123 of the 290 devices here already had an empty
        startup config and loaded correctly.

        Returns the number of ``<LINE>`` elements removed.
        """
        removed = 0
        for sid in self.sid.values():
            eng = self.lab._els[sid].find("ENGINE")
            if eng is None:
                continue
            startup = eng.find("STARTUPCONFIG")
            if startup is None:
                continue
            for line in list(startup):
                if line.tag == "LINE":
                    startup.remove(line)
                    removed += 1
        self.startup_lines_cleared = removed
        return removed

    def power_cabled_ports(self):
        """Some harvested templates ship with <POWER>false</POWER> on their ports
        (notably AccessPoint-PT).  A cabled port on a device we placed is by
        definition powered, so raise it -- otherwise PT draws the link down."""
        cabled = set()
        for (a, ap, b, bp, _k, _d) in self.links:
            cabled.add(a)
            cabled.add(b)
        n = 0
        for key in cabled:
            for p in self.lab._els[self.sid[key]].iter("PORT"):
                e = p.find("POWER")
                if e is None:
                    e = ET.SubElement(p, "POWER")
                if e.text != "true":
                    e.text = "true"
                    n += 1
        return n

    def power_all_devices(self, staged_off=None):
        """Force <ENGINE><POWER>true</POWER> on every placed device.

        Defence in depth beside power_cabled_ports() -- which is *port*-level
        and cannot touch <ENGINE><POWER>.  A harvested model template must
        never decide the power state of a placed device: the 3650-24PS
        template was harvested from a save where that switch was switched off
        and silently took all ten core/aggregation switches down with it
        (docs/POWER_INVESTIGATION.md).  lab_api.add_device() now writes the
        element explicitly in both directions; this pass guarantees the final
        document regardless of template provenance.

        Only the device-level element is written.  <PORT><POWER> keeps its own
        semantics (unused router/PC ports legitimately ship false/absent) and
        stays under the cabled-port rule of power_cabled_ports().

        Devices named in `staged_off` (default: cls.STAGED_OFF) keep their
        state -- deliberately powered-down gear is a lab feature, not a bug.
        Returns the number of devices whose power was raised.
        """
        keep = set(self.STAGED_OFF if staged_off is None else staged_off)
        n = 0
        for key, sid in self.sid.items():
            if self.meta[key]["name"] in keep:
                continue
            eng = self.lab._els[sid].find("ENGINE")
            e = eng.find("POWER")
            if e is None:
                e = ET.Element("POWER")
                kids = list(eng)
                anchor = eng.find("NAME")
                # canonical slot: TYPE, NAME, POWER, ... (child index 2)
                at = kids.index(anchor) + 1 if anchor is not None else min(2, len(kids))
                eng.insert(at, e)
            if e.text != "true":
                e.text = "true"
                n += 1
        return n

    def save(self, path):
        self.lab.save(str(path))

    def report(self):
        by = {}
        for n in self.meta.values():
            by[n["model"]] = by.get(n["model"], 0) + 1
        return dict(profile=self.profile, devices=len(self.lab.device_names()),
                    links=len(self.links), routed_ports=len(self.routed),
                    dns_records=len(set(self.dns)), wlans=len(self.wlans),
                    by_model=dict(sorted(by.items(), key=lambda kv: -kv[1])),
                    seed_removed=self.seed_removed)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=list(PROFILES), default="enterprise")
    ap.add_argument("--out", type=Path, default=ROOT / "out" / "JASDF_AEWC_JADGE.pkt")
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--inventory", type=Path, default=None)
    a = ap.parse_args(argv)
    rep_path = a.report or (ROOT / "build" / f"report_{a.profile}.json")
    inv_path = a.inventory or (ROOT / "docs" / f"INVENTORY_{a.profile}.csv")

    j = JASDF(a.profile)
    j.build_backbone(); j.build_jadge_dc(); j.build_hq(); j.build_crcs()
    j.build_radars(); j.build_airbases(); j.build_airborne(); j.build_coalition()
    j.cable()
    j.configure()
    j.services()
    n = j.fix_serial()
    cleared = j.sanitize()
    leftovers = j.strip_template_leftovers()
    startup_cleared = j.clear_template_startup_config()
    powered = j.power_cabled_ports()
    devices_powered = j.power_all_devices()

    a.out.parent.mkdir(parents=True, exist_ok=True)
    j.save(a.out)

    rep = j.report(); rep["serial_ports_clocked"] = n
    rep["stale_nic_fields_cleared"] = cleared
    rep["template_leftovers_removed"] = leftovers
    rep["template_leftovers_detail"] = j.leftover_report
    rep["startup_config_lines_cleared"] = startup_cleared
    # These two count what the *repair passes fixed*, which is not the same as
    # "how many are on".  A correctly built lab needs no repairs at all, so both
    # read 0 -- and a reader seeing `devices_powered_on: 0` would conclude the
    # opposite of the truth.  The actual state is reported separately.
    rep["ports_switched_on_by_repair"] = powered
    rep["devices_switched_on_by_repair"] = devices_powered
    power_true = sum(1 for el in j.lab.devs.findall("DEVICE")
                     if el.findtext("ENGINE/POWER") == "true")
    rep["devices_with_power_true"] = power_true
    rep["output"] = str(a.out)
    rep["size_bytes"] = a.out.stat().st_size
    rep["sha256"] = hashlib.sha256(a.out.read_bytes()).hexdigest()
    rep_path.parent.mkdir(parents=True, exist_ok=True)
    rep_path.write_text(json.dumps(rep, indent=1))

    inv_path.parent.mkdir(parents=True, exist_ok=True)
    with inv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["name", "model", "role", "site", "mgmt_ip"])
        for nd in j.meta.values():
            w.writerow([nd["name"], nd["model"], nd["role"], nd["site"], nd["ip"] or ""])

    print(f"wrote {a.out}  ({rep['size_bytes']:,} bytes)")
    print(f"  profile : {a.profile}")
    print(f"  devices : {rep['devices']}   links: {rep['links']}   "
          f"routed ports: {rep['routed_ports']}")
    print(f"  dns A   : {rep['dns_records']}   WLANs: {rep['wlans']}   "
          f"DCE serial ports clocked: {n}")
    print("  models  : " + ", ".join(f"{k}x{v}" for k, v in rep["by_model"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
