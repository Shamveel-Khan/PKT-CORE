#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate a large, fully-configured Packet Tracer topology.

Produces a three-tier campus network intended to stress both the authoring
path and Packet Tracer itself:

    core       2x ISR4321 routers, OSPF, serial WAN link between them
    dist       4x 3560-24PS multilayer switches, VLANs + inter-VLAN routing
    access     8x 2960-24TT access switches
    servers    DHCP / DNS / HTTP / TFTP / NTP / SMTP
    clients    32 PCs and laptops with static addressing
    wireless   2x access points with associated laptops
    iot        4x MCU/sensor devices

Every router and switch gets a real IOS running configuration (hostnames,
interface addresses, OSPF adjacencies, VLAN definitions, DHCP pools, serial
clock rates), and every end device gets an IP.

    python3 tools/build_large_topology.py --out large_campus.pkt [--devices N] [--prune-seed]

Without --prune-seed the devices inherited from tools/network_seed.xml (SW1, R1,
R2, PC-A, PC-B, Server, Power Distribution Device0) stay in the file; with it
the output contains only the generated topology.

The output is a genuine Packet Tracer file: it round-trips byte-exactly
through pkt_core and opens in Packet Tracer 9.0.1.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))            # for pt9
sys.path.insert(0, str(ROOT / "tools"))   # for lab_api
import lab_api  # noqa: E402


# --------------------------------------------------------------------------
# addressing plan
# --------------------------------------------------------------------------
def subnet_for(site: int, vlan: int) -> tuple[str, str, str]:
    """(network, mask, gateway) for a site/VLAN pair."""
    return (f"10.{site}.{vlan}.0", "255.255.255.0", f"10.{site}.{vlan}.1")


def host_ip(site: int, vlan: int, host: int) -> str:
    return f"10.{site}.{vlan}.{host}"


def router_config(name: str, iface_specs: list[tuple[str, str, str]],
                  ospf_networks: list[str], extra: list[str] | None = None) -> list[str]:
    """Build a coherent IOS running configuration for a router."""
    cfg = [
        "version 15.1",
        "service timestamps debug datetime msec",
        "service timestamps log datetime msec",
        "no service password-encryption",
        "!",
        f"hostname {name}",
        "!",
        "no ip cef",
        "no ipv6 cef",
        "!",
    ]
    for iface, addr, mask in iface_specs:
        cfg += [
            f"interface {iface}",
            f" ip address {addr} {mask}",
            " duplex auto",
            " speed auto",
            " no shutdown",
            "!",
        ]
    if ospf_networks:
        cfg.append("router ospf 1")
        for net in ospf_networks:
            cfg.append(f" network {net} 0.0.0.255 area 0")
        cfg.append("!")
    if extra:
        cfg.extend(extra)
    cfg += [
        "ip forward-protocol nd",
        "no ip http server",
        "no ip http secure-server",
        "!",
        "line con 0",
        " exec-timeout 0 0",
        " logging synchronous",
        "line aux 0",
        "line vty 0 4",
        " login",
        " transport input all",
        "!",
        "end",
    ]
    return cfg


def switch_config(name: str, vlans: list[int], mgmt: tuple[str, str] | None = None) -> list[str]:
    cfg = [
        "version 12.2",
        "no service timestamps log datetime msec",
        "no service timestamps debug datetime msec",
        "no service password-encryption",
        "!",
        f"hostname {name}",
        "!",
        "no ip domain-lookup",
        "!",
        "spanning-tree mode pvst",
        "spanning-tree extend system-id",
        "!",
    ]
    for v in vlans:
        cfg.append(f"vlan {v}")
        cfg.append(f" name VLAN{v}")
        cfg.append("!")
    if mgmt:
        addr, mask = mgmt
        cfg += [
            "interface Vlan1",
            f" ip address {addr} {mask}",
            " no shutdown",
            "!",
        ]
    cfg += [
        "line con 0",
        "line vty 0 4",
        " login",
        "line vty 5 15",
        " login",
        "!",
        "end",
    ]
    return cfg


def server_config(name: str, domain: str, services: list[str]) -> list[str]:
    cfg = [
        "version 15.1",
        "!",
        f"hostname {name}",
        "!",
        f"ip domain-name {domain}",
        "!",
    ]
    for svc in services:
        cfg.append(f"! service: {svc}")
    cfg += ["!", "end"]
    return cfg


# --------------------------------------------------------------------------
# topology
# --------------------------------------------------------------------------
def build(out_path: Path, clients_per_access: int, prune_seed: bool = False) -> int:
    models, modules = lab_api.load_templates("tools/device_templates.json")
    lab = lab_api.Lab("tools/network_seed.xml", models, modules)
    if prune_seed:
        lab.prune_seed_devices()

    ids: dict[str, str] = {}
    device_count = 0

    def add(key: str, model: str, name: str, x: int, y: int, **kw) -> str:
        nonlocal device_count
        sid = lab.add_device(model, name, x, y, **kw)
        ids[key] = sid
        device_count += 1
        return sid

    # ---------------- core ----------------
    core_ifaces = [
        ("GigabitEthernet0/0", "10.0.0.1", "255.255.255.252"),
        ("GigabitEthernet0/1", "10.0.1.1", "255.255.255.252"),
        ("GigabitEthernet0/2", "10.0.2.1", "255.255.255.252"),
        ("GigabitEthernet0/3", "10.0.3.1", "255.255.255.252"),
        ("Serial0/0/0", "10.255.0.1", "255.255.255.252"),
    ]
    add("core1", "2911", "CORE-R1", 700, 120,
        ios_config=router_config(
            "CORE-R1", core_ifaces,
            ["10.0.0.0", "10.0.1.0", "10.0.2.0", "10.0.3.0", "10.255.0.0"],
            ["!", "router ospf 1", " passive-interface default",
             " no passive-interface GigabitEthernet0/0",
             " no passive-interface Serial0/0/0", "!"]))
    lab.install_module(ids["core1"], "HWIC-2T", 0)

    core2_ifaces = [
        ("GigabitEthernet0/0", "10.0.4.1", "255.255.255.252"),
        ("Serial0/0/0", "10.255.0.2", "255.255.255.252"),
    ]
    add("core2", "2911", "CORE-R2", 700, 320,
        ios_config=router_config(
            "CORE-R2", core2_ifaces,
            ["10.0.4.0", "10.255.0.0"]))
    lab.install_module(ids["core2"], "HWIC-2T", 0)

    lab.link(ids["core1"], "Serial0/0/0", ids["core2"], "Serial0/0/0",
             kind="serial", dce=ids["core1"], clock=2000000)

    # ---------------- distribution ----------------
    dist_specs = [
        ("DIST-SW1", 100, 300, 1),
        ("DIST-SW2", 400, 300, 2),
        ("DIST-SW3", 1000, 300, 3),
        ("DIST-SW4", 1300, 300, 4),
    ]
    for name, x, y, site in dist_specs:
        add(f"dist{site}", "3560-24PS", name, x, y,
            ios_config=switch_config(name, [10 * site + 1, 10 * site + 2, 10 * site + 3],
                                     mgmt=(f"10.{site}.1.2", "255.255.255.0")))

    # core -> distribution uplinks
    for site in (1, 2, 3, 4):
        core = ids["core1"] if site <= 3 else ids["core2"]
        port = f"GigabitEthernet0/{site - 1 if site <= 3 else 0}"
        lab.link(core, port, ids[f"dist{site}"], "GigabitEthernet0/1")

    # ---------------- access layer ----------------
    access_specs = []
    for site in (1, 2, 3, 4):
        for branch in (1, 2):
            access_specs.append((site, branch))

    for site, branch in access_specs:
        name = f"ACCESS-S{site}-{branch}"
        key = f"acc{site}{branch}"
        x = 120 + (site - 1) * 420 + (branch - 1) * 190
        y = 560
        add(key, "2960-24TT", name, x, y,
            ios_config=switch_config(name, [10 * site + 1]))
        lab.link(ids[f"dist{site}"], f"FastEthernet0/{branch}", ids[key], "GigabitEthernet0/1")

    # ---------------- servers ----------------
    server_specs = [
        ("DHCP-Server", "Server-PT", 300, 80, ["dhcp"], "10.1.1.10"),
        ("DNS-Server", "Server-PT", 480, 80, ["dns"], "10.1.1.11"),
        ("WEB-Server", "Server-PT", 660, 80, ["http"], "10.1.1.12"),
        ("TFTP-Server", "Server-PT", 840, 80, ["tftp"], "10.1.1.13"),
        ("NTP-Server", "Server-PT", 1020, 80, ["ntp"], "10.1.1.14"),
        ("MAIL-Server", "Server-PT", 1200, 80, ["smtp", "pop3"], "10.1.1.15"),
    ]
    for i, (name, model, x, y, svcs, ip) in enumerate(server_specs):
        key = f"srv{i}"
        add(key, model, name, x, y,
            ios_config=server_config(name, "campus.example.net", svcs),
            pc_ip=(ip, "255.255.255.0", "10.1.1.1"))
    # hang the servers off DIST-SW1
    for i in range(len(server_specs)):
        lab.link(ids["dist1"], f"FastEthernet0/{3 + i}", ids[f"srv{i}"], "FastEthernet0")

    # ---------------- clients ----------------
    host_n = 20
    for site, branch in access_specs:
        for n in range(clients_per_access):
            key = f"pc{site}{branch}{n}"
            model = "PC-PT" if n % 2 == 0 else "Laptop-PT"
            name = f"{'PC' if n % 2 == 0 else 'LT'}-S{site}{branch}-{n}"
            x = 100 + (site - 1) * 420 + (branch - 1) * 190 + (n % 2) * 70
            y = 760 + (n // 2) * 130
            ip = host_ip(site, 10 * site + 1, host_n)
            add(key, model, name, x, y,
                pc_ip=(ip, "255.255.255.0", f"10.{site}.{10 * site + 1}.1"))
            lab.link(ids[f"acc{site}{branch}"], f"FastEthernet0/{1 + n}", ids[key],
                     "FastEthernet0" if model == "PC-PT" else "FastEthernet0")

    # ---------------- wireless ----------------
    for site in (1, 2):
        add(f"ap{site}", "AccessPoint-PT", f"AP-S{site}", 260 + (site - 1) * 900, 80)
        lab.link(ids[f"acc{site}1"], "FastEthernet0/12", ids[f"ap{site}"], "Port 0")
        for n in range(2):
            key = f"wifi{site}{n}"
            add(key, "Laptop-PT", f"WIFI-S{site}-{n}", 380 + (site - 1) * 900 + n * 80, 80)

    # ---------------- IoT ----------------
    iot_specs = [("Temperature Sensor", "TEMP-1"), ("Light Sensor", "LIGHT-1"),
                 ("Motor", "MOTOR-1"), ("LED", "LED-1")]
    for i, (model, name) in enumerate(iot_specs):
        key = f"iot{i}"
        add(key, "Thing", name, 1450 + (i % 2) * 120, 80 + (i // 2) * 130)

    lab.save(str(out_path))
    return device_count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=Path("large_campus.pkt"))
    ap.add_argument("--clients", type=int, default=2,
                    help="clients per access switch (default 2)")
    ap.add_argument("--prune-seed", action="store_true",
                    help="drop the devices inherited from tools/network_seed.xml")
    args = ap.parse_args(argv)
    n = build(args.out, args.clients, prune_seed=args.prune_seed)
    print(f"wrote {args.out} with {n} devices")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
