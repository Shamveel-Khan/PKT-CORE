#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
jasdf_kit.py -- configuration + service-injection toolkit for the
JASDF AEW&C (AWAD/AWACS) enterprise Packet Tracer model.

Two responsibilities:

1.  IOS / ASA running-config generators (pure functions returning list[str]).
    Every generator emits commands that Packet Tracer's IOS parser accepts.

2.  XML service injection for Server-PT / PC-PT devices: DNS zones, DHCP
    pools, HTTP/HTTPS, FTP accounts, NTP, Syslog, AAA (RADIUS/TACACS+),
    e-mail.  These live in <ENGINE> sub-elements, not in RUNNINGCONFIG, so
    they are written straight into the device element.

Element shapes here were derived from Cisco's own PT 9.0.1 sample labs and
from the 1,058-file reference corpus (see docs/EVIDENCE.md).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

# --------------------------------------------------------------------------- #
# enterprise constants
# --------------------------------------------------------------------------- #
DOMAIN        = "jasdf.mod.go.jp"
NTP_PRIMARY   = "10.11.60.14"
SYSLOG_HOST   = "10.11.60.15"
AAA_HOST      = "10.11.60.16"
DNS_PRIMARY   = "10.11.60.17"
DNS_SECONDARY = "10.11.60.18"
SNMP_RO       = "JASDF-RO-9f3c"
SNMP_RW       = "JASDF-RW-1a7e"
ENABLE_SECRET = "5 $1$Jz8k$QbV3nR7dTpWmYc2LxH9uK1"
ADMIN_SECRET  = "5 $1$Kp2s$Rt5Yh8Nq4WzXc6BmL3vJd0"
AAA_KEY       = "r4d1us-J4DG3-k3y"
TACACS_KEY    = "t4c4cs-J4DG3-k3y"
OSPF_AREA     = 0
BGP_ASN       = 65001          # JASDF enterprise AS
COALITION_ASN = 65002          # allied / exercise partner AS


# --------------------------------------------------------------------------- #
# generic helpers
# --------------------------------------------------------------------------- #
def _hdr(hostname: str, model_line: str | None = None) -> list[str]:
    """Common hardening / housekeeping preamble shared by routers and L3 switches."""
    cfg = [
        "!",
        "service timestamps debug datetime msec localtime",
        "service timestamps log datetime msec localtime",
        "service password-encryption",
        "service tcp-keepalives-in",
        "service tcp-keepalives-out",
        "service sequence-numbers",
        "!",
        f"hostname {hostname}",
        "!",
        "boot-start-marker",
        "boot-end-marker",
        "!",
        "logging buffered 16384 debugging",
        "logging console critical",
        "logging synchronous",
        f"logging host {SYSLOG_HOST}",
        "!",
        f"enable secret {ENABLE_SECRET}",
        f"username jasdf-admin privilege 15 secret {ADMIN_SECRET}",
        "username jasdf-ops privilege 1 secret 5 $1$Op7q$Wm2Xc9Vb4NtR6YhL1zKd3",
        "!",
        "! --- device administration: RADIUS first, local fallback ---",
        "aaa new-model",
        "aaa authentication login default group radius local",
        "aaa authentication enable default group radius enable",
        "aaa authorization exec default group radius local",
        "aaa authorization commands 15 default group radius local",
        "aaa accounting exec default start-stop group radius",
        "aaa accounting commands 15 default start-stop group radius",
        "aaa session-id common",
        f"radius-server host {AAA_HOST} auth-port 1645 acct-port 1646 key {AAA_KEY}",
        "radius-server retransmit 2",
        "radius-server timeout 3",
        "ip radius source-interface Loopback0",
        "!",
        "clock timezone JST 9",
        "clock summer-time JST recurring",
    ]
    if model_line:
        cfg.append(model_line)
    cfg += [
        "!",
        f"ip domain-name {DOMAIN}",
        "ip domain-lookup",
        f"ip name-server {DNS_PRIMARY}",
        f"ip name-server {DNS_SECONDARY}",
        "!",
        "ip cef",
        "no ipv6 cef",
        "!",
        "no ip source-route",
        "no ip gratuitous-arps",
        "no ip bootp server",
        "no ip http server",
        "no ip http secure-server",
        "ip tcp synwait-time 10",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",
        "ip ssh version 2",
        "!",
        "crypto key generate rsa modulus 2048",
        "!",
        f"ntp authentication-key 1 md5 {AAA_KEY}",
        "ntp authenticate",
        "ntp trusted-key 1",
        f"ntp server {NTP_PRIMARY} key 1 source Loopback0 prefer",
        "ntp update-calendar",
        "!",
        "snmp-server ifindex persist",
        f"snmp-server community {SNMP_RO} RO",
        f"snmp-server community {SNMP_RW} RW",
        "snmp-server location JASDF-AWACS-JADGE",
        "snmp-server contact JASDF_ADC_NOSC",
        f"snmp-server host {SYSLOG_HOST} version 2c {SNMP_RO}",
        "snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart",
        "!",
        "archive",
        " log config",
        "  logging enable",
        "  notify syslog contenttype plaintext",
        "  hidekeys",
        "!",
        "path tftp://10.11.60.19/JASDF/$h-$t",
        " write-memory",
        "!",
    ]
    return cfg


def _banner(name: str, role: str) -> list[str]:
    # NOTE: deliberately avoids ^C (0x03) -- a raw control byte is not valid
    # XML 1.0 and would corrupt the container.  '#' is a legal delimiter.
    return [
        "banner motd #",
        "*" * 74,
        f"*  JASDF AIR DEFENSE COMMAND -- {name}",
        f"*  {role}",
        "*  RESTRICTED SYSTEM. Authorised JASDF personnel only.",
        "*  All activity is monitored and logged to the ADC NOSC.",
        "*" * 74,
        "#",
    ]


def _lines(cfg: list[str]) -> list[str]:
    cfg += AAA_LINE_BLOCK
    return cfg


AAA_LINE_BLOCK = [
    "line con 0",
    " exec-timeout 5 0",
    " logging synchronous",
    " login authentication default",
    "line aux 0",
    " exec-timeout 5 0",
    "line vty 0 4",
    " access-class 90 in",
    " exec-timeout 5 0",
    " logging synchronous",
    " login authentication default",
    " transport input ssh",
    "line vty 5 15",
    " access-class 90 in",
    " exec-timeout 5 0",
    " login authentication default",
    " transport input ssh",
    "!",
]


def mgmt_acl_lines() -> list[str]:
    """ACL 90 -- management-plane filter (vty access-class)."""
    return [
        "ip access-list standard 90",
        " remark JASDF management plane - NOSC + site mgmt only",
        " permit 10.200.0.0 0.0.255.255",
        " permit 10.0.0.0 0.255.255.255",
        " deny   any log",
        "!",
    ]


# --------------------------------------------------------------------------- #
# routers
# --------------------------------------------------------------------------- #
def router_config(name: str, role: str,
                  interfaces: list[tuple[str, str, str]],
                  loopback: str | None = None,
                  ospf: list[tuple[str, str]] | None = None,
                  area: int = OSPF_AREA,
                  ospf_passive_default: bool = True,
                  ospf_active: list[str] | None = None,
                  bgp: dict | None = None,
                  statics: list[tuple[str, str, str]] | None = None,
                  extra: list[str] | None = None,
                  qos: bool = True,
                  serial_clock: dict[str, int] | None = None) -> list[str]:
    """Build a complete IOS running configuration for a JASDF router.

    interfaces : (ifname, ip, mask) triples
    ospf       : (network, wildcard) pairs advertised into `area`
    bgp        : {'router_id','networks':[...],'neighbors':[(ip,asn,desc)]}
    statics    : (prefix, mask, next_hop) triples
    """
    cfg = _hdr(name)
    cfg += [f"! role: {role}", "!"]

    if loopback:
        cfg += ["interface Loopback0",
                f" description {role} router-id / OOB anchor",
                f" ip address {loopback} 255.255.255.255",
                " no shutdown", "!"]

    for ifname, ip, mask in interfaces:
        cfg += [f"interface {ifname}"]
        if ip and ip != "unnamed":
            cfg += [f" ip address {ip} {mask}"]
        cfg += [" no shutdown"]
        if ifname.startswith("Serial"):
            if serial_clock and ifname in serial_clock:
                cfg += [f" clock rate {serial_clock[ifname]}"]
        else:
            cfg += [" duplex auto", " speed auto"]
        cfg += ["!"]

    cfg += mgmt_acl_lines()

    if ospf:
        cfg += [f"router ospf 1", f" router-id {loopback or interfaces[0][1]}",
                f" auto-cost reference-bandwidth 10000"]
        if ospf_passive_default:
            cfg += [" passive-interface default"]
            for i in (ospf_active or []):
                cfg += [f" no passive-interface {i}"]
        for entry in ospf:
            net, wc = entry[0], entry[1]
            a = entry[2] if len(entry) > 2 else area
            cfg += [f" network {net} {wc} area {a}"]
        cfg += [" log-adjacency-changes detail", "!"]

    if statics:
        for pfx, mask, nh in statics:
            cfg += [f"ip route {pfx} {mask} {nh}"]
        cfg += ["!"]

    if bgp:
        cfg += [f"router bgp {BGP_ASN}", f" bgp router-id {bgp['router_id']}",
                " bgp log-neighbor-changes", " no synchronization",
                " bgp graceful-restart restart-time 120",
                f" network {bgp['primary_net']} mask {bgp['primary_mask']}"]
        for ip, asn, desc in bgp["neighbors"]:
            cfg += [f" neighbor {ip} remote-as {asn}",
                    f" neighbor {ip} description {desc}",
                    f" neighbor {ip} update-source Loopback0"]
        cfg += ["!"]

    if qos:
        cfg += _qos_lines()

    if extra:
        cfg += extra

    cfg = _lines(cfg)
    cfg += _banner(name, role)
    cfg += ["!", "end"]
    return cfg


def _qos_lines() -> list[str]:
    """Link-16 / JADGE track-data priority treatment (LLQ + WRED)."""
    return [
        "class-map match-any CM-TRACK-DATA",
        " match access-group name ACL-TRACK-DATA",
        "class-map match-any CM-JADGE-C2",
        " match access-group name ACL-JADGE-C2",
        "class-map match-any CM-VOICE",
        " match access-group name ACL-VOICE",
        "!",
        "policy-map PM-JADGE-WAN",
        " class CM-VOICE",
        "  priority 512",
        " class CM-TRACK-DATA",
        "  priority 2048",
        "  set dscp cs5",
        " class CM-JADGE-C2",
        "  bandwidth remaining percent 40",
        "  random-detect dscp-based",
        " class class-default",
        "  fair-queue",
        "  random-detect",
        "!",
        "ip access-list extended ACL-TRACK-DATA",
        " remark Link-16 / TADIL-J track reporting",
        " permit udp any any range 4000 4010",
        " permit udp any any eq 4200",
        "ip access-list extended ACL-JADGE-C2",
        " remark JADGE C2 session + radar video",
        " permit tcp any any eq 8443",
        " permit tcp any any eq 8080",
        " permit udp any any range 5000 5010",
        "ip access-list extended ACL-VOICE",
        " permit udp any any range 16384 32767",
        "!",
    ]


# --------------------------------------------------------------------------- #
# switches
# --------------------------------------------------------------------------- #
VLAN_NAMES = {
    10: "OPS-TRACK", 20: "MISSION-SYS", 30: "VOICE", 40: "MGMT",
    50: "WIFI", 60: "SERVERS", 70: "TDL-DATALINK", 80: "RADAR-SENSOR",
    99: "BLACKHOLE",
}


def l2_switch_config(name: str, role: str, vlans: list[int],
                     mgmt: tuple[str, str] | None = None,
                     mgmt_vlan: int = 40,
                     uplinks: list[str] | None = None,
                     access_ports: dict[str, int] | None = None,
                     stp_root: list[int] | None = None) -> list[str]:
    cfg = [
        "!",
        "service timestamps debug datetime msec localtime",
        "service timestamps log datetime msec localtime",
        "service password-encryption",
        "service sequence-numbers",
        "!",
        f"hostname {name}",
        "!",
        "no ip domain-lookup",
        f"ip domain-name {DOMAIN}",
        f"enable secret {ENABLE_SECRET}",
        f"username jasdf-admin privilege 15 secret {ADMIN_SECRET}",
        "!",
        f"! role: {role}",
        "!",
        "aaa new-model",
        "aaa authentication login default group radius local",
        "aaa authorization exec default group radius local",
        f"radius-server host {AAA_HOST} auth-port 1645 acct-port 1646 key {AAA_KEY}",
        "ip radius source-interface Vlan40",
        "!",
        "vtp mode transparent",
        "!",
        "spanning-tree mode rapid-pvst",
        "spanning-tree extend system-id",
        "spanning-tree portfast default",
        "spanning-tree portfast bpduguard default",
        "spanning-tree loopguard default",
        "!",
    ]
    for v in vlans:
        cfg += [f"vlan {v}", f" name {VLAN_NAMES.get(v, 'VLAN' + str(v))}"]
    cfg += ["!"]
    if stp_root:
        for v in stp_root:
            cfg += [f"spanning-tree vlan {v} root primary"]
        cfg += ["!"]
    if access_ports:
        for port, v in access_ports.items():
            cfg += [f"interface {port}",
                    f" description access VLAN {v} - {VLAN_NAMES.get(v, v)}",
                    " switchport mode access",
                    f" switchport access vlan {v}",
                    " switchport port-security",
                    " switchport port-security maximum 2",
                    " switchport port-security violation restrict",
                    " switchport port-security mac-address sticky",
                    " no shutdown", "!"]
    if uplinks:
        for port in uplinks:
            cfg += [f"interface {port}",
                    " description 802.1Q trunk uplink",
                    " switchport trunk encapsulation dot1q",
                    " switchport mode trunk",
                    " switchport trunk allowed vlan " + ",".join(str(v) for v in vlans),
                    " switchport nonegotiate",
                    " no shutdown", "!"]
    if mgmt:
        addr, mask = mgmt
        cfg += [f"interface Vlan{mgmt_vlan}",
                f" description in-band management",
                f" ip address {addr} {mask}",
                " no shutdown", "!",
                f"ip default-gateway {mgmt_gw(addr)}", "!"]
    cfg += [f"logging host {SYSLOG_HOST}",
            f"ntp server {NTP_PRIMARY}",
            "snmp-server ifindex persist",
            f"snmp-server community {SNMP_RO} RO",
            "snmp-server enable traps snmp linkdown linkup",
            "!",
            "line con 0",
            " exec-timeout 5 0",
            " logging synchronous",
            " login authentication default",
            "line vty 0 4",
            " exec-timeout 5 0",
            " logging synchronous",
            " login authentication default",
            " transport input ssh",
            "line vty 5 15",
            " login authentication default",
            " transport input ssh",
            "!",
            "end"]
    return cfg


def mgmt_gw(addr: str) -> str:
    p = addr.split(".")
    p[3] = "1"
    return ".".join(p)


def l3_switch_config(name: str, role: str, vlans: list[int],
                     svis: dict[int, tuple[str, str]],
                     loopback: str | None,
                     ospf: list[tuple[str, str]] | None = None,
                     area: int = OSPF_AREA,
                     hsrp: dict[int, tuple[int, str]] | None = None,
                     trunks: list[str] | None = None,
                     access_ports: dict[str, int] | None = None,
                     routed_ports: list[tuple[str, str, str]] | None = None,
                     ospf_active: list[str] | None = None,
                     ip_routing: bool = True) -> list[str]:
    """Multilayer switch config: SVIs, routed WAN ports, OSPF, optional HSRP."""
    cfg = [
        "!",
        "service timestamps debug datetime msec localtime",
        "service timestamps log datetime msec localtime",
        "service password-encryption",
        "service sequence-numbers",
        "!",
        f"hostname {name}",
        "!",
        "no ip domain-lookup",
        f"ip domain-name {DOMAIN}",
        f"enable secret {ENABLE_SECRET}",
        f"username jasdf-admin privilege 15 secret {ADMIN_SECRET}",
        "!",
        f"! role: {role}",
        "!",
    ]
    if ip_routing:
        cfg += ["ip routing", "ip cef", "no ipv6 cef", "!"]
    cfg += [
        "aaa new-model",
        "aaa authentication login default group radius local",
        "aaa authorization exec default group radius local",
        f"radius-server host {AAA_HOST} auth-port 1645 acct-port 1646 key {AAA_KEY}",
        "!",
        "vtp mode transparent",
        "!",
        "spanning-tree mode rapid-pvst",
        "spanning-tree extend system-id",
        "spanning-tree portfast default",
        "spanning-tree portfast bpduguard default",
        "!",
    ]
    for v in vlans:
        cfg += [f"vlan {v}", f" name {VLAN_NAMES.get(v, 'VLAN' + str(v))}"]
    cfg += ["!"]

    if loopback:
        cfg += ["interface Loopback0",
                f" description {role} router-id",
                f" ip address {loopback} 255.255.255.255", "!"]

    for v, (addr, mask) in svis.items():
        cfg += [f"interface Vlan{v}",
                f" description {VLAN_NAMES.get(v, 'VLAN' + str(v))} gateway",
                f" ip address {addr} {mask}"]
        if hsrp and v in hsrp:
            grp, vip = hsrp[v]
            cfg += [f" standby {grp} ip {vip}",
                    f" standby {grp} priority {'110' if addr.endswith('.2') else '100'}",
                    f" standby {grp} preempt",
                    f" standby {grp} track 1 decrement 20"]
        cfg += [" no shutdown", "!"]

    if trunks:
        for port in trunks:
            cfg += [f"interface {port}",
                    " description 802.1Q trunk to access layer",
                    " switchport trunk encapsulation dot1q",
                    " switchport mode trunk",
                    " switchport trunk allowed vlan " + ",".join(str(v) for v in vlans),
                    " switchport nonegotiate",
                    " no shutdown", "!"]

    if routed_ports:
        for port, ip, mask in routed_ports:
            cfg += [f"interface {port}",
                    " description routed uplink (WAN aggregation)",
                    " no switchport",
                    f" ip address {ip} {mask}",
                    " no shutdown", "!"]

    if access_ports:
        for port, v in access_ports.items():
            cfg += [f"interface {port}",
                    " switchport mode access",
                    f" switchport access vlan {v}",
                    " switchport port-security",
                    " switchport port-security maximum 3",
                    " switchport port-security mac-address sticky",
                    " no shutdown", "!"]

    cfg += mgmt_acl_lines()

    if ip_routing and ospf:
        cfg += ["track 1 interface Vlan10 line-protocol", "!",
                "router ospf 1", f" router-id {loopback or '0.0.0.0'}",
                " auto-cost reference-bandwidth 10000",
                " passive-interface default"]
        for i in (ospf_active or []):
            cfg += [f" no passive-interface {i}"]
        for entry in ospf:
            net, wc = entry[0], entry[1]
            a = entry[2] if len(entry) > 2 else area
            cfg += [f" network {net} {wc} area {a}"]
        cfg += [" log-adjacency-changes detail", "!"]

    cfg += ["ip access-list standard 90",
            " permit 10.200.0.0 0.0.255.255",
            " permit 10.0.0.0 0.255.255.255",
            " deny   any log", "!",
            f"logging host {SYSLOG_HOST}",
            f"ntp server {NTP_PRIMARY}",
            "snmp-server ifindex persist",
            f"snmp-server community {SNMP_RO} RO",
            "!",
            "line con 0",
            " exec-timeout 5 0",
            " logging synchronous",
            " login authentication default",
            "line vty 0 4",
            " access-class 90 in",
            " exec-timeout 5 0",
            " login authentication default",
            " transport input ssh",
            "line vty 5 15",
            " access-class 90 in",
            " login authentication default",
            " transport input ssh",
            "!",
            "end"]
    return cfg


# --------------------------------------------------------------------------- #
# Cisco ASA 5505  (the 5505 is a switchport ASA: Ethernet0/x are L2 ports
# bound to VLANs; the routed interfaces are Vlan1/Vlan2/...)
# --------------------------------------------------------------------------- #
def asa_config(name: str, role: str,
               zones: list[dict],
               acls: list[str] | None = None,
               statics: list[tuple[str, str, str]] | None = None,
               routes: list[tuple[str, str, str]] | None = None) -> list[str]:
    """zones: list of {'vlan':int,'nameif':str,'sec':int,'ip':str,'mask':str,
                       'ports':[str,...],'dhcp':bool}"""
    cfg = [
        "!",
        f"hostname {name}",
        "enable password 8Ry2YjIyt7RRXU24 encrypted",
        "passwd 2KFQnbNIdI.2KYOU encrypted",
        "names",
        "!",
        f"! role: {role}",
        "!",
        "interface Ethernet0/0",
        "!",
    ]
    for z in zones:
        for p in z["ports"]:
            cfg += [f"interface {p}", f" switchport access vlan {z['vlan']}", "!"]
    for z in zones:
        cfg += [f"interface Vlan{z['vlan']}",
                f" nameif {z['nameif']}",
                f" security-level {z['sec']}"]
        if z.get("dhcp"):
            cfg += [f" ip address dhcp"]
        else:
            cfg += [f" ip address {z['ip']} {z['mask']}"]
        cfg += ["!"]
    cfg += [
        "interface Ethernet0/0",
        " shutdown",
        "!",
        "boot system disk0:/asa842-k8.bin",
        "ftp mode passive",
        "clock timezone JST 9",
        "same-security-traffic permit inter-interface",
        "same-security-traffic permit intra-interface",
        "!",
        "object network OBJ-ANY",
        " subnet 0.0.0.0 0.0.0.0",
        "!",
    ]
    if acls:
        cfg += acls
    cfg += [
        "pager lines 24",
        "logging enable",
        "logging timestamp",
        f"logging host {zones[0]['nameif']} {SYSLOG_HOST}",
        "logging trap informational",
        "logging asdm informational",
        f"mtu {zones[0]['nameif']} 1500",
        "no failover",
        "icmp unreachable rate-limit 1 burst-size 1",
        "no asdm history enable",
        "arp timeout 14400",
        "no arp permit-nonconnected",
        "!",
        "timeout xlate 3:00:00",
        "timeout pat-xlate 0:00:30",
        "timeout conn 1:00:00 half-closed 0:10:00 udp 0:02:00 icmp 0:00:02",
        "timeout sunrpc 0:10:00 h323 0:05:00 h225 1:00:00 mgcp 0:05:00 mgcp-pat 0:05:00",
        "timeout sip 0:30:00 sip_media 0:02:00 sip-invite 0:03:00 sip-disconnect 0:02:00",
        "timeout uauth 0:05:00 absolute",
        "!",
        "aaa authentication ssh console LOCAL",
        "aaa authentication enable console LOCAL",
        "aaa authorization command LOCAL",
        f"username jasdf-admin password {ADMIN_SECRET.split('$')[-1]} encrypted privilege 15",
        "http server enable",
        f"http 10.200.0.0 255.255.0.0 {zones[0]['nameif']}",
        "no snmp-server location",
        "no snmp-server contact",
        "snmp-server enable traps snmp authentication linkup linkdown coldstart",
        "crypto ipsec ikev1 transform-set TS-JADGE esp-aes-256 esp-sha-hmac",
        "crypto ipsec security-association pmtu-aging infinite",
        "crypto map CM-JADGE 10 match address ACL-VPN-COALITION",
        "crypto map CM-JADGE 10 set peer 10.254.0.2",
        "crypto map CM-JADGE 10 set ikev1 transform-set TS-JADGE",
        "crypto map CM-JADGE interface outside",
        "crypto ikev1 enable outside",
        "crypto ikev1 policy 10",
        " authentication pre-share",
        " encryption aes-256",
        " hash sha",
        " group 14",
        " lifetime 86400",
        "!",
        "telnet timeout 5",
        "ssh stricthostkeycheck",
        f"ssh 10.200.0.0 255.255.0.0 {zones[0]['nameif']}",
        "ssh timeout 10",
        "ssh version 2",
        "console timeout 0",
        "!",
        "class-map inspection_default",
        " match default-inspection-traffic",
        "!",
        "policy-map global_policy",
        " class inspection_default",
        "  inspect dns preset_dns_map",
        "  inspect ftp",
        "  inspect h323 h225",
        "  inspect icmp",
        "  inspect sip",
        "  inspect skinny",
        "  inspect sqlnet",
        "  inspect sunrpc",
        "!",
        "service-policy global_policy global",
        "prompt hostname context",
        "no call-home reporting anonymous",
        "Cryptochecksum:0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        ": end",
    ]
    if statics:
        for o, i, iface in statics:
            cfg += [f"object network OBJ-{o.replace('.', '_')}",
                    f" host {o}",
                    f" nat ({iface},outside) static {i}", "!"]
    if routes:
        for pfx, mask, nh in routes:
            cfg += [f"route outside {pfx} {mask} {nh} 1"]
    return cfg


# --------------------------------------------------------------------------- #
# Server-PT / PC-PT service injection (XML level)
# --------------------------------------------------------------------------- #
def _child(parent: ET.Element, tag: str) -> ET.Element:
    e = parent.find(tag)
    if e is None:
        e = ET.SubElement(parent, tag)
    return e


def _set(parent: ET.Element, tag: str, text) -> ET.Element:
    e = _child(parent, tag)
    e.text = str(text)
    return e


def _clear(parent: ET.Element, tag: str) -> ET.Element:
    e = _child(parent, tag)
    for c in list(e):
        e.remove(c)
    return e


def configure_server(dev_el: ET.Element, *,
                     dns_records: list[tuple[str, str]] | None = None,
                     dhcp_pools: list[dict] | None = None,
                     http: bool = False, http_user: str = "", http_pass: str = "",
                     https: bool = False,
                     ftp_user: str | None = None, ftp_pass: str = "cisco",
                     ntp: bool = False,
                     syslog: bool = False,
                     aaa_users: list[tuple[str, str]] | None = None,
                     aaa_clients: list[tuple[str, str, str]] | None = None,
                     email_domain: str | None = None,
                     iface: str = "FastEthernet0") -> None:
    """Write Server-PT service configuration into the device's <ENGINE>."""
    eng = dev_el.find("ENGINE")
    if eng is None:
        return

    if https:
        _set(_child(eng, "HTTPS_SERVER"), "HTTPSENABLED", 1)
    if http:
        h = _child(eng, "HTTP_SERVER")
        _set(h, "ENABLED", 1)
        _set(h, "USERNAME", http_user)
        _set(h, "PASSWORD", http_pass)

    if dns_records is not None:
        d = _child(eng, "DNS_SERVER")
        _set(d, "ENABLED", 1)
        db = _clear(d, "NAMESERVER-DATABASE")
        for name, ip in dns_records:
            r = ET.SubElement(db, "RESOURCE-RECORD")
            ET.SubElement(r, "TYPE").text = "A-REC"
            ET.SubElement(r, "NAME").text = name
            ET.SubElement(r, "TTL").text = "86400"
            ET.SubElement(r, "IPADDRESS").text = ip

    if dhcp_pools:
        wrap = _child(eng, "DHCP_SERVERS")
        ports = _clear(wrap, "ASSOCIATED_PORTS")
        for pool in dhcp_pools:
            ap = ET.SubElement(ports, "ASSOCIATED_PORT")
            ET.SubElement(ap, "NAME").text = iface
            srv = ET.SubElement(ap, "DHCP_SERVER")
            ET.SubElement(srv, "ENABLED").text = "1"
            pools = ET.SubElement(srv, "POOLS")
            p = ET.SubElement(pools, "POOL")
            ET.SubElement(p, "NAME").text = pool["name"]
            ET.SubElement(p, "NETWORK").text = pool["network"]
            ET.SubElement(p, "MASK").text = pool["mask"]
            ET.SubElement(p, "DEFAULT_ROUTER").text = pool["router"]
            ET.SubElement(p, "TFTP_ADDRESS").text = pool.get("tftp", "0.0.0.0")
            ET.SubElement(p, "START_IP").text = pool["start"]
            ET.SubElement(p, "END_IP").text = pool["end"]
            ET.SubElement(p, "DNS_SERVER").text = pool.get("dns", DNS_PRIMARY)
            ET.SubElement(p, "MAX_USERS").text = str(pool.get("max", 512))
            ET.SubElement(p, "DOMAIN_NAME").text = pool.get("domain", DOMAIN)
            ET.SubElement(p, "DHCP_POOL_LEASES")
            ET.SubElement(p, "LEASE_TIME").text = str(pool.get("lease", 86400000))
            ET.SubElement(p, "WLC_ADDRESS").text = "0.0.0.0"
            ET.SubElement(srv, "DHCP_RESERVATIONS")
            ET.SubElement(srv, "AUTOCONFIG")

    if ftp_user:
        f = _child(eng, "FTP_SERVER")
        _set(f, "ENABLED", 1)
        m = _clear(f, "USER_ACCOUNT_MNGR")
        a = ET.SubElement(m, "ACCOUNT")
        ET.SubElement(a, "USERNAME").text = ftp_user
        ET.SubElement(a, "PASSWORD").text = ftp_pass
        ET.SubElement(a, "PERMISSIONS").text = "RWDNL"

    if ntp:
        n = _child(eng, "NTP_SERVER")
        _set(n, "ENABLED", 1)
        _set(n, "ENABLED_SERVER_AUTHENTICATE", 0)
        _set(n, "KEY", 1)
        _set(n, "MD5PASSWORD", AAA_KEY)

    if syslog:
        _set(_child(eng, "SYSLOG_SERVER"), "ENABLED", 1)

    if aaa_users is not None or aaa_clients is not None:
        s = _child(eng, "ACS_SERVER")
        _set(s, "ENABLED", 1)
        us = _clear(s, "USERS")
        for u, p in (aaa_users or []):
            x = ET.SubElement(us, "USER")
            ET.SubElement(x, "NAME").text = u
            ET.SubElement(x, "PASSWORD").text = p
            ET.SubElement(x, "DESCRIPTION").text = "JASDF privileged operator"
        cs = _clear(s, "ACS_CLIENTS")
        for ip, key, desc in (aaa_clients or []):
            c = ET.SubElement(cs, "CLIENT")
            ET.SubElement(c, "HOST_IP").text = ip
            ET.SubElement(c, "KEY").text = key
            ET.SubElement(c, "DESCRIPTION").text = desc
            ET.SubElement(c, "SERVER_TYPE").text = "RADIUS"
        rs = _child(s, "RADIUS_SETTINGS")
        _set(rs, "AUTH_PORT", 1645)

    if email_domain:
        e = _child(eng, "EMAIL_SERVER")
        _set(e, "SMTP_ENABLED", 1)
        _set(e, "SMTP_DOMAIN", email_domain)
        _set(e, "POP3_ENABLED", 1)
        _set(e, "FORWARD_MAIL", 0)
        _set(e, "NO_OF_USERS", 0)
