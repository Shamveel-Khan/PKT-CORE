# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Tests for the IOS-command attestation auditor (problem 20).

What is tested here, and why
----------------------------
``tools/audit_ios_commands.py`` makes a claim about every configuration line a
generator emits: *either* Packet Tracer has stored this command before (the
reference corpus attests it), *or* it is a recognisable standard Cisco IOS
construct, *or* it is suspicious.  A false "suspicious" would make the tool
useless (everything fails); a false "standard" would hide exactly the defect
the tool exists to find.  So the tests pin down:

1. **the normaliser** — volatile parts (hostnames, IPs, descriptions, secrets,
   sequence numbers, interface numbers, ACL/policy names) must never influence
   the signature, while the command verb and keyword chain always must;
2. **submode recovery** — IOS running-config is indentation-based, so the
   submode (``interface`` / ``router ospf`` / ``line`` ...) is part of a
   command's identity and must be recovered from indentation alone;
3. **multi-line banner state** — ``banner motd #`` is followed by free text
   terminated by a second ``#``; those lines are content, never commands;
4. **the verdict classifier** — the curated standard-IOS vocabulary accepts
   real CCNA/CCNP constructs and rejects template artefacts, truncated
   commands and unrecognised verbs;
5. **the artefact walker** — ``<LINE>`` elements are read from
   ``<DEVICE><ENGINE><RUNNINGCONFIG>`` in both the plain and the nested
   activity document skeletons.

Nothing in this module needs Packet Tracer.  The end-to-end corpus test is
opt-in (``-m corpus``) and skips cleanly when the corpus is not fetched.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

audit = pytest.importorskip(
    "audit_ios_commands",
    reason="tools/audit_ios_commands.py is not importable",
)

# Corpus locations used by the rest of the suite (see tests/test_corpus_acceptance.py).
CORPUS_INDEX = REPO.parent / "corpus" / "CORPUS_INDEX.tsv"
CORPUS_DIR = REPO.parent / "corpus" / "internet"


# =========================================================================== #
# 1. Token shapes
# =========================================================================== #


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("10.11.60.16", "<ip>"),
        ("0.0.0.0", "<ip>"),
        ("255.255.255.252", "<ip>"),
        ("10.10.10.1/24", "<ip>"),
        ("2001:db8::1", "<ip6>"),
        ("fe80::1/64", "<ip6>"),
        ("0011.2233.4455", "<mac>"),
        ("00:11:22:33:44:55", "<mac>"),
        ("GigabitEthernet1/0/1", "<if>"),
        ("Gi0/1", "<if>"),
        ("Serial0/0/0", "<if>"),
        ("Vlan40", "<if>"),
        ("Loopback0", "<if>"),
        ("Port-channel1", "<if>"),
        ("65001", "<n>"),
        ("0", "<n>"),
        ("$1$Jz8k$QbV3nR7dTpWmYc2LxH9uK1", "<secret>"),
        ("$9$abcdefghijkl", "<secret>"),
        ("0011aabbccddeeff0011", "<hash>"),
        ("admin@example.mod.go.jp", "<email>"),
        ("3:00:00", "<time>"),
        ("tftp://10.11.60.19/JASDF/$h-$t", "<url>"),
        # --- must NOT be masked -------------------------------------------
        ("vlan", "vlan"),          # a keyword, not `Vlan<n>`
        ("serial", "serial"),
        ("permit", "permit"),
        ("access-group", "access-group"),
        ("jasdf-hsrp", "jasdf-hsrp"),
        ("acl-vpn-coalition", "acl-vpn-coalition"),
        ("crypto", "crypto"),
        ("<ip>", "<ip>"),          # our own placeholder is never re-masked
        ("<text>", "<text>"),
        ("1:00", "1:00"),          # not a valid IPv6 address, not a <time>
        ("hostname-x", "hostname-x"),
        ("Giants", "Giants"),      # `Gi` prefix without a number
    ],
)
def test_shape_token(token: str, expected: str) -> None:
    assert audit.shape_token(token) == expected


def test_ipv6_shape_is_strict() -> None:
    """A loose hex/colon pattern silently eats ASA timeout literals."""
    assert audit.shape_token("2001:db8::1") == "<ip6>"
    assert audit.shape_token("1:00:00") == "<time>"
    assert audit.shape_token("0:30:00") != "<ip6>"


# =========================================================================== #
# 2. The normaliser
# =========================================================================== #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # --- verb + keyword chain survives --------------------------------
        ("spanning-tree mode rapid-pvst", "spanning-tree mode rapid-pvst"),
        ("ip route 0.0.0.0 0.0.0.0 10.0.0.1", "ip route <ip> <ip> <ip>"),
        ("ip address 10.11.60.11 255.255.255.0", "ip address <ip> <ip>"),
        ("switchport access vlan 60", "switchport access vlan <n>"),
        ("switchport trunk encapsulation dot1q",
         "switchport trunk encapsulation dot1q"),
        ("no shutdown", "no shutdown"),
        ("shutdown", "shutdown"),
        ("clock rate 4000000", "clock rate <n>"),
        ("encapsulation dot1q 10", "encapsulation dot1q <n>"),
        ("mtu 1500", "mtu <n>"),
        ("duplex auto", "duplex auto"),
        ("line con 0", "line con <n> <n>"),
        ("line vty 0 4", "line vty <n> <n>"),
        # --- volatile parts are gone --------------------------------------
        ("hostname JADGE-BB-SW-01", "hostname <text>"),
        ("ip domain-name jasdf.mod.go.jp", "ip domain-name <text>"),
        ("description access VLAN 60 - SERVERS", "description <text>"),
        ("enable secret 5 $1$Jz8k$QbV3nR7dTpWmYc2LxH9uK1",
         "enable secret <n> <secret>"),
        ("enable password 7 0822455D0A16", "enable password <n> <secret>"),
        # ASA form: the value after `password` is a hash, not a type digit
        ("enable password 8Ry2YjIyt7RRXU24 encrypted", "enable password <secret>"),
        ("passwd 2KFQnbNIdI.2KYOU encrypted", "passwd <secret> encrypted"),
        ("username jasdf-admin privilege 15 secret 5 $1$Kp2s$Rt5Yh8Nq4WzXc6BmL3vJd0",
         "username <text> privilege <n> secret <n> <secret>"),
        ("username jasdf-admin password Rt5Yh8Nq4WzXc6BmL3vJd0 encrypted privilege 15",
         "username <text> password <secret> encrypted privilege <n>"),
        ("snmp-server community JASDF-RO-9f3c RO", "snmp-server community <text> ro"),
        ("snmp-server community JASDF-RW-1a7e RW", "snmp-server community <text> rw"),
        ("snmp-server location JASDF-AWACS-JADGE", "snmp-server location <text>"),
        ("snmp-server contact JASDF_ADC_NOSC", "snmp-server contact <text>"),
        ("snmp-server host 10.11.60.15 version 2c JASDF-RO-9f3c",
         "snmp-server host <ip> version 2c <text>"),
        ("radius-server host 10.11.60.16 auth-port 1645 acct-port 1646 key r4d1us-J4DG3-k3y",
         "radius-server host <ip> auth-port <n> acct-port <n> key <text>"),
        ("ntp authentication-key 1 md5 r4d1us-J4DG3-k3y",
         "ntp authentication-key <n> md5 <text>"),
        ("ntp server 10.11.60.14 key 1 source Loopback0 prefer",
         "ntp server <ip> key <n> source <if> prefer"),
        ("vlan 10", "vlan <n>"),
        ("name OPS-TRACK", "name <text>"),
        ("nameif outside", "nameif <text>"),
        ("security-level 100", "security-level <n>"),
        ("ip access-list extended ACL-TRACK-DATA",
         "ip access-list extended <text>"),
        ("class-map match-any CM-TRACK-DATA", "class-map match-any <text>"),
        ("policy-map PM-JADGE-WAN", "policy-map <text>"),
        ("class CM-VOICE", "class <text>"),
        ("class class-default", "class class-default"),
        ("match access-group name ACL-JADGE-C2", "match access-group name <text>"),
        ("service-policy output PM-JADGE-WAN", "service-policy output <text>"),
        ("service-policy global_policy global", "service-policy <text> global"),
        ("neighbor 10.255.0.2 description iBGP JADGE peer cr2",
         "neighbor <ip> description <text>"),
        ("neighbor 10.255.0.2 remote-as 65001", "neighbor <ip> remote-as <n>"),
        ("standby 10 authentication md5 key-string JASDF-HSRP",
         "standby <n> authentication md5 key-string <text>"),
        ("standby 10 track 1 decrement 20", "standby <n> track <n> decrement <n>"),
        ("crypto map CM-JADGE 10 match address ACL-VPN-COALITION",
         "crypto map <text> <n> match address <name>"),
        ("crypto map CM-JADGE 10 set peer 10.254.0.2",
         "crypto map <text> <n> set peer <ip>"),
        ("crypto ipsec ikev1 transform-set TS-JADGE esp-aes-256 esp-sha-hmac",
         "crypto ipsec ikev1 transform-set <text> esp-aes-256 esp-sha-hmac"),
        ("access-list outside-in extended permit tcp any host 10.11.60.15 eq 443",
         "access-list <name> extended permit tcp any host <ip> eq <n>"),
        ("boot system disk0:/asa842-k8.bin", "boot system <text>"),
        ("path tftp://10.11.60.19/JASDF/$h-$t", "path <url>"),
        ("timeout xlate 3:00:00", "timeout xlate <time>"),
        ("track 1 interface GigabitEthernet0/0/1 line-protocol",
         "track <n> interface <if> line-protocol"),
        ("switchport trunk allowed vlan 10,20,30,40,50,60",
         "switchport trunk allowed vlan <text>"),
        ("logging host 10.11.60.15", "logging host <ip>"),
        ("ip dhcp pool pool1", "ip dhcp pool <text>"),
        ("ip dhcp excluded-address 192.168.1.1 192.168.1.10",
         "ip dhcp excluded-address <ip> <ip>"),
    ],
)
def test_normalise_body(raw: str, expected: str) -> None:
    assert audit.normalise_body(raw) == expected


def test_normalise_is_case_and_whitespace_insensitive() -> None:
    assert audit.normalise_body("  SWITCHPORT   ACCESS  VLAN   60 ") == \
        audit.normalise_body("switchport access vlan 60")


def test_normalise_ignores_leading_indentation() -> None:
    assert audit.normalise_body("   ip address 10.0.0.1 255.255.255.0") == \
        audit.normalise_body("ip address 10.0.0.1 255.255.255.0")


def test_two_different_labs_produce_one_signature() -> None:
    """The whole point: volatility must not split a signature."""
    a = audit.normalise_body("hostname JADGE-BB-SW-01")
    b = audit.normalise_body("hostname RDR-WAKKANAI-RTR")
    assert a == b == "hostname <text>"


def test_keyword_chain_is_never_collapsed() -> None:
    """Over-masking would produce a false ATTESTED; these must stay distinct."""
    assert audit.normalise_body("ip ospf network point-to-point") != \
        audit.normalise_body("ip ospf cost 10")
    assert audit.normalise_body("switchport mode trunk") != \
        audit.normalise_body("switchport mode access")
    assert audit.normalise_body("no shutdown") != audit.normalise_body("shutdown")
    assert audit.normalise_body("router ospf 1") != audit.normalise_body("router bgp 1")


def test_prompt_prefix_is_stripped() -> None:
    assert audit.normalise_body("R1(config-if)# ip address 10.0.0.1 255.0.0.0") == \
        "ip address <ip> <ip>"
    assert audit.normalise_body("Switch> enable") == "enable"


def test_control_bytes_are_normalised_not_dropped() -> None:
    """PT stores the IOS banner delimiter as raw 0x03 (illegal XML 1.0).

    The delimiter must survive as its own token so a `^C`-delimited banner is
    still recognised, and any other C0 byte must not crash the normaliser.
    """
    assert audit.normalise_body("\x03") == "\x03"
    assert audit.normalise_body("banner motd \x03") == "banner motd <text>"
    assert audit.normalise_body("ip cef\x01") == "ip cef"
    # a line carrying an embedded control byte still yields a signature
    assert "<ip>" in audit.normalise_body("ip ad\x03dress 10.0.0.1 255.0.0.0")


# =========================================================================== #
# 3. Submode recovery and banner handling
# =========================================================================== #


def _feed(lines: list[str]) -> list[audit.NormalisedLine]:
    return list(audit.SignatureExtractor().feed_all(lines))


def test_indentation_recovers_submodes() -> None:
    out = _feed([
        "hostname R1",
        "interface GigabitEthernet0/0",
        " description uplink",
        " ip address 10.0.0.1 255.255.255.252",
        " no shutdown",
        "line vty 0 4",
        " transport input ssh",
        "router ospf 1",
        " network 10.0.0.0 0.0.0.3 area 0",
        "ip route 0.0.0.0 0.0.0.0 10.0.0.2",
    ])
    assert [(n.mode, n.body) for n in out] == [
        ("global", "hostname <text>"),
        ("interface", "interface <if>"),
        ("interface", "description <text>"),
        ("interface", "ip address <ip> <ip>"),
        ("interface", "no shutdown"),
        ("line", "line vty <n> <n>"),
        ("line", "transport input ssh"),
        ("router-ospf", "router ospf <n>"),
        ("router-ospf", "network <ip> <ip> area <n>"),
        ("global", "ip route <ip> <ip> <ip>"),
    ]


def test_nested_submodes_pop_correctly() -> None:
    """`log config` nests inside `archive`; both must be recovered."""
    out = _feed([
        "archive",
        " log config",
        "  logging enable",
        "  hidekeys",
        " write-memory",
    ])
    assert [(n.mode, n.body) for n in out] == [
        ("archive", "archive"),
        ("archive-log-config", "log config"),
        ("archive-log-config", "logging enable"),
        ("archive-log-config", "hidekeys"),
        ("archive", "write-memory"),
    ]


def test_same_command_in_different_submodes_is_a_different_signature() -> None:
    """`network` under `router ospf` is not `network` under `ip dhcp pool`."""
    out = _feed([
        "router ospf 1",
        " network 10.0.0.0 0.0.0.255 area 0",
        "ip dhcp pool LAN",
        " network 192.168.1.0 255.255.255.0",
    ])
    keys = {n.key for n in out if n.body.startswith("network")}
    assert keys == {
        "router-ospf|network <ip> <ip> area <n>",
        "ip-dhcp-pool|network <ip> <ip>",
    }


def test_banner_body_is_never_a_command() -> None:
    out = _feed([
        "banner motd #",
        "******************************",
        "*  RESTRICTED SYSTEM",
        "*  hostname R1",
        "#",
        "ip cef",
    ])
    kinds = [n.kind for n in out]
    assert kinds == ["command", "banner-body", "banner-body", "banner-body",
                     "banner-body", "command"]
    assert out[0].body == "banner motd <text>"
    # `ip cef` after the banner terminator is a command again
    assert out[-1].body == "ip cef"
    assert out[-1].mode == "global"


def test_banner_content_never_leaks_into_a_signature() -> None:
    """A `hostname`-shaped line inside a banner must not become a signature."""
    out = _feed([
        "banner motd #",
        "hostname EVIL-SHOULD-NOT-COUNT",
        "#",
    ])
    assert [n.body for n in out] == ["banner motd <text>", "", ""]


def test_one_line_banner_does_not_swallow_following_config() -> None:
    out = _feed(["banner motd #Authorised use only#", "ip cef"])
    assert [(n.kind, n.body) for n in out] == [
        ("command", "banner motd <text>"),
        ("command", "ip cef"),
    ]


def test_comments_and_blanks_are_ignored() -> None:
    out = _feed(["!", "", "   ", "! role: core switch", "end", "ip cef"])
    assert [n.kind for n in out] == ["ignored"] * 5 + ["command"]


def test_inline_comment_after_bang_is_ignored() -> None:
    """`! role: ...` is a comment; it must never become a signature."""
    out = _feed(["! role: JADGE backbone L3 core switch A (OSPF area 0, iBGP edge)"])
    assert out[0].kind == "ignored"


# =========================================================================== #
# 4. The verdict classifier
# =========================================================================== #


def test_genuine_standard_construct_is_not_suspicious() -> None:
    cls = audit.classify_unattested("ip ospf network point-to-point")
    assert cls.verdict == "UNATTESTED"
    assert cls.category == "standard"
    assert "ip" in cls.reason


@pytest.mark.parametrize(
    "body",
    [
        "ip ospf network point-to-point",
        "ip ospf cost 10",
        "ip ospf priority 1",
        "standby 10 track 1 decrement 20",
        "crypto ikev1 policy 10",
        "inspect h323 h225",
        "random-detect dscp-based",
        "bandwidth remaining percent 40",
        "spanning-tree portfast bpduguard default",
        "snmp-server ifindex persist",
        "ip dhcp relay information trust-all",
        "ntp update-calendar",
        "ip radius source-interface Loopback0",
        "service tcp-keepalives-in",
        "ssh stricthostkeycheck",
        "same-security-traffic permit intra-interface",
        "no ip gratuitous-arps",
        "passive-interface default",
        "auto-cost reference-bandwidth 10000",
        "log-adjacency-changes detail",
        "write-memory",
        "hidekeys",
    ],
)
def test_standard_ios_vocabulary_accepts_real_constructs(body: str) -> None:
    cls = audit.classify_unattested(body)
    assert cls.category == "standard", f"{body!r} -> {cls}"


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("ip routng 10.0.0.0 255.0.0.0 10.0.0.1", "unrecognised-ip-keyword:routng"),
        ("ipv6 addres 2001:db8::1/64", "unrecognised-ipv6-keyword:addres"),
        ("routng ospf 1", "unrecognised-command-verb:routng"),
        ("{{hostname}}", "template-placeholder"),
        ("${DEVICE_NAME}", "template-placeholder"),
        ("<% name %>", "template-placeholder"),
        ("TODO configure ospf", "development-marker"),
        ("<INSERT_COMMUNITY>", "unresolved-html-placeholder"),
        ("ip address", "truncated-command"),
        ("description", "truncated-command"),
        ("permit", "truncated-command"),
        ("network", "truncated-command"),
        ("ip ip cef", "duplicated-keyword"),
        ("-------", "separator-line"),
        ("42", "bare-number"),
        ("x", "single-character-command"),
    ],
)
def test_suspicious_lines_are_detected(body: str, reason: str) -> None:
    cls = audit.classify_unattested(body)
    assert cls.verdict == "UNATTESTED"
    assert cls.category == "suspicious", f"{body!r} -> {cls}"
    assert cls.reason == reason


def test_non_ascii_is_suspicious() -> None:
    cls = audit.classify_unattested("hostname RØUTER")
    assert cls.category == "suspicious"
    assert cls.reason == "non-ascii-byte"


def test_submode_mismatch_is_standard_not_suspicious() -> None:
    """A command attested in another submode is a finding, not a defect."""
    cls = audit.classify_unattested("write-memory", body_attested_in="archive")
    assert cls.category == "standard"

    # a body with no standard vocabulary of its own still passes once the
    # corpus is known to attest it somewhere else
    cls = audit.classify_unattested("jasdf-widget-mode 7",
                                    body_attested_in="interface")
    assert cls.category == "standard"
    assert "interface" in cls.reason


def test_duplicated_keyword_is_suspicious() -> None:
    cls = audit.classify_unattested("ip ip nat inside source")
    assert cls.category == "suspicious"


def test_classifier_returns_a_frozen_dataclass() -> None:
    cls = audit.classify_unattested("ip cef")
    assert isinstance(cls, audit.Classification)
    with pytest.raises(Exception):
        cls.verdict = "ATTESTED"  # type: ignore[misc]


# =========================================================================== #
# 5. The artefact walker
# =========================================================================== #

_PLAIN_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5>
 <VERSION>9.0.1.0858</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE>
    <ENGINE>
     <NAME>R1</NAME>
     <TYPE>1</TYPE>
     <RUNNINGCONFIG>
      <LINE>hostname R1</LINE>
      <LINE>!</LINE>
      <LINE>interface GigabitEthernet0/0</LINE>
      <LINE> ip address 10.0.0.1 255.255.255.0</LINE>
      <LINE> no shutdown</LINE>
     </RUNNINGCONFIG>
    </ENGINE>
   </DEVICE>
   <DEVICE>
    <ENGINE>
     <NAME>SW1</NAME>
     <RUNNINGCONFIG>
      <LINE>hostname SW1</LINE>
      <LINE>vlan 10</LINE>
      <LINE> name OPS</LINE>
     </RUNNINGCONFIG>
    </ENGINE>
   </DEVICE>
  </DEVICES>
  <LINKS/>
 </NETWORK>
</PACKETTRACER5>
"""

_NESTED_ACTIVITY_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5_ACTIVITY>
 <PACKETTRACER5>
  <NETWORK>
   <DEVICES>
    <DEVICE>
     <ENGINE>
      <NAME>R9</NAME>
      <RUNNINGCONFIG>
       <LINE>ip cef</LINE>
      </RUNNINGCONFIG>
     </ENGINE>
    </DEVICE>
   </DEVICES>
  </NETWORK>
 </PACKETTRACER5>
 <ACTIVITY/>
</PACKETTRACER5_ACTIVITY>
"""


def test_walker_reads_plain_skeleton() -> None:
    got = dict(audit._iter_running_configs(_PLAIN_XML))
    assert set(got) == {"R1", "SW1"}
    assert got["R1"][0] == "hostname R1"
    assert " interface GigabitEthernet0/0" not in got["R1"]
    assert " ip address 10.0.0.1 255.255.255.0" in got["R1"]


def test_walker_reads_nested_activity_skeleton() -> None:
    got = dict(audit._iter_running_configs(_NESTED_ACTIVITY_XML))
    assert got == {"R9": ["ip cef"]}


def test_walker_handles_document_without_devices() -> None:
    assert list(audit._iter_running_configs(b"<PACKETTRACER5><NETWORK/></PACKETTRACER5>")) == []


def test_extractor_end_to_end_on_synthetic_document(tmp_path: Path) -> None:
    """Full pipeline: XML bytes -> signatures -> adjudication."""
    from pkt_core import encode_bytes

    pkt = tmp_path / "synthetic.pkt"
    pkt.write_bytes(encode_bytes(_PLAIN_XML, "pkt"))

    report = audit.extract_artifact_signatures(pkt)
    assert report.devices == 2
    assert report.blocks == 2
    assert report.lines == 8
    bodies = {s.body for s in report.signatures.values()}
    assert "ip address <ip> <ip>" in bodies
    assert "vlan <n>" in bodies
    assert "name <text>" in bodies

    # An attestation set that knows two of the five signatures.
    att = audit.Attestation(
        signatures={
            "global|hostname <text>": 12,
            "interface|ip address <ip> <ip>": 30,
        },
        bodies={"hostname <text>": 12, "ip address <ip> <ip>": 30},
        files_ok=12,
    )
    rows = audit.adjudicate(report, att)
    by_sig = {r["signature"]: r for r in rows}
    assert by_sig["global|hostname <text>"]["verdict"] == "ATTESTED"
    assert by_sig["global|hostname <text>"]["corpus_files"] == 12
    assert by_sig["interface|ip address <ip> <ip>"]["verdict"] == "ATTESTED"
    assert by_sig["interface|no shutdown"]["verdict"] == "UNATTESTED"
    assert by_sig["interface|no shutdown"]["category"] == "standard"


def test_adjudicate_reports_body_only_attestation(tmp_path: Path) -> None:
    from pkt_core import encode_bytes

    pkt = tmp_path / "synthetic.pkt"
    pkt.write_bytes(encode_bytes(_PLAIN_XML, "pkt"))
    report = audit.extract_artifact_signatures(pkt)

    # `write-memory` is attested only under `archive` in the corpus.
    att = audit.Attestation(signatures={"archive|write-memory": 3},
                            bodies={"write-memory": 3})
    rows = audit.adjudicate(report, att)
    # none of the synthetic signatures are `write-memory`; assert the plumbing
    assert all(r["verdict"] == "UNATTESTED" for r in rows)
    assert all(r["corpus_files_body_only"] == 0 for r in rows)


# =========================================================================== #
# 6. Summary / report shapes
# =========================================================================== #


def test_summarise_rows_counts_categories() -> None:
    rows = [
        {"verdict": "ATTESTED", "category": None, "emitted": 10},
        {"verdict": "UNATTESTED", "category": "standard", "emitted": 3},
        {"verdict": "UNATTESTED", "category": "standard", "emitted": 1},
        {"verdict": "UNATTESTED", "category": "suspicious", "emitted": 7},
    ]
    s = audit.summarise_rows(rows)
    assert s["distinct_signatures"] == 4
    assert s["attested_signatures"] == 1
    assert s["unattested_signatures"] == 3
    assert s["unattested_standard"] == 2
    assert s["unattested_suspicious"] == 1
    assert s["suspicious_emissions"] == 7


def test_cache_round_trip(tmp_path: Path) -> None:
    att = audit.Attestation(
        signatures={"global|ip cef": 5},
        bodies={"ip cef": 5},
        files_ok=5,
        files_failed=1,
        failures={"broken.pkt": "IntegrityError: bad tag"},
        corpus_dir="/tmp/corpus",
        fingerprint="abc123",
        generated="2026-01-01T00:00:00Z",
    )
    cache = tmp_path / "ios_attestation.json"
    audit.save_cache(att, cache)
    back = audit.load_cache(cache)
    assert back is not None
    assert back.signatures == att.signatures
    assert back.failures == {"broken.pkt": "IntegrityError: bad tag"}
    assert back.files_failed == 1
    assert back.cache_hit is True


def test_cache_rejects_wrong_schema(tmp_path: Path) -> None:
    cache = tmp_path / "ios_attestation.json"
    cache.write_text(json.dumps({"schema": "something-else"}), encoding="utf-8")
    assert audit.load_cache(cache) is None


def test_decode_failure_is_never_an_empty_file(tmp_path: Path) -> None:
    """A failed decode must be an explicit failure record, not zero signatures."""
    junk = tmp_path / "not-a-pkt.pkt"
    junk.write_bytes(b"this is not a packet tracer container" * 10)
    res = audit.decode_one(str(junk))
    assert res.ok is False
    assert res.error
    assert res.signatures == []


def test_iter_corpus_files_finds_files_subdirectory(tmp_path: Path) -> None:
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "a.pkt").write_bytes(b"x")
    (tmp_path / "files" / "b.pka").write_bytes(b"x")
    (tmp_path / "files" / "notes.txt").write_bytes(b"x")
    got = [p.name for p in audit.iter_corpus_files(tmp_path, None)]
    assert got == ["a.pkt", "b.pka"]


def test_iter_corpus_files_accepts_flat_directory(tmp_path: Path) -> None:
    (tmp_path / "c.pkt").write_bytes(b"x")
    got = [p.name for p in audit.iter_corpus_files(tmp_path, None)]
    assert got == ["c.pkt"]


def test_iter_corpus_files_includes_suffixed_duplicates(tmp_path: Path) -> None:
    """The harvester renames duplicates to `<name>.pkt__<id>`."""
    (tmp_path / "a.pkt").write_bytes(b"x")
    (tmp_path / "a.pkt__12345").write_bytes(b"x")
    got = [p.name for p in audit.iter_corpus_files(tmp_path, None)]
    assert got == ["a.pkt", "a.pkt__12345"]


def test_iter_corpus_files_prefers_the_manifest(tmp_path: Path) -> None:
    (tmp_path / "a.pkt").write_bytes(b"x")
    (tmp_path / "b.pka").write_bytes(b"x")
    (tmp_path / "not-listed.pkt").write_bytes(b"x")
    (tmp_path / "bundle.zip").write_bytes(b"x")
    index = tmp_path / "CORPUS_INDEX.tsv"
    index.write_text(
        "filename\tbytes\tsha256\tdecode_status\txml_root_tag\tsource\n"
        "a.pkt\t1\tdeadbeef\tOK\tPACKETTRACER5\tsrc\n"
        "bundle.zip\t1\tdeadbeef\tOK\t?\tsrc\n",
        encoding="utf-8",
    )
    got = [p.name for p in audit.iter_corpus_files(tmp_path, index)]
    assert got == ["a.pkt"]


# =========================================================================== #
# 7. CLI behaviour (no Packet Tracer, no corpus needed)
# =========================================================================== #


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOLS / "audit_ios_commands.py"), *args],
        capture_output=True, text=True, cwd=str(REPO),
    )


def test_cli_exits_one_without_an_artefact() -> None:
    proc = _run_cli()
    assert proc.returncode == 1
    assert "no artefact" in proc.stderr


def test_cli_exits_one_on_a_missing_artefact() -> None:
    proc = _run_cli("--artifact", "/nonexistent/lab.pkt")
    assert proc.returncode == 1
    assert "not found" in proc.stderr


def test_cli_exits_one_when_the_corpus_is_missing(tmp_path: Path) -> None:
    from pkt_core import encode_bytes

    pkt = tmp_path / "synthetic.pkt"
    pkt.write_bytes(encode_bytes(_PLAIN_XML, "pkt"))
    proc = _run_cli("--artifact", str(pkt), "--corpus", str(tmp_path / "nope"))
    assert proc.returncode == 1
    assert "not a directory" in proc.stderr


def test_cli_end_to_end_exit_code_reflects_suspicious_only(tmp_path: Path) -> None:
    """Non-zero exit must come from category (b) alone, never from ATTESTED lines."""
    from pkt_core import encode_bytes

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "donor.pkt").write_bytes(encode_bytes(_PLAIN_XML, "pkt"))
    pkt = tmp_path / "under-test.pkt"
    pkt.write_bytes(encode_bytes(_PLAIN_XML, "pkt"))

    out = tmp_path / "report.json"
    proc = _run_cli(
        "--artifact", str(pkt),
        "--corpus", str(corpus),
        "--cache", str(tmp_path / "cache.json"),
        "--json", str(out),
        "--quiet",
    )
    # The synthetic document contains only real IOS constructs, so every
    # signature is ATTESTED by the identical donor file: exit 0.
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["summary"]["unattested_suspicious"] == 0
    assert payload["summary"]["attested_signatures"] == \
        payload["summary"]["distinct_signatures"]
    assert payload["corpus"]["files_ok"] == 1
    assert payload["corpus"]["files_failed"] == 0


def test_cli_reports_suspicious_with_exit_two(tmp_path: Path) -> None:
    from pkt_core import encode_bytes

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "donor.pkt").write_bytes(encode_bytes(_PLAIN_XML, "pkt"))

    bad_xml = _PLAIN_XML.replace(
        b"<LINE>ip cef</LINE>", b"").replace(
        b"<LINE>hostname R1</LINE>", b"<LINE>hostname R1</LINE><LINE>ip routng 1.2.3.4</LINE>")
    pkt = tmp_path / "bad.pkt"
    pkt.write_bytes(encode_bytes(bad_xml, "pkt"))

    out = tmp_path / "report.json"
    proc = _run_cli(
        "--artifact", str(pkt), "--corpus", str(corpus),
        "--cache", str(tmp_path / "cache.json"),
        "--json", str(out), "--quiet",
    )
    assert proc.returncode == 2
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["summary"]["unattested_suspicious"] == 1
    bad = [r for r in payload["signatures"] if r["category"] == "suspicious"]
    assert bad[0]["body"] == "ip routng <ip>"


# =========================================================================== #
# 8. Raw-line scanning (the normalised body legitimately contains placeholders)
# =========================================================================== #


def test_placeholders_do_not_look_like_template_artefacts() -> None:
    """`<ip>`/`<text>` are this tool's own output, not a templating bug."""
    body = "radius-server host <ip> auth-port <n> acct-port <n> key <text>"
    assert audit.classify_unattested(body, raw=body).category == "standard"
    assert audit.classify_unattested(
        body, raw="radius-server host 10.0.0.1 auth-port 1 acct-port 2 key SECRET",
    ).category == "standard"


def test_real_template_artefact_is_still_caught() -> None:
    cls = audit.classify_unattested("hostname <HOSTNAME>", raw="hostname <HOSTNAME>")
    assert cls.category == "suspicious"
    assert cls.reason == "unresolved-html-placeholder"


def test_masked_repetition_is_not_a_duplicated_keyword() -> None:
    """`class class-default` and `... in interface outside` are both legal."""
    for raw in ("class class-default", "access-group OUTSIDE-IN in interface outside"):
        cls = audit.classify_unattested(
            audit.normalise_body(raw), raw=raw)
        assert cls.category == "standard", f"{raw!r} -> {cls}"


def test_ip_subkeywords_are_empirically_complete() -> None:
    """Every `ip <X>` second token the corpus attests must be accepted."""
    for tok in ("access-group", "access-list", "address", "arp", "authentication",
                "cef", "classless", "default-gateway", "default-network", "dhcp",
                "domain-name", "flow", "flow-export", "hello-interval",
                "helper-address", "host", "inspect", "local", "name-server",
                "nat", "ospf", "route", "routing", "source-address", "ssh",
                "summary-address", "unnumbered"):
        assert tok in audit.IP_SUBKEYWORDS, tok


# =========================================================================== #
# 9. Opt-in corpus test
# =========================================================================== #


@pytest.mark.corpus
@pytest.mark.skipif(
    not (CORPUS_INDEX.exists() and CORPUS_DIR.exists()),
    reason="corpus not fetched (see corpus/README.md)",
)
def test_corpus_builds_a_non_trivial_attestation_set() -> None:
    att = audit.build_attestation(CORPUS_DIR, index=CORPUS_INDEX, workers=4,
                                  progress=False)
    assert att.files_ok > 0
    # Every failure must be recorded explicitly, never swallowed.
    assert att.files_ok + att.files_failed >= 900
    assert len(att.signatures) > 1000, len(att.signatures)
    # The corpus must attest the most basic router configuration.
    assert att.attest("global|hostname <text>") > 100
    assert att.attest("interface|ip address <ip> <ip>") > 100
