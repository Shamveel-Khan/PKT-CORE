#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
audit_ios_commands.py -- attest every emitted IOS config line against the
reference corpus (docs/ENTERPRISE_PROBLEMS.md, problem 20).

The problem
-----------
Packet Tracer's IOS is a *subset* of real Cisco IOS.  A command can be
structurally present, byte-correct, load without error, and still be silently
dropped by PT's CLI parser.  A 22,000-line enterprise lab therefore makes
thousands of configuration claims that have never been checked against what PT
actually accepts.

What this tool does
-------------------
1. **Extract** every ``<LINE>`` of every ``<RUNNINGCONFIG>`` from a ``.pkt`` /
   ``.pka`` (via ``pkt_core``).
2. **Normalise** each raw line into a *command signature*: the volatile parts
   (hostnames, IPs, descriptions, secrets, sequence numbers, interface
   numbers, ACL/policy names) are replaced by placeholders, but the
   command verb / keyword chain and the configuration submode are kept.
3. **Attest**: decode the reference corpus, harvest every config line Packet
   Tracer itself has ever stored, and build the set of signatures PT has
   demonstrably round-tripped.  Corpus decoding is cached
   (``build/ios_attestation.json``, ``--refresh-cache`` to rebuild).
4. **Report** each distinct emitted signature with its emission count, the
   number of corpus files attesting it, and a verdict of ``ATTESTED`` /
   ``UNATTESTED``.

UNATTESTED is a *finding*, not automatically an error
-----------------------------------------------------
A standard CCNA/CCNP construct such as ``ip ospf network point-to-point`` may
legitimately never appear in 952 harvested labs.  UNATTESTED signatures are
therefore classified into:

* ``standard``   -- the command verb / keyword chain is recognisable from the
  curated standard-IOS vocabulary in :data:`STANDARD_IOS_VERBS` /
  :data:`STANDARD_IOS_PREFIXES`.
* ``suspicious`` -- structural red flags (template artefacts, non-ASCII or
  control bytes, placeholder braces, duplicated keywords, truncated commands)
  **or** a leading verb that is not part of the standard IOS vocabulary at all.

The process exits non-zero **only** when the suspicious category is non-empty.

Usage
-----
    python3 tools/audit_ios_commands.py \\
        --artifact /path/lab.pkt \\
        --corpus   corpus/files \\
        --json     build/ios_audit.json \\
        --markdown build/ios_audit.md

    # force a corpus re-decode (952 files; ~1-3 min)
    python3 tools/audit_ios_commands.py --artifact lab.pkt --refresh-cache

A failed corpus decode is **never** silently treated as an empty file: every
failure is recorded with its reason and reported in the summary and the JSON.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

# --------------------------------------------------------------------------- #
# import path: this tool lives in tools/ next to pt9.py and uses src/pkt_core
# --------------------------------------------------------------------------- #
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
for _p in (str(REPO / "src"), str(REPO), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pkt_core import decode  # noqa: E402
from pkt_core.xml import XmlElement, parse_xml_bytes  # noqa: E402

# The XML layer's element type; aliased so the annotations above stay readable.
XmlElementLike = XmlElement

__all__ = [
    "CACHE_SCHEMA",
    "Signature",
    "NormalisedLine",
    "SignatureExtractor",
    "classify_unattested",
    "extract_artifact_signatures",
    "build_attestation",
    "load_cache",
    "save_cache",
    "main",
]

CACHE_SCHEMA = "pkt-ios-attestation/1"

# =========================================================================== #
# 1. Token shapes
# =========================================================================== #
#
# A "shape" is a volatile token class.  Replacing these with placeholders is
# what collapses 22,827 emitted lines into a few hundred distinct signatures
# without destroying the command's identity.

# IOS interface abbreviations, most-specific first.  A token only counts as an
# interface when it is <prefix><digits/slashes/dots/colons> and nothing else,
# so a device called `Giants` or `Seoul-RTR` can never be mistaken for one.
_IF_TYPES = (
    "TwentyFiveGigE", "FortyGigabitEthernet", "HundredGigE", "TenGigabitEthernet",
    "GigabitEthernet", "FastEthernet", "Wlan-GigabitEthernet", "Port-channel",
    "Port-Channel", "Virtual-Template", "VirtualPortGroup", "Embedded-Service-Engine",
    "Group-Async", "Dot11Radio", "Multilink", "Tunnel", "Loopback", "Ethernet",
    "Serial", "Cellular", "Dialer", "Management", "Async", "Vlan", "BVI", "NVI",
    "Vif", "mgmt",
    # two-letter abbreviations used by `show run` and by hand-written configs
    "Gi", "Fa", "Et", "Se", "Vl", "Lo", "Tu", "Po", "Te", "Fo", "Tw", "Hu",
    "Vi", "As", "Ce", "Di", "Mu", "Nv", "Wl",
)
_IF_RE = re.compile(
    # `[\d/.:]+` (not `*`) so a bare `vlan` or `serial` keyword is never
    # mistaken for an interface name.
    r"^(?:" + "|".join(re.escape(t) for t in _IF_TYPES) + r")[\d/.:]+$",
    re.IGNORECASE,
)


def _is_ipv6(tok: str) -> bool:
    """Strict IPv6 test.

    A loose `[0-9a-f:]+` pattern also matches ASA timeout literals such as
    `1:00:00` and `0:30:00`, which is exactly the kind of silent
    over-normalisation this tool exists to avoid, so the real parser decides.
    """
    if ":" not in tok:
        return False
    candidate = tok
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True

# Material that is *always* volatile regardless of the command it belongs to.
_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # `<ip>` covers dotted quads with or without a prefix length.
    ("<ip>", re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")),
    ("<mac>", re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")),
    ("<mac>", re.compile(r"^[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}$")),
    # IOS type-5 (MD5) and type-7 secrets, and $9$ scrypt secrets.
    ("<secret>", re.compile(r"^\$\d\$\S*$")),
    ("<if>", _IF_RE),
    ("<email>", re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")),
    # ASA timeout literals: h:mm:ss.  Without this, every distinct
    # timeout value becomes its own signature.
    ("<time>", re.compile(r"^\d{1,3}:\d{2}:\d{2}$")),
    # tftp:/flash:/disk0: URLs (e.g. `archive` path statements).
    ("<url>", re.compile(r"^[a-z][a-z0-9+.\-]*://\S+$")),
    # a long hex blob that contains at least one letter (so plain 65001 stays <n>)
    ("<hash>", re.compile(r"^(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{12,}$")),
    ("<n>", re.compile(r"^\d+$")),
)

# After the text rules have run, a token that is *still* one of our own
# placeholders must not be re-masked.
_PLACEHOLDER_RE = re.compile(r"^<[a-z0-9_]+>$")


def shape_token(tok: str) -> str:
    """Return the volatile-class placeholder for *tok*, or *tok* unchanged."""
    if _PLACEHOLDER_RE.match(tok):
        return tok
    if _is_ipv6(tok):
        return "<ip6>"
    for placeholder, pattern in _SHAPES:
        if pattern.match(tok):
            return placeholder
    return tok


# =========================================================================== #
# 2. Free-text / name rules
# =========================================================================== #
#
# Shape masking alone cannot tell `hostname JADGE-BB-SW-01` from
# `spanning-tree mode rapid-pvst`, because both contain identifier-shaped
# tokens.  These rules are the curated IOS knowledge in this tool: each one
# names the exact keyword chain that introduces free text or an object name,
# and replaces only that tail.  Rules are applied to the **whole** lowercased
# line, first match wins, and are deliberately anchored so they cannot fire
# on an unrelated command that merely contains the same word.
#
# Every replacement keeps the leading keyword chain; only the variable tail
# becomes a placeholder.  `\\1`-style back references below preserve tokens
# that are themselves keywords (e.g. the `standard`/`extended` in
# `ip access-list`, the `md5` in `standby ... authentication md5`).

TEXT_RULES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), r)
    for p, r in (
        # ---- identity ---------------------------------------------------- #
        (r"^hostname\s+\S+$", "hostname <text>"),
        (r"^ip domain-name\s+\S+$", "ip domain-name <text>"),
        (r"^ip domain-lookup$", "ip domain-lookup"),
        (r"^boot\s+system\s+\S+$", "boot system <text>"),
        (r"^description\s+\S.*$", "description <text>"),
        (r"^name\s+\S+$", "name <text>"),
        (r"^nameif\s+\S+$", "nameif <text>"),
        (r"^switchport\s+port-security\s+mac-address\s+\S+$",
         "switchport port-security mac-address <text>"),
        # ---- credentials and keys ---------------------------------------- #
        # The numeric form (`enable secret 5 <hash>`) keeps its type digit;
        # the ASA form (`enable password <hash> encrypted`) does not have one.
        (r"^enable\s+(secret|password)\s+(\d)\s+(\S+)$", "enable \\1 \\2 <secret>"),
        (r"^enable\s+(secret|password)(?:\s+.*)?$", "enable \\1 <secret>"),
        (r"^passwd\s+\S+(?:\s+encrypted)?$", "passwd <secret> encrypted"),
        (r"^username\s+(\S+)\s+password\s+(\S+)(?:\s+(encrypted))?(?:\s+privilege\s+(\S+))?$",
         "username <text> password <secret> encrypted privilege <n>"),
        (r"^username\s+(\S+)(?:\s+(.*))?$", "username <text> \\2"),
        (r"^password(?:\s+(\S+))?(?:\s+(\S+))?$", "password \\1 <secret>"),
        (r"^secret(?:\s+(\S+))?(?:\s+(\S+))?$", "secret \\1 <secret>"),
        (r"^key-string(?:\s+\S+)?$", "key-string <text>"),
        (r"^key(?:\s+(\S+))?(?:\s+\S+)?$", "key \\1 <text>"),
        (r"^radius-server\s+host\s+(\S+)\s+auth-port\s+(\S+)\s+acct-port\s+(\S+)\s+key\s+(\S+)$",
         "radius-server host \\1 auth-port <n> acct-port <n> key <text>"),
        (r"^radius-server\s+key\s+(\S+)$", "radius-server key <text>"),
        (r"^ntp\s+authentication-key\s+(\S+)\s+(\S+)\s+(\S+)$",
         "ntp authentication-key \\1 md5 <text>"),
        (r"^crypto\s+isakmp\s+key\s+(\S+)\s+address\s+(\S+)$",
         "crypto isakmp key <text> address <ip>"),
        (r"^crypto\s+isakmp\s+key\s+(\S+)$", "crypto isakmp key <text>"),
        (r"^standby\s+(\S+)\s+authentication\s+(\S+)\s+(\S+)\s+(\S+)$",
         "standby \\1 authentication \\2 \\3 <text>"),
        (r"^standby\s+(\S+)\s+authentication\s+(\S+)$",
         "standby \\1 authentication \\2"),
        # ---- banners ------------------------------------------------------ #
        (r"^banner\s+(\S+)\s+.*$", "banner \\1 <text>"),
        # ---- SNMP --------------------------------------------------------- #
        (r"^snmp-server\s+location(?:\s+\S.*)?$", "snmp-server location <text>"),
        (r"^snmp-server\s+contact(?:\s+\S.*)?$", "snmp-server contact <text>"),
        # NB: the body is lowercased before the rules run, so `ro`/`rw` here.
        (r"^snmp-server\s+community\s+(\S+)(?:\s+(ro|rw))?$",
         "snmp-server community <text> \\2"),
        (r"^snmp-server\s+host\s+(\S+)\s+version\s+(\S+)\s+(\S+)$",
         "snmp-server host <ip> version \\2 <text>"),
        (r"^snmp-server\s+host\s+(\S+)\s+(\S+)\s+(\S+)$",
         "snmp-server host <ip> \\2 <text>"),
        # ---- routing protocols -------------------------------------------- #
        (r"^neighbor\s+(\S+)\s+description\s+\S.*$",
         "neighbor \\1 description <text>"),
        (r"^neighbor\s+(\S+)\s+password\s+(\S+)$", "neighbor \\1 password <text>"),
        (r"^bgp\s+router-id\s+(\S+)$", "bgp router-id <ip>"),
        # ---- ACLs, classes, policies, maps -------------------------------- #
        (r"^ip\s+access-list\s+(standard|extended)\s+\S+$",
         "ip access-list \\1 <text>"),
        # Keep the ACE body (it is the security-relevant part) and mask only
        # the ACL identifier, which is a lab-chosen name in every real lab.
        (r"^access-list\s+(\S+)\s+(permit|deny|remark|dynamic|evaluate|extended|standard)\s+(.*)$",
         "access-list <name> \\2 \\3"),
        (r"^remark\s+\S.*$", "remark <text>"),
        (r"^object-group\s+(\S+)\s+(\S+)$", "object-group \\1 <text>"),
        (r"^object-group\s+(\S+)\s+(\S+)\s+(\S+)$", "object-group \\1 \\2 <text>"),
        (r"^class-map\s+(\S+)\s+(\S+)$", "class-map \\1 <text>"),
        (r"^class-map\s+(\S+)$", "class-map <text>"),
        (r"^policy-map\s+\S+$", "policy-map <text>"),
        (r"^class\s+class-default$", "class class-default"),
        (r"^class\s+\S+$", "class <text>"),
        (r"^match\s+access-group\s+name\s+\S+$", "match access-group name <text>"),
        (r"^service-policy\s+(input|output)\s+\S+$", "service-policy \\1 <text>"),
        (r"^service-policy\s+(\S+)\s+(\S+)$", "service-policy <text> \\2"),
        (r"^route-map\s+(\S+)(?:\s+(permit|deny))?(?:\s+(\S+))?$",
         "route-map <text> \\2 \\3"),
        (r"^ip\s+prefix-list\s+(\S+)\s+(\S+)\s+(\S+)$",
         "ip prefix-list <text> \\2 \\3"),
        # ---- switching / VLANs -------------------------------------------- #
        (r"^switchport\s+trunk\s+allowed\s+vlan\s+\S+$",
         "switchport trunk allowed vlan <text>"),
        (r"^switchport\s+trunk\s+native\s+vlan\s+\S+$",
         "switchport trunk native vlan <n>"),
        (r"^vtp\s+domain\s+\S+$", "vtp domain <text>"),
        (r"^ip\s+dhcp\s+pool\s+\S+$", "ip dhcp pool <text>"),
        (r"^ip\s+dhcp\s+excluded-address\s+\S+\s+\S+$",
         "ip dhcp excluded-address <ip> <ip>"),
        # ---- crypto / IPsec / NAT (ASA and IOS) ---------------------------- #
        (r"^crypto\s+ipsec\s+transform-set\s+\S+\s+(.*)$",
         "crypto ipsec transform-set <text> \\1"),
        (r"^crypto\s+ipsec\s+ikev1\s+transform-set\s+\S+\s+(.*)$",
         "crypto ipsec ikev1 transform-set <text> \\1"),
        (r"^crypto\s+map\s+\S+\s+(\S+)\s+match\s+address\s+\S+$",
         "crypto map <text> <n> match address <name>"),
        (r"^crypto\s+map\s+\S+\s+(\S+)\s+set\s+peer\s+(\S+)$",
         "crypto map <text> <n> set peer <ip>"),
        (r"^crypto\s+map\s+\S+\s+(\S+)\s+set\s+(\S+)\s+(\S+)\s+(\S+)$",
         "crypto map <text> <n> set \\2 \\3 <text>"),
        (r"^crypto\s+map\s+\S+\s+interface\s+\S+$",
         "crypto map <text> interface <text>"),
        (r"^crypto\s+dynamic-map\s+\S+\s+(\S+)$", "crypto dynamic-map <text> <n>"),
        (r"^nat\s+\(([^)]*)\)\s+(\S+)\s+(\S+)$", "nat (\\1) \\2 \\3"),
        (r"^object\s+network\s+\S+$", "object network <text>"),
        # ---- AAA / lines --------------------------------------------------- #
        (r"^aaa\s+authentication\s+(\S+)\s+(\S+)(?:\s+(.*))?$",
         "aaa authentication \\1 \\2 \\3"),
        (r"^line\s+(con|vty|aux|tty)\s+(.*)$", "line \\1 <n> <n>"),
        (r"^access-class\s+(\S+)\s+(in|out)$", "access-class <name> \\2"),
        # ---- misc named objects -------------------------------------------- #
        (r"^logging\s+host\s+(\S+)\s+(\S+)$", "logging host \\1 <ip>"),
        (r"^alias\s+(\S+)\s+(\S+)$", "alias \\1 <text>"),
        (r"^event-manager\s+(\S+)\s+(\S+)\s+(\S+)$", "event-manager \\1 \\2 <text>"),
    )
)

# =========================================================================== #
# 3. Submodes
# =========================================================================== #
#
# IOS stores sub-mode commands indented under their opener.  The submode is
# part of a command's identity (`ip address` is only legal under `interface`,
# `network` means different things under `router ospf` and `ip dhcp pool`), so
# it is carried in the signature.  The rule below is deliberately conservative:
# anything not recognised becomes `submode` rather than a wrong guess.

MODE_OPENERS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), label)
    for p, label in (
        (r"^interface\s+\S+$", "interface"),
        (r"^router\s+ospf\s+\S+$", "router-ospf"),
        (r"^router\s+ospfv3\s+\S+$", "router-ospfv3"),
        (r"^router\s+bgp\s+\S+$", "router-bgp"),
        (r"^router\s+eigrp\s+\S+$", "router-eigrp"),
        (r"^router\s+rip$", "router-rip"),
        (r"^router\s+isis.*$", "router-isis"),
        (r"^line\s+\S+.*$", "line"),
        (r"^vlan\s+\S+$", "vlan"),
        (r"^vlan\s+configuration$", "vlan-configuration"),
        (r"^ip\s+access-list\s+(standard|extended)\s+\S+$", "ip-access-list"),
        (r"^ip\s+dhcp\s+pool\s+\S+$", "ip-dhcp-pool"),
        (r"^class-map\s+\S+.*$", "class-map"),
        (r"^policy-map\s+\S+$", "policy-map"),
        (r"^route-map\s+\S+.*$", "route-map"),
        (r"^crypto\s+ikev1\s+policy\s+\S+$", "crypto-ikev1-policy"),
        (r"^crypto\s+isakmp\s+policy\s+\S+$", "crypto-isakmp-policy"),
        (r"^crypto\s+ipsec\s+profile\s+\S+$", "crypto-ipsec-profile"),
        (r"^crypto\s+pki\s+trustpoint\s+\S+$", "crypto-pki-trustpoint"),
        (r"^object-group\s+\S+.*$", "object-group"),
        (r"^object\s+network\s+\S+$", "object-network"),
        (r"^key\s+chain\s+\S+$", "key-chain"),
        (r"^key\s+\S+$", "key"),
        (r"^controller\s+\S+.*$", "controller"),
        (r"^ip\s+sla\s+\S+$", "ip-sla"),
        (r"^archive$", "archive"),
        (r"^log\s+config$", "archive-log-config"),
        (r"^telephony-service$", "telephony-service"),
        (r"^ephone-dn\s+\S+$", "ephone-dn"),
        (r"^ephone\s+\S+$", "ephone"),
        (r"^sip-ua$", "sip-ua"),
        (r"^voice\s+register$", "voice-register"),
        (r"^voice\s+card\s+\S+$", "voice-card"),
        (r"^dial-peer\s+\S+\s+\S+.*$", "dial-peer"),
        (r"^call-manager-fallback$", "call-manager-fallback"),
        (r"^mgcp$", "mgcp"),
        (r"^sccp\s+\S+$", "sccp"),
        (r"^line\s+con\s+\S+.*$", "line"),
        (r"^bba-group\s+\S+$", "bba-group"),
        (r"^parameter-map\s+\S+$", "parameter-map"),
        (r"^template\s+\S+.*$", "template"),
        (r"^flow\s+exporter\s+\S+$", "flow-exporter"),
        (r"^ip\s+nat\s+pool\s+\S+.*$", "ip-nat-pool"),
    )
)

# Lines that carry no configuration and are never audited.
_IGNORED_BODY = frozenset({"", "!", "end", "exit", "quit"})
_COMMENT_PREFIXES = ("!", "#", "//", ":", "...")
# Non-configuration trailer lines that some PT releases store verbatim.
_IGNORED_PREFIXES = ("cryptochecksum",)


# =========================================================================== #
# 4. Normalisation
# =========================================================================== #


@dataclass(frozen=True, slots=True)
class NormalisedLine:
    """One raw config line reduced to its identity."""

    mode: str
    body: str          # masked, lowercased keyword chain
    raw: str           # the original line, stripped
    kind: str          # "command" | "ignored" | "banner-body"

    @property
    def key(self) -> str:
        return f"{self.mode}|{self.body}"

    @property
    def body_key(self) -> str:
        return self.body


# A prompt prefix such as `R1(config-if)#` or `Switch>` sometimes survives into
# stored config text (older PT releases, hand-pasted configs).
_PROMPT_RE = re.compile(r"^\s*[A-Za-z0-9_.:+-]+(?:\([^)]*\))?\s*[#>]\s*(?=\S)")


def _strip_prompt(line: str) -> str:
    return _PROMPT_RE.sub("", line, count=1)


def _clean(raw: str) -> str:
    """Strip a raw line of transport noise but not of its meaning."""
    s = raw.replace("\r", "").replace("\n", "")
    # PT stores the IOS `banner motd ^C...^C` delimiter as a raw 0x03 (it is
    # illegal XML 1.0, see ENTERPRISE_PROBLEMS.md problem 29).  It is a
    # delimiter, not content, so it is kept as its own standalone token; every
    # other C0 control byte becomes a separator.
    out = []
    for ch in s:
        if ch == "\x03":
            out.append(" \x03 ")
        elif ord(ch) < 0x20 and ch != "\t":
            out.append(" ")
        else:
            out.append(ch)
    s = "".join(out)
    s = _strip_prompt(s)
    return s.rstrip()


def apply_text_rules(body: str) -> str:
    """Apply :data:`TEXT_RULES` to a lowercased command body."""
    for pattern, replacement in TEXT_RULES:
        if pattern.match(body):
            return pattern.sub(replacement, body, count=1)
    return body


def shape_body(body: str) -> str:
    """Replace every volatile token in *body* with its shape placeholder."""
    return " ".join(shape_token(tok) for tok in body.split())


def normalise_body(raw: str) -> str:
    """Full normalisation of a single command line body.

    ``raw`` may keep its indentation or not; leading whitespace is ignored.
    The result is lowercase, whitespace-collapsed, and free of volatile parts.
    """
    s = _clean(raw).strip().lower()
    if not s:
        return ""
    s = apply_text_rules(s)
    s = shape_body(s)
    return " ".join(s.split())


def detect_mode(body: str) -> str | None:
    """Return the submode label if *body* opens one, else ``None``."""
    for pattern, label in MODE_OPENERS:
        if pattern.match(body):
            return label
    return None


class SignatureExtractor:
    """Stateful line-by-line reducer: raw config lines -> signatures.

    Two pieces of state are required and both are why this is a class rather
    than a function:

    * the **indentation stack**, which recovers the submode each indented line
      belongs to (IOS running-config is indentation-based, and PT stores it
      exactly that way, verified against the corpus);
    * the **banner state**, because ``banner motd #`` is followed by unbounded
      free-text lines terminated by a second ``#``.

    Feed lines with :meth:`feed`; each call yields one :class:`NormalisedLine`.
    """

    __slots__ = ("_stack", "_banner_delim", "_banner_type", "_banner_lines")

    def __init__(self) -> None:
        # (indent, mode) pairs, outermost first
        self._stack: list[tuple[int, str]] = []
        self._banner_delim: str | None = None
        self._banner_type: str | None = None
        self._banner_lines: int = 0

    # -- banner --------------------------------------------------------- #
    @property
    def in_banner(self) -> bool:
        return self._banner_delim is not None

    @property
    def banner_body_lines(self) -> int:
        return self._banner_lines

    def _banner_start(self, cleaned: str) -> NormalisedLine:
        """Consume the first line of a banner and arm the terminator state.

        The delimiter is the **first character** of everything after the banner
        type, so `banner motd #Text#` is a complete one-line banner while
        `banner motd #` opens a multi-line one.
        """
        toks = cleaned.split(None, 2)
        btype = toks[1].lower() if len(toks) > 1 else "?"
        line = NormalisedLine("global", f"banner {btype} <text>", cleaned, "command")
        if len(toks) < 3 or not toks[2]:
            # `banner motd` on its own: the delimiter is on the next line.
            self._banner_delim = "\x00"
            self._banner_type = btype
            return line
        remainder = toks[2]
        delim = remainder[0]
        after = remainder[1:]
        if after.endswith(delim):
            # opened and closed on the same line
            self._banner_delim = None
            self._banner_type = None
            return line
        self._banner_delim = delim
        self._banner_type = btype
        return line

    # -- main ----------------------------------------------------------- #
    def feed(self, raw: str) -> NormalisedLine:
        # --- inside a banner body: consume until the terminator ----------
        if self._banner_delim is not None:
            if self._banner_delim == "\x00":
                # the whole body is the delimiter line itself; treat as one-line
                self._banner_delim = None
                self._banner_type = None
                return NormalisedLine("global", "", raw.strip(), "ignored")
            stripped = _clean(raw).strip()
            if stripped.endswith(self._banner_delim):
                self._banner_delim = None
                self._banner_type = None
            self._banner_lines += 1
            return NormalisedLine("global", "", raw.strip(), "banner-body")

        cleaned = _clean(raw)
        body = cleaned.strip()

        if not body or body.lower() in _IGNORED_BODY:
            return NormalisedLine("global", "", body, "ignored")
        if body.startswith(_COMMENT_PREFIXES):
            return NormalisedLine("global", "", body, "ignored")
        if body.lower().startswith(_IGNORED_PREFIXES):
            return NormalisedLine("global", "", body, "ignored")

        indent = len(cleaned) - len(cleaned.lstrip(" \t"))

        lower = body.lower()
        if lower.startswith("banner") and len(lower.split()) >= 2:
            line = self._banner_start(cleaned)
            self._push_if_opener(indent, normalise_body(body))
            return line

        norm = normalise_body(body)

        # Pop submodes that this line's indentation has left.
        while self._stack and self._stack[-1][0] >= indent:
            self._stack.pop()
        mode = self._stack[-1][1] if self._stack else "global"

        # An opener at this indentation becomes the mode for its children.
        opener = detect_mode(norm)
        if opener is not None:
            mode = "global" if indent == 0 else mode
            self._stack.append((indent, opener))
            return NormalisedLine(opener, norm, body, "command")

        return NormalisedLine(mode, norm, body, "command")

    def _push_if_opener(self, indent: int, norm: str) -> None:
        while self._stack and self._stack[-1][0] >= indent:
            self._stack.pop()
        opener = detect_mode(norm)
        if opener is not None:
            self._stack.append((indent, opener))

    def feed_all(self, lines: Iterable[str]) -> Iterator[NormalisedLine]:
        for raw in lines:
            yield self.feed(raw)


def normalise_lines(lines: Iterable[str]) -> list[NormalisedLine]:
    """Convenience wrapper: normalise a whole config with one extractor."""
    return list(SignatureExtractor().feed_all(lines))


# =========================================================================== #
# 5. Extraction from an artefact
# =========================================================================== #


@dataclass
class Signature:
    """One distinct emitted command signature, merged across artefacts."""

    key: str
    mode: str
    body: str
    count: int = 0
    device_total: int = 0
    devices: set[str] = field(default_factory=set)
    artifacts: set[str] = field(default_factory=set)
    example: str = ""
    corpus_files: int = 0
    corpus_files_body_only: int = 0

    @property
    def attested(self) -> bool:
        return self.corpus_files > 0

    def as_dict(self, verdict: str, category: str | None, reason: str) -> dict[str, Any]:
        return {
            "signature": self.key,
            "mode": self.mode,
            "body": self.body,
            "emitted": self.count,
            "devices": self.device_total,
            "artifacts": sorted(self.artifacts),
            "corpus_files": self.corpus_files,
            "corpus_files_body_only": self.corpus_files_body_only,
            "verdict": verdict,
            "category": category,
            "reason": reason,
            "example": self.example,
        }


def _find_all_deep(el: "XmlElementLike", name: str, max_depth: int = 6) -> list["XmlElementLike"]:
    """Every descendant-or-self element with this tag, breadth-first.

    Packet Tracer nests the device list differently between the plain
    ``PACKETTRACER5`` skeleton (``PACKETTRACER5`` -> ``NETWORK`` -> ``DEVICES``)
    and the scored ``PACKETTRACER5_ACTIVITY`` skeleton (one extra level), so the
    walk is depth-bounded rather than path-hardcoded.
    """
    out: list[XmlElementLike] = []
    level = [el]
    for _ in range(max_depth):
        nxt: list[XmlElementLike] = []
        for node in level:
            for child in node.children:
                if not isinstance(child, XmlElement):
                    continue
                if child.tag == name:
                    out.append(child)
                else:
                    nxt.append(child)
        if out:
            return out
        level = nxt
        if not level:
            break
    return out


def _iter_running_configs(xml: bytes) -> Iterator[tuple[str, list[str]]]:
    """Yield ``(device_name, config_lines)`` for every ``RUNNINGCONFIG`` block.

    Uses the byte-level parser rather than the pydantic model layer: this tool
    walks thousands of corpus documents, and the model layer's per-element
    object construction dominates the runtime at that scale.
    """
    doc = parse_xml_bytes(xml)
    root = doc.root
    if root is None:  # pragma: no cover - defensive
        return
    containers = _find_all_deep(root, "DEVICES")
    devices: list[XmlElementLike] = []
    for node in containers:
        devices.extend(node.find_all("DEVICE"))
    if not devices:  # defensive: a document without <DEVICES>
        devices = _find_all_deep(root, "DEVICE", max_depth=8)
    for device in devices:
        engine = device.find("ENGINE")
        if engine is None:
            continue
        name_node = engine.find("NAME")
        name = name_node.text.strip() if name_node is not None else "?"
        for rc in engine.find_all("RUNNINGCONFIG"):
            yield (name or "?", [line.text for line in rc.find_all("LINE")])


@dataclass
class ArtifactReport:
    path: str
    sha256: str
    devices: int
    blocks: int
    lines: int
    banner_lines: int
    ignored_lines: int
    signatures: dict[str, Signature]
    errors: list[str] = field(default_factory=list)


def extract_artifact_signatures(path: str | os.PathLike[str]) -> ArtifactReport:
    """Extract and normalise every emitted IOS config line from one artefact."""
    p = Path(path)
    raw = p.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    container = decode(str(p))
    sigs: dict[str, Signature] = {}
    devices = 0
    blocks = 0
    total = 0
    banner = 0
    ignored = 0
    errors: list[str] = []

    for name, lines in _iter_running_configs(container.xml):
        devices += 1
        blocks += 1
        ex = SignatureExtractor()
        for norm in ex.feed_all(lines):
            total += 1
            if norm.kind == "banner-body":
                banner += 1
                continue
            if norm.kind == "ignored" or not norm.body:
                ignored += 1
                continue
            sig = sigs.get(norm.key)
            if sig is None:
                sig = Signature(key=norm.key, mode=norm.mode, body=norm.body,
                                example=norm.raw)
                sigs[norm.key] = sig
            sig.count += 1
            sig.devices.add(name)
        banner += ex.banner_body_lines

    return ArtifactReport(
        path=str(p),
        sha256=digest,
        devices=devices,
        blocks=blocks,
        lines=total,
        banner_lines=banner,
        ignored_lines=ignored,
        signatures=sigs,
        errors=errors,
    )


# =========================================================================== #
# 6. Corpus attestation
# =========================================================================== #


# The corpus harvester disambiguates duplicate basenames by appending
# ``__<number>``, so the *extension* of those files is no longer ``.pkt``.
# Prefix-matching globs catch them; `CORPUS_INDEX.tsv` catches everything.
_CORPUS_GLOBS = ("*.pkt", "*.pka", "*.PKT", "*.PKA",
                 "*.pkt__*", "*.pka__*", "*.PKT__*", "*.PKA__*")


def iter_corpus_files(corpus_dir: Path, index: Path | None) -> list[Path]:
    """Resolve the list of Packet Tracer containers to decode.

    ``corpus_dir`` may be the corpus root (containing ``files/``) or the
    directory that directly holds the containers.  When the manifest is
    available its ``filename`` column is authoritative; otherwise the directory
    is globbed.
    """
    roots = []
    if (corpus_dir / "files").is_dir():
        roots.append(corpus_dir / "files")
    roots.append(corpus_dir)

    if index is not None and index.is_file():
        import csv

        names: list[str] = []
        with index.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh, delimiter="\t"):
                name = (row.get("filename") or "").strip()
                if name and not name.lower().endswith(".zip"):
                    names.append(name)
        for root in roots:
            got = [root / n for n in names if (root / n).is_file()]
            if got:
                return sorted(got, key=lambda f: f.name)

    seen: dict[str, Path] = {}
    for root in roots:
        for pattern in _CORPUS_GLOBS:
            for f in sorted(root.glob(pattern)):
                if f.is_file():
                    seen.setdefault(f.name, f)
        if seen:
            break
    return [seen[k] for k in sorted(seen)]


@dataclass
class DecodeResult:
    name: str
    ok: bool
    error: str = ""
    signatures: list[str] = field(default_factory=list)
    bodies: list[str] = field(default_factory=list)
    lines: int = 0

    def as_cache(self) -> dict[str, Any]:
        if not self.ok:
            return {"status": "failed", "error": self.error}
        return {"status": "ok", "lines": self.lines, "signatures": self.signatures,
                "bodies": self.bodies}


def decode_one(path_str: str) -> DecodeResult:
    """Decode one corpus container and return its distinct signatures.

    A failure is *always* returned as an explicit ``ok=False`` record with the
    exception type and message; it is never collapsed into "no signatures".
    """
    name = os.path.basename(path_str)
    try:
        container = decode(path_str)
    except Exception as exc:  # noqa: BLE001 - any decoder failure is data
        return DecodeResult(name=name, ok=False,
                            error=f"{type(exc).__name__}: {exc}")
    try:
        sigs: set[str] = set()
        bodies: set[str] = set()
        total = 0
        for _dev, lines in _iter_running_configs(container.xml):
            ex = SignatureExtractor()
            for norm in ex.feed_all(lines):
                total += 1
                if norm.kind != "command" or not norm.body:
                    continue
                sigs.add(norm.key)
                bodies.add(norm.body)
        return DecodeResult(name=name, ok=True, signatures=sorted(sigs),
                            bodies=sorted(bodies), lines=total)
    except Exception as exc:  # noqa: BLE001
        return DecodeResult(name=name, ok=False,
                            error=f"harvest {type(exc).__name__}: {exc}")


@dataclass
class Attestation:
    """The corpus-derived attestation set."""

    signatures: dict[str, int] = field(default_factory=dict)   # key -> file count
    bodies: dict[str, int] = field(default_factory=dict)       # body -> file count
    files_ok: int = 0
    files_failed: int = 0
    failures: dict[str, str] = field(default_factory=dict)
    corpus_dir: str = ""
    fingerprint: str = ""
    generated: str = ""
    cache_hit: bool = False
    elapsed_s: float = 0.0

    def attest(self, key: str) -> int:
        return self.signatures.get(key, 0)

    def attest_body(self, body: str) -> int:
        return self.bodies.get(body, 0)


def _corpus_fingerprint(files: Sequence[Path], index: Path | None) -> str:
    h = hashlib.sha256()
    if index is not None and index.is_file():
        h.update(b"index:")
        h.update(hashlib.sha256(index.read_bytes()).digest())
    h.update(f"n={len(files)}".encode())
    for f in files:
        st = f.stat()
        h.update(f"{f.name}\0{st.st_size}\0{int(st.st_mtime)}\n".encode())
    return h.hexdigest()


def build_attestation(
    corpus_dir: Path,
    *,
    index: Path | None = None,
    workers: int = 0,
    progress: bool = True,
) -> Attestation:
    """Decode the whole corpus and build the attestation set."""
    files = iter_corpus_files(corpus_dir, index)
    if not files:
        raise FileNotFoundError(
            f"no .pkt/.pka files found under {corpus_dir!s} "
            f"(looked for a 'files/' subdirectory and the directory itself)"
        )
    fingerprint = _corpus_fingerprint(files, index)
    if workers <= 0:
        workers = min(8, max(1, (os.cpu_count() or 2)))
    started = time.time()

    sig_counts: Counter[str] = Counter()
    body_counts: Counter[str] = Counter()
    failures: dict[str, str] = {}
    ok = 0

    def _absorb(res: DecodeResult) -> None:
        nonlocal ok
        if not res.ok:
            failures[res.name] = res.error
            return
        ok += 1
        sig_counts.update(set(res.signatures))
        body_counts.update(set(res.bodies))

    if workers == 1:
        for i, f in enumerate(files, 1):
            _absorb(decode_one(str(f)))
            if progress and i % 100 == 0:
                print(f"  ... {i}/{len(files)} corpus files", file=sys.stderr)
    else:
        ctx = None
        try:
            import multiprocessing as mp

            ctx = mp.get_context("fork")
        except (ImportError, ValueError):  # pragma: no cover
            ctx = None
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=workers, mp_context=ctx
        ) as pool:
            for i, res in enumerate(pool.map(decode_one, [str(f) for f in files],
                                             chunksize=8), 1):
                _absorb(res)
                if progress and i % 100 == 0:
                    print(f"  ... {i}/{len(files)} corpus files", file=sys.stderr)

    return Attestation(
        signatures=dict(sig_counts),
        bodies=dict(body_counts),
        files_ok=ok,
        files_failed=len(failures),
        failures=failures,
        corpus_dir=str(corpus_dir),
        fingerprint=fingerprint,
        generated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        elapsed_s=round(time.time() - started, 2),
    )


def load_cache(path: Path) -> Attestation | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if data.get("schema") != CACHE_SCHEMA:
        return None
    att = Attestation(
        signatures={k: int(v) for k, v in data.get("signatures", {}).items()},
        bodies={k: int(v) for k, v in data.get("bodies", {}).items()},
        files_ok=int(data.get("files_ok", 0)),
        files_failed=int(data.get("files_failed", 0)),
        failures=dict(data.get("failures", {})),
        corpus_dir=str(data.get("corpus_dir", "")),
        fingerprint=str(data.get("fingerprint", "")),
        generated=str(data.get("generated", "")),
        elapsed_s=float(data.get("elapsed_s", 0.0)),
        cache_hit=True,
    )
    return att


def save_cache(att: Attestation, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": CACHE_SCHEMA,
        "generated": att.generated,
        "corpus_dir": att.corpus_dir,
        "fingerprint": att.fingerprint,
        "files_ok": att.files_ok,
        "files_failed": att.files_failed,
        "failures": att.failures,
        "elapsed_s": att.elapsed_s,
        "signatures": att.signatures,
        "bodies": att.bodies,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(path)


# =========================================================================== #
# 7. Classification of UNATTESTED signatures
# =========================================================================== #
#
# Curated standard Cisco IOS vocabulary.  This is the CCNA -> CCNP -> PT
# surface: if a command's leading verb is in here, the construct is a normal
# IOS construct that PT *may* simply not have needed before.  If it is not,
# the line is not recognisable as IOS at all and is reported as suspicious.

STANDARD_IOS_VERBS: frozenset[str] = frozenset({
    # global / housekeeping
    "aaa", "alias", "archive", "banner", "boot", "cdp", "clock", "config",
    "crypto", "enable", "end", "event-manager", "file", "hostname", "lldp",
    "logging", "memory", "no", "ntp", "parser", "privilege", "scheduler",
    "service", "snmp-server", "username", "version", "vtp", "license",
    "line", "exit", "do", "show", "debug", "undebug", "copy", "write",
    # L2
    "spanning-tree", "switchport", "channel-group", "channel-protocol",
    "mac", "mac-address-table", "storm-control", "udld", "pagp", "lacp",
    "vlan", "interface", "port-channel", "etherchannel", "mtu", "duplex",
    "speed", "shutdown", "description", "name", "switchport-mode",
    "dot1x", "authentication", "mab", "port-security", "vmps",
    # L3 / addressing
    "ip", "ipv6", "ipv4", "arp", "dhcp", "bootp", "helper-address",
    "standby", "hsrp", "vrrp", "glbp", "track", "sla", "object",
    "encapsulation", "frame-relay", "ppp", "hdlc", "atm", "x25",
    "dialer", "isdn", "async", "modem", "chat-script", "script",
    # routing
    "router", "network", "neighbor", "redistribute", "passive-interface",
    "default-information", "auto-cost", "log-adjacency-changes", "area",
    "summary-address", "distribute-list", "offset-list", "distance",
    "maximum-paths", "timers", "variance", "bgp", "address-family",
    "route-map", "match", "set", "continue", "ipv6-router",
    "ipv6-router-ospf", "ipv6-router-eigrp", "ipv6-router-rip",
    "ipv6-router-bgp", "deny", "permit", "access-list", "access-class",
    "prefix-list", "community-list", "as-path", "distribute",
    "ip-route", "key", "key-string", "key-chain", "send-lifetime",
    "accept-lifetime", "eigrp", "ospf", "rip", "bgp-router-id", "bgp-log",
    # QoS / policy
    "class-map", "policy-map", "class", "priority", "bandwidth", "police",
    "shape", "random-detect", "fair-queue", "queue-limit", "service-policy",
    "inspect", "inspection", "set-dscp", "wrr-queue", "mls", "srr-queue",
    "auto-qos", "priority-queue", "hold-queue", "tx-ring-limit",
    # security / VPN
    "isakmp", "ikev1", "ikev2", "transform-set", "map", "dynamic-map",
    "pki", "trustpoint", "certificate", "rsakeypair", "hash", "group",
    "lifetime", "nat", "nameif", "security-level", "object-group",
    "subnet", "allocation", "aaa-server", "radius", "tacacs-server",
    "dot1x-pae", "macros", "webvpn", "tunnel-group", "tunnel",
    "zone", "zone-pair", "class-class-default", "inspect-ftp",
    # physical / controller / voice / wireless
    "controller", "telephony-service", "ephone", "ephone-dn", "dial-peer",
    "voice", "sip-ua", "voice-port", "call-manager-fallback", "mgcp",
    "sccp", "wlan", "dot11", "wireless", "ssid", "radius-server",
    "antenna", "channel", "station-role", "wpa", "wep", "encryption",
    "authentication-open", "guest-mode", "infrastructure", "bridge",
    # misc hardware / services
    "ias", "sge", "boot-start-marker", "boot-end-marker", "diagnostic",
    "environment", "exception", "fabric", "hw-module", "platform",
    "proxy-server", "redundancy", "stack-mac", "transceiver", "udld-enable",
    "vmware", "xconnect", "appliance", "scada", "iot", "mcu",
    # ASA / older-platform verbs seen in the enterprise artefact's firewall tier
    "ssh", "telnet", "http", "https", "prompt", "passwd", "access-group",
    "route", "timeout", "pager", "ftp", "names", "same-security-traffic",
    "icmp", "asdm", "failover", "call-home", "dhcpd", "ssl", "webvpn",
    "management-access", "threat-detection", "user-identity", "smtp",
    "tls-proxy", "auth-prompt", "banner-exec", "terminal", "whois",
    "logging-rate-limit", "console", "class-default",
})

# `ip` and `ipv6` are too broad to certify on their own: `ip` alone would make
# the misspelling `ip routng ...` "standard".  These sets are the union of
# (a) every second token attested in the reference corpus, (b) every second
# token the enterprise artefact emits, and (c) the rest of the documented IOS
# `ip`/`ipv6` command surface -- so a token that is in neither is a genuine
# finding rather than a vocabulary gap.
IP_SUBKEYWORDS: frozenset[str] = frozenset({
    "access-group", "access-list", "accounting", "address", "admission",
    "arp", "as-path", "audit", "authentication", "bandwidth", "banner",
    "bgp", "bootp", "boot-server", "cef", "classless", "community-list",
    "default-gateway", "default-network", "device", "dhcp", "dns",
    "domain-lookup", "domain-name", "domain", "eigrp", "extcommunity-list",
    "finger", "flow", "flow-aggregation", "flow-export", "flow-top-talkers",
    "forward-protocol", "ftp", "gratuitous-arps", "hello-interval",
    "helper-address", "host", "hosts", "http", "icmp", "identd", "igmp",
    "inspect", "kerberos", "load-sharing", "local", "logging", "mroute",
    "msdp", "multicast", "multicast-routing", "name-server", "nat", "nbar",
    "ospf", "pim", "policy", "port-map", "prefix-list", "probe", "protocol",
    "proxy-arp", "radius", "redirects", "reflexive-list", "rip", "route",
    "routing", "rsvp", "rtp", "sap", "scope", "scp", "sctp", "sla", "snmp",
    "source-address", "source-route", "source", "split-horizon", "ssh",
    "summary-address", "tacacs", "tcp", "telnet", "tftp", "trace",
    "unicast-routing", "unnumbered", "unreachables", "vrf", "wccp",
})

IPV6_SUBKEYWORDS: frozenset[str] = frozenset({
    "access-class", "access-list", "address", "authentication", "cef",
    "dhcp", "eigrp", "enable", "general-prefix", "host", "local", "mld",
    "mtu", "nd", "neighbor", "ospf", "pim", "prefix-list", "rip", "route",
    "router", "source-route", "summary-address", "traffic-filter",
    "unicast-routing", "unnumbered",
})

# Multi-token prefixes that are unambiguous as a whole but whose first token
# alone is too generic to certify.
STANDARD_IOS_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("ip", "ospf", "network"),
    ("ip", "ospf", "cost"),
    ("ip", "ospf", "priority"),
    ("ip", "ospf", "hello-interval"),
    ("ip", "ospf", "dead-interval"),
    ("ip", "ospf", "authentication"),
    ("ip", "ospf", "message-digest-key"),
    ("ip", "ospf", "mtu-ignore"),
    ("ip", "ospf", "database-filter"),
    ("ip", "ospf", "retransmit-interval"),
    ("ip", "ospf", "transmit-delay"),
    ("ip", "helper-address"),
    ("ip", "route"),
    ("ip", "default-gateway"),
    ("ip", "classless"),
    ("ip", "domain-lookup"),
    ("ip", "domain-name"),
    ("ip", "name-server"),
    ("ip", "host"),
    ("ip", "http"),
    ("ip", "ssh"),
    ("ip", "telnet"),
    ("ip", "cef"),
    ("ip", "routing"),
    ("ip", "vrf"),
    ("ip", "sla"),
    ("ip", "access-list"),
    ("ip", "prefix-list"),
    ("ip", "nat"),
    ("ip", "dhcp"),
    ("ip", "flow-export"),
    ("ip", "inspect"),
    ("ip", "audit"),
    ("ip", "tcp"),
    ("ip", "icmp"),
    ("ip", "sctp"),
    ("ip", "accounting"),
    ("ip", "arp"),
    ("ip", "probe"),
    ("ip", "local"),
    ("ip", "address"),
    ("ip", "unnumbered"),
    ("ip", "pim"),
    ("ip", "igmp"),
    ("ip", "multicast"),
    ("ip", "policy"),
    ("ip", "admission"),
    ("ip", "banner"),
    ("ip", "device"),
    ("ip", "source"),
    ("ip", "split-horizon"),
    ("ip", "summary-address"),
    ("ip", "bandwidth"),
    ("ip", "load-sharing"),
    ("ip", "mroute"),
    ("ip", "hosts"),
    ("ip", "bootp"),
    ("ip", "boot-server"),
    ("ip", "gratuitous-arps"),
    ("ip", "redirects"),
    ("ip", "unreachables"),
    ("ip", "proxy-arp"),
    ("ip", "finger"),
    ("ip", "identd"),
    ("ip", "kerberos"),
    ("ip", "logging"),
    ("ip", "rip"),
    ("ip", "eigrp"),
    ("ip", "protocol"),
    ("ipv6", "unicast-routing"),
    ("ipv6", "nd"),
    ("no", "ip"),
    ("no", "ipv6"),
    ("no", "shutdown"),
    ("no", "cdp"),
    ("no", "lldp"),
    ("no", "service"),
    ("no", "spanning-tree"),
    ("no", "switchport"),
    ("no", "snmp-server"),
    ("no", "logging"),
    ("no", "aaa"),
    ("no", "passive-interface"),
    ("no", "synchronization"),
    ("no", "auto-summary"),
    ("no", "network"),
    ("no", "neighbor"),
    ("no", "router"),
    ("no", "vlan"),
    ("no", "username"),
    ("no", "access-list"),
    ("no", "banner"),
    ("no", "vtp"),
    ("no", "boot"),
    ("no", "keepalive"),
    ("no", "fair-queue"),
    ("no", "crypto"),
    ("spanning-tree", "portfast"),
    ("spanning-tree", "bpduguard"),
    ("spanning-tree", "mode"),
    ("spanning-tree", "extend"),
    ("spanning-tree", "vlan"),
    ("spanning-tree", "port-priority"),
    ("spanning-tree", "cost"),
    ("spanning-tree", "guard"),
    ("spanning-tree", "link-type"),
    ("switchport", "mode"),
    ("switchport", "access"),
    ("switchport", "trunk"),
    ("switchport", "port-security"),
    ("switchport", "nonegotiate"),
    ("switchport", "voice"),
    ("switchport", "block"),
    ("service", "timestamps"),
    ("service", "password-encryption"),
    ("service", "sequence-numbers"),
    ("service", "dhcp"),
    ("service", "compress-config"),
    ("service", "nagle"),
    ("service", "pad"),
    ("service", "prompt"),
    ("service", "tcp-keepalives"),
    ("service", "udp-small-servers"),
    ("service", "call-home"),
    ("logging", "synchronous"),
    ("logging", "buffered"),
    ("logging", "console"),
    ("logging", "monitor"),
    ("logging", "trap"),
    ("logging", "host"),
    ("logging", "source-interface"),
    ("logging", "facility"),
    ("logging", "timestamp"),
    ("logging", "event"),
    ("logging", "asdm"),
    ("exec-timeout",),
    ("transport", "input"),
    ("transport", "output"),
    ("history", "size"),
    ("session-timeout",),
    ("privilege", "level"),
    ("access-class",),
    ("password",),
    ("secret",),
    ("login",),
    ("login", "local"),
    ("login", "authentication"),
    ("exec",),
    ("autocommand",),
    ("activation-character",),
    ("escape-character",),
    ("flowcontrol",),
    ("stopbits",),
    ("databits",),
    ("parity",),
    ("modem",),
    ("script", "dialer"),
    ("bba-group",),
    ("ppp", "authentication"),
    ("ppp", "chap"),
    ("ppp", "pap"),
    ("ppp", "encapsulation"),
    ("ppp", "multilink"),
    ("encapsulation", "dot1q"),
    ("encapsulation", "dot1Q"),
    ("encapsulation", "ppp"),
    ("encapsulation", "hdlc"),
    ("encapsulation", "frame-relay"),
    ("frame-relay", "lmi"),
    ("frame-relay", "map"),
    ("frame-relay", "interface-dlci"),
    ("clock", "rate"),
    ("bandwidth",),
    ("delay",),
    ("mtu",),
    ("keepalive",),
    ("load-interval",),
    ("cdp", "enable"),
    ("lldp", "run"),
    ("lldp", "receive"),
    ("lldp", "transmit"),
    ("mac-address",),
    ("arp",),
    ("standby",),
    ("vrrp",),
    ("track",),
    ("delay", "startup"),
    ("crypto", "key"),
    ("crypto", "map"),
    ("crypto", "ipsec"),
    ("crypto", "isakmp"),
    ("crypto", "ikev1"),
    ("crypto", "ikev2"),
    ("crypto", "pki"),
    ("crypto", "dynamic-map"),
    ("hash",),
    ("group",),
    ("lifetime",),
    ("authentication", "pre-share"),
    ("authentication", "rsa-sig"),
    ("authentication", "md5"),
    ("encryption", "aes"),
    ("encryption", "3des"),
    ("encryption", "des"),
    ("nat",),
    ("nameif",),
    ("security-level",),
    ("object", "network"),
    ("object-group",),
    ("subnet",),
    ("class", "inspection_default"),
    ("inspect",),
    ("policy-map", "global_policy"),
    ("control-plane",),
    ("dial-peer",),
    ("voice", "register"),
    ("telephony-service",),
    ("ephone",),
    ("sip-ua",),
    ("mgcp",),
    ("sccp",),
    ("call-manager-fallback",),
    ("line",),
    ("vlan",),
    ("interface",),
    ("router",),
    ("network",),
    ("neighbor",),
    ("redistribute",),
    ("passive-interface",),
    ("default-information", "originate"),
    ("auto-cost", "reference-bandwidth"),
    ("log-adjacency-changes",),
    ("area",),
    ("summary-address",),
    ("distribute-list",),
    ("offset-list",),
    ("distance",),
    ("maximum-paths",),
    ("maximum-paths", "ibgp"),
    ("timers",),
    ("variance",),
    ("bgp",),
    ("synchronization",),
    ("address-family",),
    ("route-map",),
    ("match",),
    ("set",),
    ("deny",),
    ("permit",),
    ("remark",),
    ("evaluate",),
    ("access-list",),
    ("ip", "access-list"),
    ("ntp", "server"),
    ("ntp", "authentication-key"),
    ("ntp", "authenticate"),
    ("ntp", "trusted-key"),
    ("ntp", "update-calendar"),
    ("ntp", "master"),
    ("ntp", "access-group"),
    ("ntp", "source"),
    ("snmp-server", "community"),
    ("snmp-server", "host"),
    ("snmp-server", "location"),
    ("snmp-server", "contact"),
    ("snmp-server", "enable"),
    ("snmp-server", "ifindex"),
    ("snmp-server", "trap-source"),
    ("radius-server", "host"),
    ("radius-server", "key"),
    ("tacacs-server", "host"),
    ("tacacs-server", "key"),
    ("aaa", "new-model"),
    ("aaa", "authentication"),
    ("aaa", "authorization"),
    ("aaa", "accounting"),
    ("aaa", "session-id"),
    ("aaa", "group"),
    ("aaa", "server"),
    ("username",),
    ("enable", "secret"),
    ("enable", "password"),
    ("enable", "password"),
    ("hostname",),
    ("banner",),
    ("vtp", "mode"),
    ("vtp", "domain"),
    ("vtp", "version"),
    ("vtp", "password"),
    ("vtp", "pruning"),
    ("vtp", "transparent"),
    ("line", "con"),
    ("line", "vty"),
    ("line", "aux"),
    ("class-map",),
    ("policy-map",),
    ("bandwidth", "remaining"),
    ("priority",),
    ("police",),
    ("shape",),
    ("random-detect",),
    ("fair-queue",),
    ("queue-limit",),
    ("service-policy",),
    ("ip", "cef"),
    ("ip", "routing"),
    ("ip", "domain-lookup"),
    ("ip", "domain-name"),
    ("ip", "domain"),
    ("ip", "default-gateway"),
    ("archive",),
    ("log", "config"),
    ("logging", "enable"),
    ("notify", "syslog"),
    ("hidekeys",),
    ("write-memory",),
    ("time-period",),
    ("maximum",),
    ("path",),
    ("ipv6", "cef"),
    ("ipv6", "unicast-routing"),
    ("ipv6", "address"),
    ("ipv6", "enable"),
    ("ipv6", "ospf"),
    ("ipv6", "router"),
    ("ipv6", "nd"),
    ("ipv6", "dhcp"),
    ("authentication", "login"),
    ("authentication", "enable"),
    ("authorization", "exec"),
    ("authorization", "commands"),
    ("accounting", "exec"),
    ("accounting", "commands"),
)

# Every placeholder this tool itself emits.  A genuine templating artefact
# (`<IP_ADDRESS>`, `<NAME>`) is a red flag; our own `<ip>`/`<text>` are not.
PLACEHOLDERS: frozenset[str] = frozenset({
    "<ip>", "<ip6>", "<mac>", "<secret>", "<if>", "<email>", "<hash>",
    "<n>", "<text>", "<name>", "<time>", "<url>",
})
_UNRESOLVED_PLACEHOLDER_RE = re.compile(r"<[A-Za-z_][A-Za-z0-9_]*>")

# A repeated keyword is a red flag only in the *command* part of a line: ACL
# operands legitimately repeat (`permit udp any any range 4000 4010`).
# `(?=\s|$)` additionally keeps `class class-default` out.
_DUPLICATED_KEYWORD_RE = re.compile(r"\b(\w+)\s+\1(?=\s|$)")
_DUPLICATED_KEYWORD_TOKENS = 3

# Structural red flags that no legitimate IOS configuration line carries.
#
# These run against the **raw** configuration line, never against the
# normalised body: the body is full of this tool's own `<ip>`/`<text>`
# placeholders, and masking legitimately produces repeated words
# (`class class-default`, `access-group OUTSIDE-IN in interface outside`).
SUSPICIOUS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\{\{|\}\}|\{%|<%|%>|\$\{"), "template-placeholder"),
    (re.compile(r"\bTODO\b|\bFIXME\b|\bXXX\b|\bTBD\b",
                re.IGNORECASE), "development-marker"),
    (re.compile(r"[^\x20-\x7e]"), "non-ascii-byte"),
    (re.compile(r"^[-=*_~]{2,}$"), "separator-line"),
    (re.compile(r"^\d+$"), "bare-number"),
    (re.compile(r"^[a-z]$"), "single-character-command"),
)

# Commands that are *always* followed by an argument.  Seeing one of these
# with no argument means the emitted config was truncated.
REQUIRES_ARGUMENT: frozenset[str] = frozenset({
    "description", "hostname", "name", "password", "secret", "username",
    "banner", "banner motd", "vlan", "interface", "router", "line",
    "ip address", "ip route", "ip domain-name", "ip dhcp pool",
    "network", "neighbor", "mtu", "speed", "duplex", "bandwidth", "delay",
    "encapsulation", "clock rate", "access-list", "permit", "deny", "match",
    "class", "set", "policy-map", "class-map", "route-map", "key",
    "key-string", "enable secret", "enable password", "switchport access vlan",
    "switchport trunk allowed vlan", "standby", "crypto map", "logging host",
    "radius-server host", "snmp-server community", "snmp-server host",
    "ip access-list", "load-interval", "keepalive", "exec-timeout",
})


@dataclass(frozen=True, slots=True)
class Classification:
    verdict: str            # ATTESTED | UNATTESTED
    category: str | None    # standard | suspicious | None
    reason: str


def classify_unattested(
    body: str,
    *,
    raw: str | None = None,
    body_attested_in: str | None = None,
) -> Classification:
    """Classify an UNATTESTED signature as ``standard`` or ``suspicious``.

    ``body`` is the *normalised* signature body.  ``raw`` is the original
    configuration line the signature came from; the syntactic red-flag scan
    runs against it when supplied, because the normalized body legitimately
    contains placeholders and repeated words.  When ``raw`` is omitted the body
    is scanned instead (which is what the unit tests do).

    ``body_attested_in`` is the first submode in which the same command body is
    attested; passing it downgrades a submode mismatch to an informational
    ``standard`` finding rather than a suspicious one.
    """
    stripped = body.strip().lower()
    scanned = raw if raw is not None else body

    for pattern, reason in SUSPICIOUS_PATTERNS:
        if pattern.search(scanned):
            return Classification("UNATTESTED", "suspicious", reason)

    if _DUPLICATED_KEYWORD_RE.search(
            " ".join(scanned.split()[:_DUPLICATED_KEYWORD_TOKENS])):
        return Classification("UNATTESTED", "suspicious", "duplicated-keyword")

    for match in _UNRESOLVED_PLACEHOLDER_RE.findall(scanned):
        if match not in PLACEHOLDERS:
            return Classification("UNATTESTED", "suspicious",
                                  "unresolved-html-placeholder")

    if stripped in REQUIRES_ARGUMENT:
        return Classification("UNATTESTED", "suspicious", "truncated-command")

    tokens = stripped.split()
    bare = tokens[1:] if tokens and tokens[0] == "no" else tokens
    if not bare:
        return Classification("UNATTESTED", "suspicious", "empty-command")

    head = bare[0]

    # `ip`/`ipv6` second-token check: catches misspellings (`ip routng`) that a
    # leading-verb vocabulary alone cannot see.
    if head in ("ip", "ipv6") and len(bare) > 1:
        allowed = IP_SUBKEYWORDS if head == "ip" else IPV6_SUBKEYWORDS
        second = bare[1]
        if not _PLACEHOLDER_RE.match(second) and second not in allowed:
            return Classification("UNATTESTED", "suspicious",
                                  f"unrecognised-{head}-keyword:{second}")

    if head in STANDARD_IOS_VERBS:
        if body_attested_in:
            return Classification(
                "UNATTESTED", "standard",
                f"standard-verb:{head} (body attested in submode '{body_attested_in}')",
            )
        return Classification("UNATTESTED", "standard", f"standard-verb:{head}")

    for prefix in STANDARD_IOS_PREFIXES:
        if tuple(bare[: len(prefix)]) == prefix:
            return Classification(
                "UNATTESTED", "standard", "standard-prefix:" + " ".join(prefix))

    if body_attested_in:
        return Classification(
            "UNATTESTED", "standard",
            f"body attested in submode '{body_attested_in}'",
        )

    return Classification("UNATTESTED", "suspicious",
                          f"unrecognised-command-verb:{head}")


# =========================================================================== #
# 8. Report assembly
# =========================================================================== #


def adjudicate(
    reports: ArtifactReport | Sequence[ArtifactReport],
    att: Attestation,
) -> list[dict[str, Any]]:
    """Merge emitted signatures with the attestation set into report rows.

    A signature emitted by more than one artefact is reported **once**, with
    the summed emission count and the list of artefacts that emitted it.
    """
    if isinstance(reports, ArtifactReport):
        reports = [reports]

    body_attested_modes: dict[str, str] = {}
    for key in att.signatures:
        mode, _, body = key.partition("|")
        body_attested_modes.setdefault(body, mode)

    merged: dict[str, Signature] = {}
    for report in reports:
        for key, sig in report.signatures.items():
            acc = merged.get(key)
            if acc is None:
                acc = Signature(key=key, mode=sig.mode, body=sig.body,
                                example=sig.example)
                merged[key] = acc
            acc.count += sig.count
            acc.device_total += len(sig.devices)
            acc.artifacts.add(report.path)

    rows: list[dict[str, Any]] = []
    for sig in merged.values():
        files = att.attest(sig.key)
        sig.corpus_files = files
        sig.corpus_files_body_only = att.attest_body(sig.body)
        if files:
            rows.append(sig.as_dict("ATTESTED", None, f"attested-by-{files}-files"))
        else:
            cls = classify_unattested(
                sig.body, raw=sig.example,
                body_attested_in=body_attested_modes.get(sig.body))
            rows.append(sig.as_dict(cls.verdict, cls.category, cls.reason))
    rows.sort(key=lambda r: (r["verdict"] != "UNATTESTED", -r["emitted"], r["signature"]))
    return rows


def default_corpus_candidates() -> list[Path]:
    """Places to look for the corpus when ``--corpus`` is not given."""
    return [
        REPO / "corpus" / "files",
        REPO.parent / "corpus" / "files",
        REPO.parent / "corpus" / "internet",
        REPO.parent / "corpus",
        REPO / "corpus",
        Path.cwd() / "corpus" / "files",
        Path.cwd() / "corpus",
    ]


def resolve_default_corpus() -> Path | None:
    for cand in default_corpus_candidates():
        if not cand.is_dir():
            continue
        try:
            if iter_corpus_files(cand, None):
                return cand
        except OSError:
            continue
    return None


def summarise_rows(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    attested = [r for r in rows if r["verdict"] == "ATTESTED"]
    unattested = [r for r in rows if r["verdict"] != "ATTESTED"]
    standard = [r for r in unattested if r["category"] == "standard"]
    suspicious = [r for r in unattested if r["category"] == "suspicious"]
    return {
        "distinct_signatures": len(rows),
        "attested_signatures": len(attested),
        "unattested_signatures": len(unattested),
        "unattested_standard": len(standard),
        "unattested_suspicious": len(suspicious),
        "attested_emissions": sum(r["emitted"] for r in attested),
        "unattested_emissions": sum(r["emitted"] for r in unattested),
        "suspicious_emissions": sum(r["emitted"] for r in suspicious),
    }


def render_markdown(
    rows: Sequence[dict[str, Any]],
    summary: dict[str, Any],
    artifacts: Sequence[ArtifactReport],
    att: Attestation,
    *,
    max_rows: int = 200,
) -> str:
    out: list[str] = []
    out.append("# IOS command attestation audit")
    out.append("")
    out.append(f"Corpus: `{att.corpus_dir}` — {att.files_ok} files decoded, "
               f"{att.files_failed} failed, {len(att.signatures)} attested "
               f"signatures ({att.elapsed_s:g}s).")
    out.append("")
    for a in artifacts:
        out.append(f"* `{a.path}` — {a.devices} devices with a RUNNINGCONFIG, "
                   f"{a.lines} config lines, {len(a.signatures)} distinct "
                   f"signatures (sha256 `{a.sha256[:12]}…`)")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| metric | value |")
    out.append("| --- | ---: |")
    for k in ("distinct_signatures", "attested_signatures", "unattested_signatures",
              "unattested_standard", "unattested_suspicious",
              "unattested_emissions", "suspicious_emissions"):
        out.append(f"| {k.replace('_', ' ')} | {summary[k]:,} |")
    out.append("")

    suspicious = [r for r in rows if r["category"] == "suspicious"]
    if suspicious:
        out.append("## Suspicious UNATTESTED signatures (exit non-zero)")
        out.append("")
        out.append("| signature | emitted | devices | reason | example |")
        out.append("| --- | ---: | ---: | --- | --- |")
        for r in suspicious:
            out.append("| `{}` | {} | {} | {} | `{}` |".format(
                r["signature"], r["emitted"], r["devices"], r["reason"],
                r["example"][:90].replace("|", "\\|")))
        out.append("")

    unattested = [r for r in rows if r["verdict"] != "ATTESTED"][:max_rows]
    if unattested:
        out.append(f"## UNATTESTED signatures (first {len(unattested)})")
        out.append("")
        out.append("| signature | emitted | corpus files | category | reason |")
        out.append("| --- | ---: | ---: | --- | --- |")
        for r in unattested:
            out.append("| `{}` | {} | {} | {} | {} |".format(
                r["signature"], r["emitted"], r["corpus_files"],
                r["category"], r["reason"]))
        out.append("")

    if att.failures:
        out.append(f"## Corpus decode failures ({len(att.failures)})")
        out.append("")
        out.append("These files were **not** treated as empty — they contributed "
                   "nothing to the attestation set.")
        out.append("")
        out.append("| file | error |")
        out.append("| --- | --- |")
        for name, err in sorted(att.failures.items())[:max_rows]:
            out.append(f"| `{name}` | {err[:120]} |")
        out.append("")
    return "\n".join(out) + "\n"


# =========================================================================== #
# 9. CLI
# =========================================================================== #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="audit_ios_commands.py",
        description="Attest every emitted Packet Tracer IOS config line against "
                    "the reference corpus (ENTERPRISE_PROBLEMS.md problem 20).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("artifacts", nargs="*", metavar="ARTIFACT",
                   help=".pkt/.pka files to audit (may also use --artifact)")
    p.add_argument("--artifact", action="append", default=[], metavar="PATH",
                   help="a .pkt/.pka to audit; repeatable")
    p.add_argument("--corpus", metavar="DIR",
                   help="corpus directory (the corpus root or the directory "
                        "holding the containers); default: auto-discover")
    p.add_argument("--index", metavar="TSV",
                   help="CORPUS_INDEX.tsv used for the cache fingerprint")
    p.add_argument("--cache", metavar="PATH", default=str(REPO / "build" / "ios_attestation.json"),
                   help="attestation cache (default: build/ios_attestation.json)")
    p.add_argument("--refresh-cache", action="store_true",
                   help="re-decode the corpus even if the cache is valid")
    p.add_argument("--workers", type=int, default=0,
                   help="corpus decode parallelism (0 = auto, 1 = in-process)")
    p.add_argument("--json", metavar="PATH", help="write the machine-readable report")
    p.add_argument("--markdown", metavar="PATH", help="write a markdown report")
    p.add_argument("--max-rows", type=int, default=200,
                   help="maximum UNATTESTED rows printed / rendered (default 200)")
    p.add_argument("--quiet", action="store_true", help="suppress the text summary")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    artifact_paths = list(args.artifact) + list(args.artifacts)
    if not artifact_paths:
        print("error: no artefact given (use --artifact PATH)", file=sys.stderr)
        return 1
    missing = [a for a in artifact_paths if not Path(a).is_file()]
    if missing:
        print(f"error: artefact(s) not found: {missing}", file=sys.stderr)
        return 1

    corpus_dir = Path(args.corpus) if args.corpus else resolve_default_corpus()
    if corpus_dir is None:
        print("error: could not locate the reference corpus; pass --corpus DIR",
              file=sys.stderr)
        return 1
    if not corpus_dir.is_dir():
        print(f"error: --corpus {corpus_dir} is not a directory", file=sys.stderr)
        return 1

    index = Path(args.index) if args.index else (corpus_dir / "CORPUS_INDEX.tsv")
    if not index.is_file():
        parent_index = corpus_dir.parent / "CORPUS_INDEX.tsv"
        index = parent_index if parent_index.is_file() else None

    cache_path = Path(args.cache)
    att: Attestation | None = None
    if not args.refresh_cache:
        att = load_cache(cache_path)
        if att is not None:
            files = iter_corpus_files(corpus_dir, index)
            if files and _corpus_fingerprint(files, index) != att.fingerprint:
                if not args.quiet:
                    print("cache fingerprint mismatch -> re-decoding corpus",
                          file=sys.stderr)
                att = None
    if att is None:
        if not args.quiet:
            print(f"decoding corpus {corpus_dir} ...", file=sys.stderr)
        att = build_attestation(corpus_dir, index=index, workers=args.workers,
                                progress=not args.quiet)
        save_cache(att, cache_path)

    reports = [extract_artifact_signatures(p) for p in artifact_paths]
    all_rows = adjudicate(reports, att)
    summary = summarise_rows(all_rows)

    payload = {
        "schema": "pkt-ios-audit/1",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": [
            {
                "path": a.path,
                "sha256": a.sha256,
                "devices": a.devices,
                "runningconfig_blocks": a.blocks,
                "config_lines": a.lines,
                "banner_body_lines": a.banner_lines,
                "ignored_lines": a.ignored_lines,
                "distinct_signatures": len(a.signatures),
            }
            for a in reports
        ],
        "corpus": {
            "dir": att.corpus_dir,
            "cache": str(cache_path),
            "cache_hit": att.cache_hit,
            "fingerprint": att.fingerprint,
            "generated": att.generated,
            "files_ok": att.files_ok,
            "files_failed": att.files_failed,
            "attested_signatures": len(att.signatures),
            "attested_bodies": len(att.bodies),
            "decode_failures": att.failures,
        },
        "summary": summary,
        "signatures": all_rows,
    }

    if args.json:
        jp = Path(args.json)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
    if args.markdown:
        mp = Path(args.markdown)
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(render_markdown(all_rows, summary, reports, att,
                                      max_rows=args.max_rows), encoding="utf-8")

    if not args.quiet:
        print()
        for a in reports:
            print(f"artefact      : {a.path}")
            print(f"  sha256      : {a.sha256}")
            print(f"  devices     : {a.devices} RUNNINGCONFIG blocks, {a.lines} lines "
                  f"({a.banner_lines} banner-body, {a.ignored_lines} comment/blank)")
            print(f"  signatures  : {len(a.signatures)} distinct")
        print(f"corpus        : {att.corpus_dir}")
        print(f"  decoded     : {att.files_ok} ok, {att.files_failed} FAILED"
              f"{' (cache)' if att.cache_hit else ''}"
              f"  [{len(att.signatures)} attested signatures]")
        if att.files_failed:
            print("  failures are recorded in the report and were NOT treated as empty")
        print(f"distinct sigs : {summary['distinct_signatures']}")
        print(f"  ATTESTED    : {summary['attested_signatures']}"
              f"  ({summary['attested_emissions']} emissions)")
        print(f"  UNATTESTED  : {summary['unattested_signatures']}"
              f"  ({summary['unattested_emissions']} emissions)")
        print(f"     standard : {summary['unattested_standard']}")
        print(f"     SUSPICIOUS: {summary['unattested_suspicious']}"
              f"  ({summary['suspicious_emissions']} emissions)")
        suspicious = [r for r in all_rows if r["category"] == "suspicious"]
        if suspicious:
            print("\nsuspicious signatures:")
            for r in suspicious[:args.max_rows]:
                print(f"  [{r['emitted']:>6}x] {r['signature']}   <- {r['reason']}")
                print(f"           e.g. {r['example']}")
            if len(suspicious) > args.max_rows:
                print(f"  ... and {len(suspicious) - args.max_rows} more (see --json)")
        else:
            print("\nno suspicious signatures: every UNATTESTED line is a "
                  "recognisable standard IOS construct")
        if args.json:
            print(f"\njson          : {args.json}")
        if args.markdown:
            print(f"markdown      : {args.markdown}")

    return 2 if summary["unattested_suspicious"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
