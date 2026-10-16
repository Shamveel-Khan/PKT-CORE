# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Tests for the template sanitiser, service inventory and uniqueness validator.

The defect this suite exists for: harvested device templates carry service
configuration (AAA clients, DHCP pools, accounts) that a generator never
authored, and a validator that counts services without proving them distinct
prints ``PASSED`` on the inflated figures.  Three layers are tested:

1. the sanitiser removes template leftovers (and only those, after authoring);
2. the inventory reports raw *and* distinct counts, and the validator FAILS on
   duplicates;
3. regression against the shipped enterprise artefact
   (``JASDF_AEWC_JADGE.pkt``) and against the generator's own output.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from xml.etree.ElementTree import Element as ETElement
from xml.etree.ElementTree import fromstring as et_fromstring

import pytest

from pkt_core import decode_bytes, encode_bytes
from pkt_core.audit import (
    DEFAULT_LEFTOVER_RULES,
    ConfigLineStats,
    DedupCount,
    LeftoverRule,
    SanitizeReport,
    TemplateLeftovers,
    as_view,
    format_identity,
    inventory,
    sanitize_engine,
    sanitize_template_leftovers,
    sanitize_xml,
    strip_service_records,
    validate_lab,
)
from pkt_core.cli.main import main as cli_main
from pkt_core.models import Lab
from pkt_core.models.services import (
    AaaClient,
    DhcpPool,
    DeviceServices,
    DnsRecord,
    zone_identity,
)

REPO = Path(__file__).resolve().parent.parent
TEMPLATES_JSON = REPO / "tools" / "device_templates.json"
GENERATOR = REPO / "generators" / "jasdf_aewc" / "build_jasdf_aewc.py"
REAL_ARTEFACT = Path("/home/saoria/filedrop/uploads/JASDF_AEWC_JADGE.pkt")

needs_real = pytest.mark.skipif(
    not REAL_ARTEFACT.exists(),
    reason="shipped enterprise artefact not available",
)
needs_generator = pytest.mark.skipif(
    not GENERATOR.exists(),
    reason="vendored JASDF generator not available",
)


# --------------------------------------------------------------------------- #
# synthetic fixtures
# --------------------------------------------------------------------------- #
# A harvested Server-PT-like template carrying *duplicate* leftovers: two
# identical AAA clients, two identical degenerate DHCP pools (one with a lease
# table from the donor lab), plus the usual account residue.
TEMPLATE_DEVICE = """<DEVICE>
 <ENGINE>
  <TYPE model="Server-PT">Server</TYPE>
  <NAME translate="true">Server-PT</NAME>
  <POWER>true</POWER>
  <ACS_SERVER>
   <ENABLED>1</ENABLED>
   <USERS>
    <USER><NAME>user</NAME><PASSWORD>cisco</PASSWORD><DESCRIPTION /></USER>
   </USERS>
   <ACS_CLIENTS>
    <CLIENT><HOST_IP>192.168.10.1</HOST_IP><KEY>ciscosecret</KEY><DESCRIPTION>R1</DESCRIPTION><SERVER_TYPE>RADIUS</SERVER_TYPE></CLIENT>
    <CLIENT><HOST_IP>192.168.10.1</HOST_IP><KEY>ciscosecret</KEY><DESCRIPTION>R1</DESCRIPTION><SERVER_TYPE>RADIUS</SERVER_TYPE></CLIENT>
   </ACS_CLIENTS>
  </ACS_SERVER>
  <DHCP_SERVERS>
   <ASSOCIATED_PORTS>
    <ASSOCIATED_PORT>
     <NAME>FastEthernet0</NAME>
     <DHCP_SERVER>
      <ENABLED>1</ENABLED>
      <POOLS>
       <POOL><NAME>serverPool</NAME><NETWORK>0.0.0.0</NETWORK><MASK>0.0.0.0</MASK>
        <DEFAULT_ROUTER>0.0.0.0</DEFAULT_ROUTER>
        <DHCP_POOL_LEASES /></POOL>
       <POOL><NAME>serverPool</NAME><NETWORK>0.0.0.0</NETWORK><MASK>0.0.0.0</MASK>
        <DEFAULT_ROUTER>0.0.0.0</DEFAULT_ROUTER>
        <DHCP_POOL_LEASES><DHCP_POOL_LEASE><IP>192.168.10.50</IP></DHCP_POOL_LEASE></DHCP_POOL_LEASES></POOL>
      </POOLS>
     </DHCP_SERVER>
    </ASSOCIATED_PORT>
   </ASSOCIATED_PORTS>
  </DHCP_SERVERS>
  <DNS_SERVER>
   <ENABLED>1</ENABLED>
   <NAMESERVER-DATABASE>
    <RESOURCE-RECORD><TYPE>A-REC</TYPE><NAME>old</NAME><TTL>86400</TTL><IPADDRESS>192.168.10.9</IPADDRESS></RESOURCE-RECORD>
   </NAMESERVER-DATABASE>
  </DNS_SERVER>
  <FTP_SERVER>
   <ENABLED>1</ENABLED>
   <USER_ACCOUNT_MNGR>
    <ACCOUNT><USERNAME>cisco</USERNAME><PASSWORD>cisco</PASSWORD><PERMISSIONS>RWDNL</PERMISSIONS></ACCOUNT>
   </USER_ACCOUNT_MNGR>
  </FTP_SERVER>
 </ENGINE>
</DEVICE>"""


def _doc(*devices: str) -> bytes:
    """Wrap DEVICE fragments in a minimal PACKETTRACER5 document."""
    return (
        "<PACKETTRACER5><VERSION>9.0.1.0858</VERSION><NETWORK><DEVICES>"
        + "".join(devices)
        + "</DEVICES><LINKS /></NETWORK></PACKETTRACER5>"
    ).encode("utf-8")


def _server(name: str, *, clients: tuple[str, ...] = (), pools: tuple[tuple[str, str, str], ...] = (),
            dns: tuple[tuple[str, str], ...] = (), users: tuple[str, ...] = (),
            ftp: tuple[str, ...] = (), ios_lines: tuple[str, ...] = (),
            model: str = "Server-PT") -> str:
    """A Server-PT device carrying only what the generator authored."""
    def block(tag: str, body: str) -> str:
        return f"<{tag}>{body}</{tag}>" if body else ""

    client_xml = "".join(
        f"<CLIENT><HOST_IP>{ip}</HOST_IP><KEY>k</KEY><DESCRIPTION>authored</DESCRIPTION>"
        f"<SERVER_TYPE>RADIUS</SERVER_TYPE></CLIENT>"
        for ip in clients
    )
    pool_xml = "".join(
        f"<POOL><NAME>{n}</NAME><NETWORK>{net}</NETWORK><MASK>{mask}</MASK>"
        f"<DEFAULT_ROUTER>10.0.0.1</DEFAULT_ROUTER><START_IP>10.0.0.10</START_IP>"
        f"<END_IP>10.0.0.20</END_IP><MAX_USERS>10</MAX_USERS><DHCP_POOL_LEASES /></POOL>"
        for n, net, mask in pools
    )
    dns_xml = "".join(
        f"<RESOURCE-RECORD><TYPE>A-REC</TYPE><NAME>{n}</NAME><TTL>86400</TTL>"
        f"<IPADDRESS>{ip}</IPADDRESS></RESOURCE-RECORD>"
        for n, ip in dns
    )
    user_xml = "".join(
        f"<USER><NAME>{u}</NAME><PASSWORD>p</PASSWORD><DESCRIPTION /></USER>" for u in users
    )
    ftp_xml = "".join(
        f"<ACCOUNT><USERNAME>{u}</USERNAME><PASSWORD>p</PASSWORD><PERMISSIONS>RWDNL</PERMISSIONS></ACCOUNT>"
        for u in ftp
    )
    cfg = block(
        "RUNNINGCONFIG",
        "".join(f"<LINE>{line}</LINE>" for line in ios_lines),
    )
    # No STARTUPCONFIG: whether a device is an IOS/ASA device is decided by its
    # model, not by this element.  See NETWORK_DEVICE_MODELS.
    startup = ""
    return f"""<DEVICE>
 <ENGINE>
  <TYPE model="{model}">Server</TYPE>
  <NAME translate="true">{name}</NAME>
  <POWER>true</POWER>
  {cfg}
  {startup}
  {block("ACS_SERVER", block("USERS", user_xml) + block("ACS_CLIENTS", client_xml))}
  {block("DHCP_SERVERS", "<ASSOCIATED_PORTS><ASSOCIATED_PORT><NAME>FastEthernet0</NAME><DHCP_SERVER><ENABLED>1</ENABLED>" + block("POOLS", pool_xml) + "</DHCP_SERVER></ASSOCIATED_PORT></ASSOCIATED_PORTS>") if pool_xml else ""}
  {block("DNS_SERVER", "<ENABLED>1</ENABLED>" + block("NAMESERVER-DATABASE", dns_xml))}
  {block("FTP_SERVER", "<ENABLED>1</ENABLED>" + block("USER_ACCOUNT_MNGR", ftp_xml))}
 </ENGINE>
</DEVICE>"""


# --------------------------------------------------------------------------- #
# 1. template sanitiser
# --------------------------------------------------------------------------- #
def test_template_leftovers_fingerprint_finds_duplicate_records() -> None:
    leftovers = TemplateLeftovers.from_templates({"Server-PT": TEMPLATE_DEVICE})
    per_family = leftovers.for_model("Server-PT")
    # identity sets are deduped: the template's two identical clients are one
    assert per_family["aaa_clients"] == frozenset({("192.168.10.1",)})
    assert per_family["dhcp_pools"] == frozenset(
        {("serverPool", "0.0.0.0", "0.0.0.0")}
    )
    assert per_family["dns_records"] == frozenset({("A-REC", "old", "192.168.10.9")})
    assert leftovers.is_leftover("Server-PT", "aaa_clients", ("192.168.10.1",))
    assert not leftovers.is_leftover("Server-PT", "aaa_clients", ("10.0.0.1",))
    assert not leftovers.is_leftover("Pc-PT", "aaa_clients", ("192.168.10.1",))


def test_sanitize_removes_duplicate_template_leftovers() -> None:
    """A synthetic template carrying duplicate AAA clients and DHCP pools:
    the sanitiser removes them (all instances, not one per identity)."""
    leftovers = TemplateLeftovers.from_templates({"Server-PT": TEMPLATE_DEVICE})
    doc = _doc(
        _server("authored", clients=("10.1.1.1",), pools=(("p1", "10.9.0.0", "255.255.255.0"),),
                users=("admin",), ftp=("cfg",), dns=(("new", "10.2.2.2"),)),
        # instantiated template verbatim: everything here is residue
        TEMPLATE_DEVICE.replace('translate="true">Server-PT', 'translate="true">leftover'),
    )
    lab = Lab.from_bytes(doc)

    before = inventory(lab, leftovers=leftovers)
    assert before.aaa_clients.raw == 3            # 1 authored + 2 template copies
    assert before.dhcp_pools.raw == 3
    assert before.aaa_users.raw == 2
    assert before.ftp_accounts.raw == 2
    assert before.dns_records.raw == 2

    report = sanitize_template_leftovers(lab, leftovers=leftovers)
    assert report.as_dict() == {
        "aaa-clients": 2,
        "aaa-users": 1,
        "dhcp-pools": 2,
        "dns-records": 1,
        "ftp-accounts": 1,
        "dhcp-port-bindings": 1,
    }

    after = inventory(lab, leftovers=leftovers)
    assert after.aaa_clients.raw == 1 and after.aaa_clients.items == (("10.1.1.1",),)
    assert after.dhcp_pools.raw == 1
    assert after.aaa_users.raw == 1 and after.aaa_users.items == (("admin",),)
    assert after.ftp_accounts.raw == 1
    assert after.dns_records.raw == 1
    # every leftover identity is gone
    for family, count in after.families.items():
        assert count.leftover_instances == 0, family


def test_sanitize_template_mode_keeps_authored_records() -> None:
    """Template-derived mode must not delete authored records, even ones that
    merely look like leftovers of another family."""
    leftovers = TemplateLeftovers.from_templates({"Server-PT": TEMPLATE_DEVICE})
    doc = _doc(_server("srv", clients=("10.1.1.1", "10.1.1.2"),
                       pools=(("a", "10.9.0.0", "255.255.255.0"), ("b", "10.9.1.0", "255.255.255.0"))))
    lab = Lab.from_bytes(doc)
    report = sanitize_template_leftovers(lab, leftovers=leftovers)
    assert report.total == 0
    inv = inventory(lab, leftovers=leftovers)
    assert inv.aaa_clients.raw == 2 and inv.dhcp_pools.raw == 2


def test_strip_service_records_is_a_blank_slate() -> None:
    doc = _doc(_server("srv", clients=("10.1.1.1",), pools=(("p", "10.9.0.0", "255.255.255.0"),),
                       users=("u",), ftp=("f",), dns=(("n", "10.2.2.2"),)))
    lab = Lab.from_bytes(doc)
    report = strip_service_records(lab)
    # 1 client + 1 pool + its port binding + 1 user + 1 dns + 1 ftp account.
    # The binding counts because an <ASSOCIATED_PORT> whose pools are all gone
    # must go with them -- leaving it behind is what made the first sanitiser
    # look like it had worked.
    assert report.total == 6
    assert report.as_dict()["dhcp-port-bindings"] == 1
    inv = inventory(lab)
    assert inv.aaa_clients.raw == inv.dhcp_pools.raw == 0
    assert inv.aaa_users.raw == inv.ftp_accounts.raw == inv.dns_records.raw == 0


def test_sanitize_works_on_stdlib_elementtree() -> None:
    """The generator builds stdlib ElementTree documents; the sanitiser core
    must accept that tree too."""
    leftovers = TemplateLeftovers.from_templates({"Server-PT": TEMPLATE_DEVICE})
    el: ETElement = et_fromstring(TEMPLATE_DEVICE.replace('translate="true">Server-PT', 'translate="true">srv'))
    report = sanitize_engine(el, leftovers=leftovers)
    assert report.as_dict() == {
        "aaa-clients": 2, "aaa-users": 1, "dhcp-pools": 2,
        "dns-records": 1, "ftp-accounts": 1,
        "dhcp-port-bindings": 1,   # the port that held only those two pools
    }
    # and the blank-slate mode on a bare ENGINE element
    engine_el = el.find("ENGINE")
    assert engine_el is not None
    assert sanitize_engine(engine_el).total == 0  # already cleaned above
    assert isinstance(as_view(engine_el).tag, str)


def test_sanitize_xml_round_trips_document() -> None:
    leftovers = TemplateLeftovers.from_templates({"Server-PT": TEMPLATE_DEVICE})
    doc = _doc(TEMPLATE_DEVICE.replace('translate="true">Server-PT', 'translate="true">srv'))
    new_xml, report = sanitize_xml(doc, leftovers=leftovers)
    assert report.total == 8  # 2 clients + 1 user + 2 pools + 1 dns + 1 ftp
                              # + the port binding that held the two pools
    # untouched header survives byte-exact
    assert new_xml.startswith(b"<PACKETTRACER5><VERSION>9.0.1.0858</VERSION>")
    assert b"192.168.10.1" not in new_xml
    assert b"serverPool" not in new_xml


def test_sanitize_report_merge_and_describe() -> None:
    a = SanitizeReport({"aaa-clients": 1})
    b = SanitizeReport({"aaa-clients": 2, "dhcp-pools": 3})
    merged = a.merge(b)
    assert merged.as_dict() == {"aaa-clients": 3, "dhcp-pools": 3}
    assert merged.total == 6
    assert "aaa-clients" in merged.describe()
    assert SanitizeReport().describe() == "no template leftovers found"


def test_leftover_rules_cover_runtime_state() -> None:
    labels = {r.label for r in DEFAULT_LEFTOVER_RULES}
    assert {"aaa-clients", "aaa-users", "dhcp-pools", "dhcp-leases",
            "dhcp-reservations", "dns-records", "ftp-accounts"} <= labels
    # blank-slate honours custom rule sets
    doc = _doc(_server("srv", clients=("10.1.1.1",)))
    lab = Lab.from_bytes(doc)
    only_clients = (LeftoverRule("ACS_CLIENTS", "CLIENT", "only-clients"),)
    assert strip_service_records(lab, rules=only_clients).as_dict() == {"only-clients": 1}


# --------------------------------------------------------------------------- #
# 2. inventory + validator
# --------------------------------------------------------------------------- #
def test_inventory_reports_raw_and_distinct_counts() -> None:
    doc = _doc(
        _server("a", clients=("10.1.1.1", "10.1.1.1", "10.1.1.2"),
                pools=(("p", "10.9.0.0", "255.255.255.0"), ("p", "10.9.0.0", "255.255.255.0"))),
    )
    inv = inventory(Lab.from_bytes(doc))
    assert inv.aaa_clients.raw == 3
    assert inv.aaa_clients.distinct == 2
    assert inv.aaa_clients.duplicate_instances == 1
    assert inv.aaa_clients.duplicates == {("10.1.1.1",): 2}
    assert not inv.aaa_clients.unique
    # The fixture lists two byte-identical pools: two *instances*, one identity.
    # `raw` counts occurrences and `distinct` counts identities -- that gap is
    # exactly what makes a duplicate visible, so they must not be conflated.
    assert inv.dhcp_pools.raw == 2
    assert inv.dhcp_pools.distinct == 1
    assert not inv.dhcp_pools.unique
    assert inv.aaa_clients.as_dict()["duplicate_instances"] == 1
    assert "10.1.1.1 x2" in inv.aaa_clients.describe()
    assert inv.count("aaa_clients") is inv.aaa_clients
    assert inv.count("dhcp_pools").family == "dhcp_pools"
    with pytest.raises(KeyError):
        inv.count("nope")
    assert "services" in inv.summary()
    assert json.loads(json.dumps(inv.as_dict()))["families"]["aaa_clients"]["raw"] == 3


def test_validator_fails_on_duplicates() -> None:
    """A validator that reports counts must prove the items distinct."""
    doc = _doc(
        _server("dup-device", clients=("10.1.1.1",)),
        _server("dup-device", clients=("10.1.1.1",),
                pools=(("IRUMA-VLAN10", "10.11.10.0", "255.255.255.0"),
                       ("IRUMA-VLAN10", "10.29.10.0", "255.255.255.0"),  # name collision
                       ("other", "10.11.10.0", "255.255.255.0")),       # scope collision
                users=("admin", "admin"), ftp=("cisco", "cisco"),
                dns=(("n1", "10.2.2.2"), ("n1", "10.2.2.2"))),
    )
    report = validate_lab(Lab.from_bytes(doc))
    assert not report.ok
    codes = set(report.codes())
    assert {
        "duplicate-device-name",
        "duplicate-aaa-client",
        "duplicate-aaa-user",
        "duplicate-ftp-account",
        "duplicate-dhcp-pool-name",
        "duplicate-dhcp-pool-scope",
        "duplicate-dns-record",
    } <= codes
    assert "FAILED" in report.summary()
    assert report.failures and not report.warnings


def test_validator_passes_on_distinct_services() -> None:
    doc = _doc(
        _server("a", clients=("10.1.1.1",), pools=(("p1", "10.9.0.0", "255.255.255.0"),),
                users=("u1",), ftp=("f1",), dns=(("n1", "10.2.2.2"),)),
        _server("b", clients=("10.1.1.2",), pools=(("p2", "10.9.1.0", "255.255.255.0"),),
                users=("u2",), ftp=("f2",), dns=(("n1", "10.2.2.2"),)),
    )
    report = validate_lab(Lab.from_bytes(doc))
    assert report.ok, report.summary()
    # replication of a zone across servers is expected, not a duplicate
    assert "duplicate-dns-record" not in report.codes()
    assert "PASSED" in report.summary()


def test_validator_flags_template_leftovers() -> None:
    leftovers = TemplateLeftovers.from_templates({"Server-PT": TEMPLATE_DEVICE})
    doc = _doc(TEMPLATE_DEVICE.replace('translate="true">Server-PT', 'translate="true">srv'))
    report = validate_lab(Lab.from_bytes(doc), leftovers=leftovers)
    assert not report.ok
    assert "template-leftovers" in report.codes()


def test_validator_warns_on_dns_zone_divergence_and_end_device_ips() -> None:
    doc = _doc(
        _server("a", dns=(("n1", "10.2.2.2"),)),
        _server("b", dns=(("n2", "10.2.2.3"),)),
        _server("c"),
    )
    # duplicated end-device IP on two ports of one device
    doc = doc.replace(
        b"<POWER>true</POWER>",
        b"<POWER>true</POWER><PORT><TYPE>eCopperFastEthernet</TYPE><IP>10.5.5.5</IP></PORT>"
        b"<PORT><TYPE>eCopperFastEthernet</TYPE><IP>10.5.5.5</IP></PORT>"
        b"<PORT><TYPE>eCopperFastEthernet</TYPE><IP>0.0.0.0</IP></PORT>",
        1,
    )
    report = validate_lab(Lab.from_bytes(doc))
    codes = report.codes()
    assert "dns-zone-divergence" in codes
    assert "duplicate-end-device-ip" in codes
    assert report.warnings and not report.failures
    assert report.ok  # warnings alone do not fail


def test_dedup_count_and_config_line_stats_are_self_consistent() -> None:
    c = DedupCount("x", (("a",), ("a",), ("b",)), frozenset({("a",)}))
    assert c.raw == 3 and c.distinct == 2
    assert c.duplicate_instances == 1
    assert c.leftover_instances == 2
    assert c.authored_instances == 1
    assert c.authored == (("b",),)
    assert c.authored_distinct == 1
    assert format_identity(()) == "<empty>"
    stats = ConfigLineStats(blocks=3, total_lines=10, ios_blocks=2, ios_lines=8,
                            min_lines=3, median_lines=5, max_lines=5)
    assert "total=8" in stats.describe()
    assert stats.as_dict()["ios_lines"] == 8


def test_config_line_stats_select_ios_by_model_not_by_startup_element() -> None:
    """IOS/ASA devices are identified by *model*.

    The old rule was "carries a `<STARTUPCONFIG>` element", which is not a proxy
    for anything: 123 of the 290 devices in the JASDF model had an empty one and
    were counted as configured, while the only 20 with content held a harvested
    template's factory default -- so the statistic described precisely the
    devices that were wrong.  A server appliance carrying a 4-line stub is a
    config block, but it is not an IOS device.
    """
    doc = _doc(
        _server("R1", model="2911", ios_lines=("!", "hostname R1", "end")),
        _server("srv", ios_lines=("!", "stub", "!", "end")),   # Server-PT
    )
    inv = inventory(Lab.from_bytes(doc))
    assert inv.config_lines.blocks == 2          # both have a RUNNINGCONFIG
    assert inv.config_lines.total_lines == 7     # 3 + 4
    assert inv.config_lines.ios_blocks == 1      # only the 2911
    assert inv.config_lines.ios_lines == 3


def test_typed_service_views_expose_identities() -> None:
    lab = Lab.from_bytes(_doc(_server("a", clients=("10.1.1.1",),
                                     pools=(("p", "10.9.0.0", "255.255.255.0"),),
                                     dns=(("n", "10.2.2.2"),))))
    dev = lab.device_named("a")
    assert dev is not None and dev.services is not None
    svc: DeviceServices = dev.services
    client: AaaClient = svc.aaa_clients[0]
    assert client.identity == ("10.1.1.1",) and client.host_ip == "10.1.1.1"
    pool: DhcpPool = svc.dhcp_pools[0]
    assert pool.identity == ("p", "10.9.0.0", "255.255.255.0")
    assert pool.scope == ("10.9.0.0", "255.255.255.0") and pool.max_users == 10
    rec: DnsRecord = svc.dns_records[0]
    assert rec.identity == ("A-REC", "n", "10.2.2.2")
    assert rec.zone_key == ("A-REC", "n") == zone_identity(rec.identity)


# --------------------------------------------------------------------------- #
# 3. regression: the shipped enterprise artefact
# --------------------------------------------------------------------------- #
@needs_real
def test_real_artefact_service_counts_are_the_measured_truth() -> None:
    """The shipped artefact carries the *repaired* counts.

    Problems #1/#2 were 202 AAA clients of which only 140 were distinct, and 259
    DHCP pools of which 131 were authored -- the difference being one phantom
    192.168.10.1 and 128 degenerate serverPool records copied off the harvested
    device templates.  The generator no longer emits them and the shipped file
    was rebuilt from it, so the counts now agree: every family is distinct and
    carries no template residue.

    This test previously asserted the broken figures.  A test that pins a shipped
    deliverable's *defects* fails the moment they are fixed, which is a bad test
    rather than a regression -- the defect behaviour is pinned by the synthetic
    fixtures above instead.
    """
    lab = Lab.from_bytes(decode_bytes(REAL_ARTEFACT.read_bytes(), "pkt").xml)
    leftovers = TemplateLeftovers.from_device_templates_json(TEMPLATES_JSON)
    inv = inventory(lab, leftovers=leftovers)

    assert inv.aaa_clients.raw == 139
    assert inv.aaa_clients.distinct == 139
    assert inv.aaa_clients.duplicates == {}
    assert inv.aaa_clients.leftover_instances == 0

    assert inv.dhcp_pools.raw == 131
    assert inv.dhcp_pools.distinct == 131           # (name, network, mask)
    assert inv.dhcp_pools.leftover_instances == 0
    assert inv.dhcp_pools.authored_distinct == 131

    # DNS was never wrong: 248 names x 2 servers = 496, and that duplication is
    # correct -- two servers serve the same zone.  It must survive sanitising.
    assert inv.dns_records.raw == 496
    assert inv.dns_records.distinct == 248
    assert inv.dns_records.leftover_instances == 0
    assert len(inv.dns_records_by_device) == 2
    assert all(len(zone) == 248 for _, zone in inv.dns_records_by_device)

    # the account residue the catalogue did not originally mention is gone too
    assert inv.aaa_users.raw == 2 and inv.aaa_users.leftover_instances == 0
    assert inv.ftp_accounts.raw == 2 and inv.ftp_accounts.leftover_instances == 0

    # problem 17: both figures, and both methods stated with them.
    # `ios_*` selects the 143 IOS/ASA devices BY MODEL (NETWORK_DEVICE_MODELS),
    # not by the presence of a <STARTUPCONFIG> element -- 123 of the devices
    # carried an empty one and the only 20 with content held another lab's
    # factory default, so the old proxy measured the wrong population.
    assert inv.config_lines.ios_lines == 22_648
    assert inv.config_lines.ios_blocks == 143
    assert inv.config_lines.total_lines == 22_896  # all 205 RUNNINGCONFIG blocks
    assert inv.config_lines.blocks == 205


@needs_real
def test_real_artefact_validator_passes_and_catches_a_synthetic_duplicate() -> None:
    """The shipped artefact is clean, and the validator still bites.

    The validator's job is to *fail* on duplicates, so it must be shown doing so
    -- but the shipped file no longer has any (problems 1, 2, 4 and 16 are
    fixed), and asserting that it does would re-break the moment it is rebuilt.
    So: assert the real file passes, and prove the detector works against a
    deliberately corrupted copy of it.
    """
    lab = Lab.from_bytes(decode_bytes(REAL_ARTEFACT.read_bytes(), "pkt").xml)
    leftovers = TemplateLeftovers.from_device_templates_json(TEMPLATES_JSON)
    report = validate_lab(lab, leftovers=leftovers)
    assert report.ok, [f.message for f in report.findings]
    assert not report.findings

    # corrupt a copy: duplicate one device's first AAA client record
    doc = decode_bytes(REAL_ARTEFACT.read_bytes(), "pkt").xml
    marker = b"<CLIENT>"
    at = doc.index(marker)
    end = doc.index(b"</CLIENT>", at) + len(b"</CLIENT>")
    corrupted = doc[:end] + doc[at:end] + doc[end:]
    bad_lab = Lab.from_bytes(corrupted)
    bad = validate_lab(bad_lab, leftovers=leftovers)
    assert not bad.ok
    codes = set(bad.codes())
    assert {"duplicate-aaa-client"} <= codes or {"template-leftovers"} <= codes


@needs_real
def test_real_artefact_needs_no_sanitising() -> None:
    """Sanitising the shipped artefact must be a no-op: the generator already
    stripped the template residue, so anything left to remove would mean the
    build regressed."""
    lab = Lab.from_bytes(decode_bytes(REAL_ARTEFACT.read_bytes(), "pkt").xml)
    leftovers = TemplateLeftovers.from_device_templates_json(TEMPLATES_JSON)
    report = sanitize_template_leftovers(lab, leftovers=leftovers)
    assert report.total == 0, report.as_dict()

    inv = inventory(lab, leftovers=leftovers)
    assert inv.aaa_clients.raw == 139 and inv.aaa_clients.unique
    assert inv.dhcp_pools.raw == 131 and inv.dhcp_pools.unique
    # DNS stays replicated: two servers, same 248 records
    assert inv.dns_records.raw == 496 and inv.dns_records.distinct == 248
    for family, count in inv.families.items():
        assert count.leftover_instances == 0, family
    # problem 16: pool *names* are unique too, so the validator finds nothing
    assert not validate_lab(lab, leftovers=leftovers).findings
    assert inv.dhcp_pools.authored_distinct == 131


# --------------------------------------------------------------------------- #
# 4. regression: the generator emits no duplicates after sanitising
# --------------------------------------------------------------------------- #
@needs_generator
def test_generator_emits_no_duplicates_and_honest_counts() -> None:
    """Run the generator (enterprise profile) and prove its output is clean.

    Uniqueness is asserted per family, except for `dns_records`: the two DNS
    servers legitimately hold the same 248 records, so 496 occurrences over 248
    identities is *correct*, not duplication.  Blanket-asserting uniqueness
    there would force someone to delete one server's zone.
    """
    out = Path(os.environ.get("TMPDIR", "/tmp")) / "pkt_audit_generator_out.pkt"
    env = dict(os.environ, PKT_TOOLKIT=str(REPO))
    proc = subprocess.run(
        [sys.executable, str(GENERATOR), "--profile", "enterprise",
         "--out", str(out), "--report", str(out.with_suffix(".json")),
         "--inventory", str(out.with_suffix(".csv"))],
        capture_output=True, text=True, env=env, timeout=600,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    lab = Lab.from_bytes(decode_bytes(out.read_bytes(), "pkt").xml)
    leftovers = TemplateLeftovers.from_device_templates_json(TEMPLATES_JSON)
    inv = inventory(lab, leftovers=leftovers)

    # Families where a repeated identity is a defect.  dns_records is excluded
    # by name and asserted separately below.
    replicated = {"dns_records"}
    for family, count in inv.families.items():
        assert count.leftover_instances == 0, family
        if family in replicated:
            continue
        assert count.unique, count.describe()

    # the one replicated family, pinned exactly
    assert inv.dns_records.raw == 496
    assert inv.dns_records.distinct == 248
    assert len(inv.dns_records_by_device) == 2

    # the authoritative statement: the validator finds nothing at all
    report = validate_lab(lab, leftovers=leftovers)
    assert report.ok, [f.message for f in report.findings]

    # pool names and scopes are globally unique (problem 16)
    names = [ident[0] for ident in inv.dhcp_pools.items]
    scopes = [ident[1:] for ident in inv.dhcp_pools.items]
    assert len(names) == len(set(names))
    assert len(scopes) == len(set(scopes))

    # per-server DNS zones are sets and replicate exactly.  Note the unpack:
    # dns_records_by_device yields (server_name, zone), and freezing the pair
    # would compare the server *names* too, which of course differ.
    assert len(inv.dns_records_by_device) == 2
    assert len({frozenset(zone) for _, zone in inv.dns_records_by_device}) == 1

    report = validate_lab(lab, leftovers=leftovers)
    assert report.ok, report.summary()

    # the numbers the docs must report
    assert inv.aaa_clients.raw == 139
    assert inv.dhcp_pools.raw == 131
    assert inv.dns_records.raw == 496
    assert inv.aaa_users.raw == 2
    assert inv.ftp_accounts.raw == 2


# --------------------------------------------------------------------------- #
# 5. CLI
# --------------------------------------------------------------------------- #
def test_pkt_audit_cli_reports_and_fails_on_duplicates(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = _doc(_server("a", clients=("10.1.1.1", "10.1.1.1")))
    container = tmp_path / "dup.pkt"
    container.write_bytes(encode_bytes(doc, "pkt"))
    rc = cli_main(["audit", str(container)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "duplicate-aaa-client" in out
    assert "FAILED" in out

    clean = _doc(_server("a", clients=("10.1.1.1",)))
    container.write_bytes(encode_bytes(clean, "pkt"))
    rc = cli_main(["audit", str(container), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["families"]["aaa_clients"]["raw"] == 1


def test_pkt_audit_cli_accepts_template_library(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    templates = tmp_path / "templates.json"
    encoded = __import__("base64").b64encode(
        __import__("gzip").compress(TEMPLATE_DEVICE.encode("utf-8"))
    ).decode("ascii")
    templates.write_text(json.dumps({"gz": True, "models": {"Server-PT": encoded}}))
    leftovers = TemplateLeftovers.from_device_templates_json(templates)
    assert leftovers.is_leftover("Server-PT", "aaa_clients", ("192.168.10.1",))

    doc = _doc(TEMPLATE_DEVICE.replace('translate="true">Server-PT', 'translate="true">srv'))
    container = tmp_path / "leftover.pkt"
    container.write_bytes(encode_bytes(doc, "pkt"))
    rc = cli_main(["audit", str(container), "--templates", str(templates)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "template-leftovers" in out
