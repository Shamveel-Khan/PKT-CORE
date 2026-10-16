# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Template-leftover sanitiser, service inventory and count validator.

Why this module exists
----------------------
Harvested device templates (``tools/device_templates.json``) are snapshots of
whatever lab they were taken from: a ``Server-PT`` template ships one AAA
client (``192.168.10.1``), two DHCP pools (``serverPool``), a ``user``/``cisco``
AAA account and a ``cisco`` FTP account.  A generator that instantiates the
template and authors *some* services inherits *all* of them.  Anything the
generator counts — AAA clients, DHCP pools, DNS records — is then inflated by
residue the generator never wrote, and a validator that only counts (and
asserts non-zero) prints ``PASSED`` on the inflated figures.

Three things fix that.  They live here rather than in :mod:`pkt_core.models`
because they are *policy* (what is residue, what must be distinct); the models
stay pure typed views:

1. :func:`sanitize_template_leftovers` / :func:`sanitize_engine` — strip
   unauthored leftovers from instantiated devices.
2. :func:`inventory` — a service inventory that reports raw *and* distinct
   counts per family, and how many instances are template leftovers.
3. :func:`validate_lab` — uniqueness proofs for every counted item.  Rule: *if
   a report prints a count, it must also prove those items are distinct*.

Determining "unauthored"
------------------------
Two explicit modes, no guessing:

* **Template-derived** (:class:`TemplateLeftovers`): identities carried by the
  model's harvested template.  Matching records are leftovers — safe to run
  *after* authoring, because authored records with the same identity would be
  indistinguishable (documented caveat).
* **Blank slate** (``leftovers=None``): every service record is removed.  Safe
  only *before* authoring, i.e. straight after instantiating a template.

Two XML trees, one implementation
---------------------------------
Generators in this project build documents with :mod:`xml.etree.ElementTree`
(``tools/lab_api``), while the typed model wraps :mod:`pkt_core.xml.nodes`.
The stripping core therefore runs over a minimal :class:`ElementView` protocol;
:func:`as_view` adapts either tree.  ``pkt_core`` callers keep the typed
entry points; a generator with an ``ElementTree`` document simply calls
:func:`sanitize_engine` on its ``<ENGINE>`` element.

Evidence for the leftover tables: decoding the 137 device templates of
``tools/device_templates.json`` shows record lists on 15 model families —
``ACS_CLIENTS``, ``USERS``, ``POOLS``/``ASSOCIATED_PORTS`` (DHCP),
``NAMESERVER-DATABASE``, ``USER_ACCOUNT_MNGR``, ``DHCP_POOL_LEASES``,
``DHCP_RESERVATIONS``, plus the home-router ``DHCP_SERVER`` pool — and
generators author only a subset of them.
"""

from __future__ import annotations

import base64
import gzip
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal, Mapping, Protocol, Sequence
from xml.etree.ElementTree import Element as StdlibElement

from pkt_core.models.lab import Lab
from pkt_core.models.network import Device
from pkt_core.models.services import (
    IDENTITY_FIELDS,
    IDENTITY_LABELS,
    ZONE_KEY_FIELDS,
    Identity,
    zone_identity,
)
from pkt_core.xml.nodes import XmlElement

__all__ = [
    "Identity",
    "ElementView",
    "as_view",
    "RecordFamily",
    "SERVICE_FAMILIES",
    "LeftoverRule",
    "DEFAULT_LEFTOVER_RULES",
    "TemplateLeftovers",
    "DedupCount",
    "ServiceInventory",
    "ConfigLineStats",
    "SanitizeReport",
    "Finding",
    "ValidationReport",
    "inventory",
    "sanitize_engine",
    "sanitize_template_leftovers",
    "sanitize_xml",
    "strip_service_records",
    "validate_lab",
]


# --------------------------------------------------------------------------- #
# element views -- one core over two XML trees
# --------------------------------------------------------------------------- #
class ElementView(Protocol):
    """Structural view of one XML element, satisfied by both tree flavours."""

    @property
    def tag(self) -> str: ...

    def child(self, name: str) -> "ElementView | None": ...

    def text_of(self, name: str) -> str: ...

    def element_children(self) -> list["ElementView"]: ...

    def descendants(self) -> Iterator["ElementView"]: ...

    def remove(self, child: "ElementView") -> None: ...


class XmlElementView:
    """Adapter over :class:`pkt_core.xml.nodes.XmlElement`."""

    __slots__ = ("el",)

    def __init__(self, el: XmlElement) -> None:
        self.el = el

    @property
    def tag(self) -> str:
        return self.el.tag

    def child(self, name: str) -> ElementView | None:
        found = self.el.find(name)
        return XmlElementView(found) if found is not None else None

    def text_of(self, name: str) -> str:
        found = self.el.find(name)
        return found.text.strip() if found is not None else ""

    def element_children(self) -> list[ElementView]:
        return [XmlElementView(c) for c in self.el.children if isinstance(c, XmlElement)]

    def descendants(self) -> Iterator[ElementView]:
        return (XmlElementView(e) for e in self.el.iter_elements())

    def remove(self, child: ElementView) -> None:
        if not isinstance(child, XmlElementView):
            raise TypeError("child does not belong to this tree")
        self.el.remove(child.el)


class StdlibElementView:
    """Adapter over :class:`xml.etree.ElementTree.Element`."""

    __slots__ = ("el",)

    def __init__(self, el: StdlibElement) -> None:
        self.el = el

    @property
    def tag(self) -> str:
        return str(self.el.tag)

    def child(self, name: str) -> ElementView | None:
        found = self.el.find(name)
        return StdlibElementView(found) if found is not None else None

    def text_of(self, name: str) -> str:
        found = self.el.find(name)
        return (found.text or "").strip() if found is not None else ""

    def element_children(self) -> list[ElementView]:
        return [StdlibElementView(c) for c in list(self.el)]

    def descendants(self) -> Iterator[ElementView]:
        return (StdlibElementView(c) for c in self.el.iter() if c is not self.el)

    def remove(self, child: ElementView) -> None:
        if not isinstance(child, StdlibElementView):
            raise TypeError("child does not belong to this tree")
        self.el.remove(child.el)


def as_view(el: XmlElement | StdlibElement | ElementView) -> ElementView:
    """Adapt a pkt_core element, a stdlib ElementTree element, or a view."""
    if isinstance(el, (XmlElementView, StdlibElementView)):
        return el
    if isinstance(el, XmlElement):
        return XmlElementView(el)
    if isinstance(el, StdlibElement):
        return StdlibElementView(el)
    return el


# --------------------------------------------------------------------------- #
# service families
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RecordFamily:
    """One counted service record list under a device's ``<ENGINE>``.

    ``name`` is the inventory's field name, ``container``/``record`` locate the
    records in the XML tree (``record="*"`` matches every element child).
    """

    name: str
    container: str
    record: str


#: The service families this module inventories and proves unique.
SERVICE_FAMILIES: tuple[RecordFamily, ...] = (
    RecordFamily("aaa_clients", "ACS_CLIENTS", "CLIENT"),
    RecordFamily("aaa_users", "USERS", "USER"),
    RecordFamily("dhcp_pools", "POOLS", "POOL"),
    RecordFamily("dns_records", "NAMESERVER-DATABASE", "RESOURCE-RECORD"),
    RecordFamily("ftp_accounts", "USER_ACCOUNT_MNGR", "ACCOUNT"),
)

_FAMILY_BY_NAME: Mapping[str, RecordFamily] = {f.name: f for f in SERVICE_FAMILIES}


def _record_identity(family: str, record: ElementView) -> Identity:
    """The identity tuple Packet Tracer keys this record on.

    Field lists come from :data:`pkt_core.models.services.IDENTITY_FIELDS`, the
    same table the typed views' ``identity`` properties use — one rule, no drift.
    """
    try:
        fields = IDENTITY_FIELDS[family]
    except KeyError:
        raise ValueError(f"unknown service family {family!r}") from None
    return tuple(record.text_of(tag) for tag in fields)


def format_identity(identity: Identity) -> str:
    """Render an identity tuple for humans and finding messages."""
    return " / ".join(part for part in identity) or "<empty>"


def _service_records(engine: ElementView, family: RecordFamily) -> list[ElementView]:
    out: list[ElementView] = []
    for container in engine.descendants():
        if container.tag != family.container:
            continue
        if family.record == "*":
            out.extend(container.element_children())
        else:
            out.extend(c for c in container.element_children() if c.tag == family.record)
    return out


def _engine_views(el: XmlElement | StdlibElement | ElementView) -> list[tuple[str, ElementView]]:
    """Resolve a DEVICE/ENGINE element to ``(model, engine view)`` pairs."""
    view = as_view(el)
    if view.tag == "ENGINE":
        return [("", view)]  # model unknown at this level; pass model= explicitly
    engine = view.child("ENGINE")
    if engine is None:
        return []
    model = ""
    type_view = engine.child("TYPE")
    if type_view is not None:
        raw = type_view if isinstance(type_view, (XmlElementView, StdlibElementView)) else None
        if raw is not None:
            model = raw.el.get("model") or ""  # attribute access is tree-specific
    return [(model, engine)]


# --------------------------------------------------------------------------- #
# template leftovers
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LeftoverRule:
    """One record list that harvested templates carry and generators do not author.

    ``container`` is matched against every element under ``<ENGINE>``;
    ``record`` names the records inside it (``"*"`` removes all element
    children).  ``label`` names the rule in :class:`SanitizeReport`.
    """

    container: str
    record: str
    label: str


#: Service record lists stripped from instantiated templates.
#:
#: Derived by diffing the service blocks of ``tools/device_templates.json``
#: against what generators write (see the module docstring).  Runtime state
#: (``DHCP_POOL_LEASES``, ``DHCP_RESERVATIONS``) is included because a
#: generator never authors it: a lease table from the donor lab is always
#: residue.
DEFAULT_LEFTOVER_RULES: tuple[LeftoverRule, ...] = (
    LeftoverRule("ACS_CLIENTS", "CLIENT", "aaa-clients"),
    LeftoverRule("USERS", "USER", "aaa-users"),
    LeftoverRule("POOLS", "POOL", "dhcp-pools"),
    LeftoverRule("ASSOCIATED_PORTS", "ASSOCIATED_PORT", "dhcp-port-bindings"),
    LeftoverRule("NAMESERVER-DATABASE", "RESOURCE-RECORD", "dns-records"),
    LeftoverRule("USER_ACCOUNT_MNGR", "ACCOUNT", "ftp-accounts"),
    LeftoverRule("DHCP_POOL_LEASES", "*", "dhcp-leases"),
    LeftoverRule("DHCP_RESERVATIONS", "*", "dhcp-reservations"),
)

#: Rules that remove *runtime* state unconditionally, even in template-derived
#: mode: nothing ever authors a lease or a reservation at generation time.
_RUNTIME_RULES: tuple[LeftoverRule, ...] = tuple(
    r for r in DEFAULT_LEFTOVER_RULES if r.label in ("dhcp-leases", "dhcp-reservations")
)


@dataclass(frozen=True)
class TemplateLeftovers:
    """Identities carried by harvested device templates, per device model.

    Build with :meth:`from_templates` from the template library a generator
    already holds.  Matching is by *identity* (never by full record): Packet
    Tracer rewrites record bodies when it re-saves a file — it adds
    ``LEASE_TIME``/``DOMAIN_NAME``/``WLC_ADDRESS`` to DHCP pools — so exact
    record matching silently misses the very leftovers this class exists to
    remove.
    """

    by_model: Mapping[str, Mapping[str, frozenset[Identity]]] = field(default_factory=dict)

    @classmethod
    def empty(cls) -> "TemplateLeftovers":
        """No known leftovers: nothing is classified as residue."""
        return cls({})

    @classmethod
    def from_templates(cls, templates: Mapping[str, bytes | str]) -> "TemplateLeftovers":
        """Fingerprint the service records of harvested ``<DEVICE>`` templates.

        ``templates`` maps device model name to the template's ``<DEVICE>`` XML
        (as ``tools/device_templates.json`` and ``lab_api.load_templates()``
        produce it).
        """
        by_model: dict[str, dict[str, frozenset[Identity]]] = {}
        for model, blob in templates.items():
            root = as_view(_parse_fragment(blob))
            engine = root.child("ENGINE") if root.tag != "ENGINE" else root
            if engine is None:
                continue
            per_family: dict[str, frozenset[Identity]] = {}
            for family in SERVICE_FAMILIES:
                ids = frozenset(
                    _record_identity(family.name, rec)
                    for rec in _service_records(engine, family)
                )
                if ids:
                    per_family[family.name] = ids
            if per_family:
                by_model[model] = per_family
        return cls(by_model)

    @classmethod
    def from_device_templates_json(cls, path: str | Path) -> "TemplateLeftovers":
        """Load the shipped ``tools/device_templates.json`` template library.

        Handles its gzip+base64 encoding (the same one
        ``tools/lab_api.load_templates`` reads).
        """
        doc = json.loads(Path(path).read_text(encoding="utf-8"))

        def decode(value: str) -> bytes:
            raw = base64.b64decode(value)
            return gzip.decompress(raw) if doc.get("gz") else raw

        models: dict[str, bytes] = {k: decode(v) for k, v in doc["models"].items()}
        return cls.from_templates(models)

    def for_model(self, model: str) -> Mapping[str, frozenset[Identity]]:
        """Leftover identities of one device model (empty when unknown)."""
        return self.by_model.get(model, {})

    def is_leftover(self, model: str, family: str, identity: Identity) -> bool:
        return identity in self.for_model(model).get(family, frozenset())


def _parse_fragment(blob: bytes | str) -> XmlElement:
    from pkt_core.xml.nodes import parse_xml_bytes

    data = blob.encode("utf-8") if isinstance(blob, str) else blob
    return parse_xml_bytes(data).root


# --------------------------------------------------------------------------- #
# counting
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DedupCount:
    """Occurrence accounting for one counted family.

    ``items`` holds one identity per *instance* found; ``leftover_identities``
    are the identities a harvested template carries (empty when no template
    library was supplied).  Everything else is derived, so the raw and distinct
    figures can never disagree with the item list.
    """

    family: str
    items: tuple[Identity, ...] = ()
    leftover_identities: frozenset[Identity] = frozenset()

    @property
    def raw(self) -> int:
        """Instances found — the figure a naive counter reports."""
        return len(self.items)

    @property
    def occurrences(self) -> dict[Identity, int]:
        out: dict[Identity, int] = {}
        for item in self.items:
            out[item] = out.get(item, 0) + 1
        return out

    @property
    def distinct(self) -> int:
        """Distinct identities among all instances."""
        return len(self.occurrences)

    @property
    def duplicate_instances(self) -> int:
        """Instances beyond the first of their identity (the inflation)."""
        return self.raw - self.distinct

    @property
    def duplicates(self) -> dict[Identity, int]:
        """Identity -> occurrence count, for identities seen more than once."""
        return {k: n for k, n in self.occurrences.items() if n > 1}

    @property
    def unique(self) -> bool:
        """True when every instance is distinct (raw == distinct)."""
        return self.duplicate_instances == 0

    @property
    def leftover_instances(self) -> int:
        """Instances whose identity is carried by the device template."""
        return sum(1 for item in self.items if item in self.leftover_identities)

    @property
    def authored_instances(self) -> int:
        """Instances that are not template leftovers."""
        return self.raw - self.leftover_instances

    @property
    def authored(self) -> tuple[Identity, ...]:
        return tuple(i for i in self.items if i not in self.leftover_identities)

    @property
    def authored_distinct(self) -> int:
        """Distinct identities among the non-leftover instances."""
        return len(set(self.authored))

    def describe(self) -> str:
        """One honest line: raw, distinct, duplicates, leftovers."""
        parts = [f"{self.raw} raw", f"{self.distinct} distinct"]
        if self.duplicate_instances:
            worst = max(self.duplicates.items(), key=lambda kv: kv[1])
            parts.append(
                f"{self.duplicate_instances} duplicate instances "
                f"(e.g. {format_identity(worst[0])} x{worst[1]})"
            )
        if self.leftover_instances:
            parts.append(
                f"{self.leftover_instances} template leftovers -> "
                f"{self.authored_instances} authored ({self.authored_distinct} distinct)"
            )
        return f"{self.family}: " + ", ".join(parts)

    def as_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "raw": self.raw,
            "distinct": self.distinct,
            "duplicate_instances": self.duplicate_instances,
            "duplicates": {
                format_identity(k): n for k, n in sorted(self.duplicates.items())
            },
            "leftover_instances": self.leftover_instances,
            "authored": self.authored_instances,
            "authored_distinct": self.authored_distinct,
        }


#: Chassis models that run IOS or ASA and are expected to carry a config.
#: Kept in step with the allow-list in ``generators/jasdf_aewc/validate.py`` so
#: the two tools cannot report the same statistic from different definitions.
NETWORK_DEVICE_MODELS: frozenset[str] = frozenset({
    "2911", "ISR4331", "ISR4321", "IR1101", "3650-24PS",
    "3560-24PS", "2960-24TT", "IE-9320", "5505",
})


@dataclass(frozen=True)
class ConfigLineStats:
    """Reproducible configuration-line counts (problem 17).

    Two figures, both defined on ``<LINE>`` elements of ``<RUNNINGCONFIG>``:

    * ``total_lines`` — every ``<RUNNINGCONFIG>`` block, including the short
      stubs some server appliances carry (``!`` / comment / ``end``).
    * ``ios_lines`` — blocks of *network devices* (routers, switches, ASAs),
      selected by :data:`NETWORK_DEVICE_MODELS`.  This is the "configuration
      lines" figure the design documents quote, and it is reproducible with
      ``pkt audit <file.pkt>``.
    """

    blocks: int = 0
    total_lines: int = 0
    ios_blocks: int = 0
    ios_lines: int = 0
    min_lines: int = 0
    median_lines: int = 0
    max_lines: int = 0

    def describe(self) -> str:
        return (
            f"config lines  : min={self.min_lines} median={self.median_lines} "
            f"max={self.max_lines} total={self.ios_lines:,} "
            f"({self.ios_blocks} IOS/ASA devices, by model); "
            f"{self.total_lines:,} <LINE> elements in {self.blocks} RUNNINGCONFIG blocks"
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "blocks": self.blocks,
            "total_lines": self.total_lines,
            "ios_blocks": self.ios_blocks,
            "ios_lines": self.ios_lines,
            "min_lines": self.min_lines,
            "median_lines": self.median_lines,
            "max_lines": self.max_lines,
        }


@dataclass(frozen=True)
class ServiceInventory:
    """Raw and distinct counts for every counted item of a lab.

    The two non-service families (``device_names``, ``end_device_ips``) are
    included because the validator has always proved them unique; keeping them
    here makes "counted => proven distinct" one uniform rule.
    """

    device_names: DedupCount
    end_device_ips: DedupCount
    aaa_clients: DedupCount
    aaa_users: DedupCount
    dhcp_pools: DedupCount
    dns_records: DedupCount
    ftp_accounts: DedupCount
    config_lines: ConfigLineStats
    #: ``(device name, zone identities)`` per DNS server — zones are sets.
    dns_records_by_device: tuple[tuple[str, tuple[Identity, ...]], ...] = ()

    def count(self, family: str) -> DedupCount:
        """Look a family up by name (``aaa_clients``, ``dhcp_pools``, ...)."""
        try:
            return self.families[family]
        except KeyError:
            raise KeyError(f"unknown counted family {family!r}") from None

    @property
    def families(self) -> dict[str, DedupCount]:
        return {
            "device_names": self.device_names,
            "end_device_ips": self.end_device_ips,
            "aaa_clients": self.aaa_clients,
            "aaa_users": self.aaa_users,
            "dhcp_pools": self.dhcp_pools,
            "dns_records": self.dns_records,
            "ftp_accounts": self.ftp_accounts,
        }

    def summary(self) -> str:
        """Multi-line honest report — the text a design document should quote."""
        dns = self.dns_records
        servers = len(self.dns_records_by_device) or 1
        lines = [
            self.device_names.describe(),
            self.end_device_ips.describe(),
            self.config_lines.describe(),
            f"services      : {dns.raw} DNS records ({dns.distinct} distinct x {servers} servers)",
        ]
        for family in ("aaa_clients", "dhcp_pools", "aaa_users", "ftp_accounts"):
            count = self.families[family]
            if count.raw:
                lines.append("  " + count.describe())
        return "\n".join(lines)

    def as_dict(self) -> dict[str, object]:
        return {
            "families": {name: c.as_dict() for name, c in self.families.items()},
            "config_lines": self.config_lines.as_dict(),
        }


def _port_ips(dev: Device) -> list[str]:
    out: list[str] = []
    engine = dev.engine
    if engine is None:
        return out
    for port in engine.iter_elements():
        if port.tag != "PORT":
            continue
        ip = port.find("IP")
        value = ip.text.strip() if ip is not None else ""
        if value and value != "0.0.0.0":
            out.append(value)
    return out


def _config_line_stats(devices: Sequence[Device]) -> ConfigLineStats:
    """Split config lines into "all blocks" and "network devices".

    A device counts as an IOS/ASA device by its **model**, not by whether it
    happens to carry a `<STARTUPCONFIG>` element.  The element was the old
    proxy and it was wrong in both directions: 123 of the 290 devices in the
    JASDF model carried an *empty* one and were counted as configured, while
    the only 20 with content were the ones holding factory-default residue
    (`hostname Router`, `hostname ciscoasa`), so the figure described precisely
    the devices that were wrong.

    The allow-list matches `generators/jasdf_aewc/validate.py`, which counts the
    same population for its "configured devices" check.  Two tools reporting the
    same statistic from different definitions is how a number becomes
    unfalsifiable; both now key off :data:`NETWORK_DEVICE_MODELS`.
    """
    blocks = total = ios_blocks = ios_lines = 0
    per_ios: list[int] = []
    for dev in devices:
        engine = dev.engine
        if engine is None:
            continue
        rc = engine.find("RUNNINGCONFIG")
        if rc is None:
            continue
        n = len(rc.find_all("LINE"))
        blocks += 1
        total += n
        if dev.model in NETWORK_DEVICE_MODELS:
            ios_blocks += 1
            ios_lines += n
            per_ios.append(n)
    if not per_ios:
        return ConfigLineStats(blocks=blocks, total_lines=total)
    ordered = sorted(per_ios)
    return ConfigLineStats(
        blocks=blocks,
        total_lines=total,
        ios_blocks=ios_blocks,
        ios_lines=ios_lines,
        min_lines=ordered[0],
        median_lines=ordered[len(ordered) // 2],
        max_lines=ordered[-1],
    )


def inventory(
    lab: Lab, *, leftovers: TemplateLeftovers | None = None
) -> ServiceInventory:
    """Count every service record and prove what is distinct.

    ``leftovers`` (from :meth:`TemplateLeftovers.from_templates`) additionally
    classifies instances as template residue, which is what separates "259 DHCP
    pools found" from "131 pools the generator authored".
    """
    template = leftovers or TemplateLeftovers.empty()
    names: list[Identity] = []
    ips: list[Identity] = []
    families: dict[str, list[tuple[str, Identity]]] = {f.name: [] for f in SERVICE_FAMILIES}
    dns_by_device: list[tuple[str, tuple[Identity, ...]]] = []

    devices = lab.devices
    for dev in devices:
        names.append((dev.name,))
        ips.extend((ip,) for ip in _port_ips(dev))
        engine = dev.engine
        if engine is None:
            continue
        model = dev.model
        view = XmlElementView(engine)
        for family in SERVICE_FAMILIES:
            for rec in _service_records(view, family):
                families[family.name].append((model, _record_identity(family.name, rec)))
        if engine.find("DNS_SERVER") is not None:
            zone = tuple(
                zone_identity(_record_identity("dns_records", rec))
                for rec in _service_records(view, _FAMILY_BY_NAME["dns_records"])
            )
            # Only devices that actually hold records count as DNS servers:
            # templates ship <DNS_SERVER><ENABLED>1</ENABLED> on appliances that
            # serve no zone at all, and those empty shells are not replicas.
            if zone:
                dns_by_device.append((dev.name, zone))

    def dedup(family: str, pairs: Iterable[tuple[str, Identity]]) -> DedupCount:
        entries = tuple(ident for _, ident in pairs)
        leftover_ids = frozenset(
            ident for model, ident in pairs if template.is_leftover(model, family, ident)
        )
        return DedupCount(family=family, items=entries, leftover_identities=leftover_ids)

    return ServiceInventory(
        device_names=DedupCount("device_names", tuple(names)),
        end_device_ips=DedupCount("end_device_ips", tuple(ips)),
        aaa_clients=dedup("aaa_clients", families["aaa_clients"]),
        aaa_users=dedup("aaa_users", families["aaa_users"]),
        dhcp_pools=dedup("dhcp_pools", families["dhcp_pools"]),
        dns_records=dedup("dns_records", families["dns_records"]),
        ftp_accounts=dedup("ftp_accounts", families["ftp_accounts"]),
        config_lines=_config_line_stats(devices),
        dns_records_by_device=tuple(dns_by_device),
    )


# --------------------------------------------------------------------------- #
# sanitiser
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SanitizeReport:
    """What a sanitiser removed, per rule label."""

    removed: Mapping[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.removed.values())

    def as_dict(self) -> dict[str, int]:
        return dict(self.removed)

    def describe(self) -> str:
        if not self.total:
            return "no template leftovers found"
        return ", ".join(f"{n} {label}" for label, n in sorted(self.removed.items()))

    def merge(self, other: "SanitizeReport") -> "SanitizeReport":
        out = dict(self.removed)
        for label, n in other.removed.items():
            out[label] = out.get(label, 0) + n
        return SanitizeReport(out)


def _strip_by_rules(engine: ElementView, rules: Iterable[LeftoverRule]) -> dict[str, int]:
    removed: dict[str, int] = {}
    for rule in rules:
        n = 0
        for container in list(engine.descendants()):
            if container.tag != rule.container:
                continue
            victims = (
                container.element_children()
                if rule.record == "*"
                else [c for c in container.element_children() if c.tag == rule.record]
            )
            for victim in victims:
                container.remove(victim)
                n += 1
        if n:
            removed[rule.label] = removed.get(rule.label, 0) + n
    return removed


def _parent_of(root: ElementView, target: ElementView) -> ElementView | None:
    for el in root.descendants():
        for child in el.element_children():
            if child is target or (
                isinstance(child, (XmlElementView, StdlibElementView))
                and isinstance(target, (XmlElementView, StdlibElementView))
                and child.el is target.el
            ):
                return el
    return None


def _strip_leftover_records(
    engine: ElementView, model: str, template: TemplateLeftovers
) -> dict[str, int]:
    removed: dict[str, int] = {}
    for family in SERVICE_FAMILIES:
        known = template.for_model(model).get(family.name, frozenset())
        if not known:
            continue
        n = 0
        for rec in _service_records(engine, family):
            if _record_identity(family.name, rec) not in known:
                continue
            parent = _parent_of(engine, rec)
            if parent is not None:
                parent.remove(rec)
                n += 1
        if n:
            removed[family.name.replace("_", "-")] = n
    # a DHCP port binding whose pools are all gone is itself a leftover shell
    for binding in list(engine.descendants()):
        if binding.tag != "ASSOCIATED_PORT":
            continue
        if not _service_records(binding, _FAMILY_BY_NAME["dhcp_pools"]):
            parent = _parent_of(engine, binding)
            if parent is not None:
                parent.remove(binding)
                removed["dhcp-port-bindings"] = removed.get("dhcp-port-bindings", 0) + 1
    # runtime state is never authored at generation time
    for rule in _RUNTIME_RULES:
        for label, n in _strip_by_rules(engine, (rule,)).items():
            removed[label] = removed.get(label, 0) + n
    return removed


def sanitize_engine(
    engine: XmlElement | StdlibElement | ElementView,
    *,
    model: str = "",
    leftovers: TemplateLeftovers | None = None,
    rules: Sequence[LeftoverRule] = DEFAULT_LEFTOVER_RULES,
) -> SanitizeReport:
    """Strip template leftovers from one ``<ENGINE>`` (or ``<DEVICE>``) element.

    Accepts either XML tree — the typed ``pkt_core`` tree or a plain
    :mod:`xml.etree.ElementTree` document, which is what generators build.

    With ``leftovers`` only records whose identity is carried by ``model``'s
    template are removed — safe after authoring.  With ``leftovers=None``
    *every* service record is removed — safe only before authoring.

    ``model`` is the device model name (``<TYPE model="...">``); it selects the
    right leftover fingerprints and may be omitted when ``leftovers`` is None.
    """
    view = as_view(engine)
    if view.tag != "ENGINE":
        resolved = _engine_views(view)
        if not resolved:
            return SanitizeReport()
        found_model, view = resolved[0]
        model = model or found_model
    if leftovers is None:
        return SanitizeReport(_strip_by_rules(view, rules))
    return SanitizeReport(_strip_leftover_records(view, model, leftovers))


def strip_service_records(
    target: Lab | Device | XmlElement | StdlibElement,
    *,
    rules: Sequence[LeftoverRule] = DEFAULT_LEFTOVER_RULES,
) -> SanitizeReport:
    """Remove *every* service record from device(s) — a blank slate.

    Use immediately after instantiating a harvested template, **before**
    authoring services; afterwards it would delete authored records too.
    """
    return sanitize_template_leftovers(target, leftovers=None, rules=rules)


def sanitize_template_leftovers(
    target: Lab | Device | XmlElement | StdlibElement,
    *,
    leftovers: TemplateLeftovers | None = None,
    rules: Sequence[LeftoverRule] = DEFAULT_LEFTOVER_RULES,
) -> SanitizeReport:
    """Strip unauthored template leftovers from a lab, a device, or one element.

    With ``leftovers`` (built from the generator's own template library) only
    records whose identity is carried by the device's template are removed —
    safe to run after authoring.  With ``leftovers=None`` every service record
    is removed (:func:`strip_service_records`) — safe only before authoring.

    Runtime lease/reservation state is removed in both modes: a generator never
    authors it, so it is always residue.
    """
    entries: list[tuple[str, ElementView]] = []
    if isinstance(target, Lab):
        for dev in target.devices:
            engine = dev.engine
            if engine is not None:
                entries.append((dev.model, XmlElementView(engine)))
    elif isinstance(target, Device):
        dev_engine = target.engine
        if dev_engine is not None:
            entries.append((target.model, XmlElementView(dev_engine)))
    else:
        entries = _engine_views(target)

    report = SanitizeReport()
    for model, engine_view in entries:
        report = report.merge(
            sanitize_engine(engine_view, model=model, leftovers=leftovers, rules=rules)
        )
    return report


def sanitize_xml(
    xml: bytes, *, leftovers: TemplateLeftovers | None = None
) -> tuple[bytes, SanitizeReport]:
    """Sanitise a whole document's XML bytes; returns ``(new xml, report)``.

    The convenience entry point for callers that hold a serialised document.
    Untouched parts of the document stay byte-identical.
    """
    lab = Lab.from_bytes(xml)
    report = sanitize_template_leftovers(lab, leftovers=leftovers)
    return lab.to_xml(), report


# --------------------------------------------------------------------------- #
# validator
# --------------------------------------------------------------------------- #
Severity = Literal["fail", "warn"]


@dataclass(frozen=True)
class Finding:
    """One validation result.  ``code`` is stable; ``message`` is for humans."""

    severity: Severity
    code: str
    message: str


@dataclass(frozen=True)
class ValidationReport:
    """Findings plus the inventory they were derived from."""

    findings: tuple[Finding, ...]
    inventory: ServiceInventory

    @property
    def failures(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "fail")

    @property
    def warnings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "warn")

    @property
    def ok(self) -> bool:
        return not self.failures

    def codes(self) -> tuple[str, ...]:
        return tuple(f.code for f in self.findings)

    def summary(self) -> str:
        lines = [self.inventory.summary()]
        for finding in self.findings:
            tag = "FAIL" if finding.severity == "fail" else "WARN"
            lines.append(f"  {tag}  {finding.code}: {finding.message}")
        verdict = "PASSED" if self.ok else "FAILED"
        lines.append(
            f"RESULT: {verdict} ({len(self.failures)} failures, {len(self.warnings)} warnings)"
        )
        return "\n".join(lines)


def _find_duplicates(count: DedupCount, code: str, what: str) -> list[Finding]:
    out: list[Finding] = []
    for identity, n in sorted(count.duplicates.items(), key=lambda kv: (-kv[1], kv[0])):
        out.append(
            Finding(
                "fail",
                code,
                f"{what} {format_identity(identity)} occurs {n} times "
                f"({count.raw} {count.family} counted, only {count.distinct} distinct)",
            )
        )
    return out


def validate_lab(
    lab: Lab, *, leftovers: TemplateLeftovers | None = None
) -> ValidationReport:
    """Prove every counted item distinct (and free of template leftovers).

    Rules, all failing the report when violated:

    * ``duplicate-device-name`` / ``duplicate-end-device-ip`` — the pre-existing
      topology checks (end-device IPs stay a warning, as before).
    * ``duplicate-aaa-client`` / ``duplicate-aaa-user`` / ``duplicate-ftp-account``
      — document-wide, because the reported counts are document-wide sums.
    * ``duplicate-dhcp-pool`` — ``(name, network, mask)`` identities.
    * ``duplicate-dhcp-pool-name`` — pool names are name-keyed in Packet Tracer
      and must be globally unique (one ``IRUMA-VLAN10`` cannot serve two sites).
    * ``duplicate-dhcp-pool-scope`` — no two pools may serve the same
      ``(network, mask)``.
    * ``duplicate-dns-record`` — per server: a DNS zone is a set, so
      ``(type, name)`` must be unique *within* each server.  Replication across
      servers is legitimate (``248 names x 2 servers = 496``) and is reported as
      such; ``dns-zone-divergence`` warns when servers hold different sets.
    * ``template-leftovers`` — residue a harvested template carried is still in
      the file, inflating every count above.
    """
    inv = inventory(lab, leftovers=leftovers)
    findings: list[Finding] = []

    if not inv.device_names.unique:
        findings.extend(
            _find_duplicates(inv.device_names, "duplicate-device-name", "device name")
        )
    if not inv.end_device_ips.unique:
        findings.append(
            Finding(
                "warn",
                "duplicate-end-device-ip",
                f"{inv.end_device_ips.duplicate_instances} duplicated end-device IPs "
                f"({inv.end_device_ips.raw} addresses, {inv.end_device_ips.distinct} distinct)",
            )
        )

    findings.extend(_find_duplicates(inv.aaa_clients, "duplicate-aaa-client", "AAA client"))
    findings.extend(_find_duplicates(inv.aaa_users, "duplicate-aaa-user", "AAA user"))
    findings.extend(_find_duplicates(inv.ftp_accounts, "duplicate-ftp-account", "FTP account"))
    findings.extend(_find_duplicates(inv.dhcp_pools, "duplicate-dhcp-pool", "DHCP pool"))

    pool_names: dict[str, int] = {}
    pool_scopes: dict[str, int] = {}
    for identity in inv.dhcp_pools.items:
        name = identity[0]
        scope = format_identity(identity[1:])
        pool_names[name] = pool_names.get(name, 0) + 1
        pool_scopes[scope] = pool_scopes.get(scope, 0) + 1
    for name, n in sorted(pool_names.items()):
        if n > 1:
            findings.append(
                Finding(
                    "fail",
                    "duplicate-dhcp-pool-name",
                    f"pool name {name!r} is used by {n} pools "
                    f"(PT pools are name-keyed: one name must serve one pool)",
                )
            )
    for scope, n in sorted(pool_scopes.items()):
        if n > 1:
            findings.append(
                Finding(
                    "fail",
                    "duplicate-dhcp-pool-scope",
                    f"network/mask {scope} is served by {n} pools",
                )
            )

    zone_sets: list[frozenset[Identity]] = []
    for device_name, zone in inv.dns_records_by_device:
        seen: dict[Identity, int] = {}
        for key in zone:
            seen[key] = seen.get(key, 0) + 1
        for key, n in sorted(seen.items()):
            if n > 1:
                findings.append(
                    Finding(
                        "fail",
                        "duplicate-dns-record",
                        f"DNS record {format_identity(key)} occurs {n} times on {device_name}",
                    )
                )
        zone_sets.append(frozenset(zone))
    if len(zone_sets) > 1 and any(z != zone_sets[0] for z in zone_sets[1:]):
        findings.append(
            Finding(
                "warn",
                "dns-zone-divergence",
                "DNS servers hold different record sets; the reported count is "
                "not explainable as names x servers",
            )
        )

    for family, count in sorted(inv.families.items()):
        if count.leftover_instances:
            examples = sorted(
                {format_identity(i) for i in count.items if i in count.leftover_identities}
            )
            findings.append(
                Finding(
                    "fail",
                    "template-leftovers",
                    f"{count.leftover_instances} {family} records are template leftovers "
                    f"(e.g. {examples[0]}); they were never authored and inflate the count",
                )
            )

    return ValidationReport(tuple(findings), inv)
