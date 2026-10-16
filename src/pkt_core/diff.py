"""Semantic comparison of two Packet Tracer documents.

Text diffing the XML is nearly useless on these files: the documents are huge,
ordering is stable but incidental, and the interesting question is "what
changed in the network?". This module compares the *model* — devices, ports,
links, canvas placement and running config — and reports additions, removals
and changes by name.

Caveat, from the corpus: ``<LINE>`` running-config text carries raw control
characters (the Cisco ``banner motd ^C...^C`` delimiters), so config lines are
compared as :class:`bytes` and never decoded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pkt_core.models import Device, Lab, RunningConfig

__all__ = ["DeviceDiff", "LinkDiff", "ConfigDiff", "LabDiff", "diff_labs"]


@dataclass(slots=True)
class DeviceDiff:
    """How one device differs between two documents."""

    name: str
    added: bool = False
    removed: bool = False
    changes: dict[str, tuple[str, str]] = field(default_factory=dict)
    port_changes: dict[str, tuple[str, str]] = field(default_factory=dict)


@dataclass(slots=True)
class LinkDiff:
    """How one link differs between two documents."""

    identity: str
    added: bool = False
    removed: bool = False
    changes: dict[str, tuple[str, str]] = field(default_factory=dict)


@dataclass(slots=True)
class ConfigDiff:
    """Line-level change in a device's IOS running configuration."""

    device: str
    added: list[bytes] = field(default_factory=list)
    removed: list[bytes] = field(default_factory=list)


@dataclass(slots=True)
class LabDiff:
    """The complete semantic difference between two documents."""

    devices: list[DeviceDiff] = field(default_factory=list)
    links: list[LinkDiff] = field(default_factory=list)
    configs: list[ConfigDiff] = field(default_factory=list)
    meta_changes: dict[str, tuple[str, str]] = field(default_factory=dict)

    @property
    def identical(self) -> bool:
        return not (self.devices or self.links or self.configs or self.meta_changes)

    def summary_lines(self) -> list[str]:
        """Human-readable rendering, one line per difference."""
        out: list[str] = []
        for key, (a, b) in sorted(self.meta_changes.items()):
            out.append(f"~ {key}: {a!r} -> {b!r}")
        for d in self.devices:
            if d.added:
                out.append(f"+ device {d.name}")
                continue
            if d.removed:
                out.append(f"- device {d.name}")
                continue
            for k, (a, b) in sorted(d.changes.items()):
                out.append(f"~ device {d.name}.{k}: {a!r} -> {b!r}")
            for k, (a, b) in sorted(d.port_changes.items()):
                out.append(f"~ device {d.name}.port[{k}]: {a!r} -> {b!r}")
        for l in self.links:
            if l.added:
                out.append(f"+ link {l.identity}")
                continue
            if l.removed:
                out.append(f"- link {l.identity}")
                continue
            for k, (a, b) in sorted(l.changes.items()):
                out.append(f"~ link {l.identity}.{k}: {a!r} -> {b!r}")
        for c in self.configs:
            for line in c.added:
                out.append(f"+ config {c.device}: {line!r}")
            for line in c.removed:
                out.append(f"- config {c.device}: {line!r}")
        return out


def _device_fields(dev: Device) -> dict[str, str]:
    return {
        "kind": dev.kind,
        "model": dev.model,
        "powered": str(dev.powered),
        "description": dev.description,
        "x": f"{dev.position[0]:.0f}",
        "y": f"{dev.position[1]:.0f}",
        "cluster": dev.cluster_id,
    }


def _port_fields(dev: Device) -> dict[str, str]:
    out: dict[str, str] = {}
    for i, port in enumerate(dev.ports):
        out[f"{i}:{port.mac_address or port.type}"] = (
            f"{port.type} bw={port.bandwidth} duplex={port.full_duplex} mac={port.mac_address}"
        )
    return out


def _link_identity(endpoints: tuple[str, str] | None, ports: list[str]) -> str:
    if endpoints is None:
        return "(no endpoints)"
    a, b = endpoints
    pair = " | ".join(sorted(ports)) if ports else ""
    return f"{a} <-> {b} {pair}".strip()


def _config_for(dev: Device) -> list[bytes]:
    node = dev.element.find("ENGINE")
    if node is None:
        return []
    cfg = node.find("RUNNINGCONFIG")
    return RunningConfig.from_element(cfg).lines if cfg is not None else []


def diff_labs(a: Lab, b: Lab) -> LabDiff:
    """Compare two documents semantically.

    Devices and links are matched **by name / endpoint identity**, so a document
    reorder shows as no change.
    """
    result = LabDiff()

    for key in ("version",):
        va, vb = a.version, b.version
        if va != vb:
            result.meta_changes[key] = (va, vb)

    if a.is_activity != b.is_activity:
        result.meta_changes["is_activity"] = (str(a.is_activity), str(b.is_activity))

    a_devs = {d.name: d for d in a.devices}
    b_devs = {d.name: d for d in b.devices}

    for name in sorted(set(a_devs) | set(b_devs)):
        da, db = a_devs.get(name), b_devs.get(name)
        if db is None:
            result.devices.append(DeviceDiff(name=name, removed=True))
            continue
        if da is None:
            result.devices.append(DeviceDiff(name=name, added=True))
            continue
        changes = {
            k: (va, vb)
            for k, (va, vb) in (
                (k, (_device_fields(da)[k], _device_fields(db)[k]))
                for k in _device_fields(da)
            )
            if va != vb
        }
        pa, pb = _port_fields(da), _port_fields(db)
        port_changes = {
            k: (pa.get(k, ""), pb.get(k, ""))
            for k in sorted(set(pa) | set(pb))
            if pa.get(k) != pb.get(k)
        }
        if changes or port_changes:
            result.devices.append(
                DeviceDiff(name=name, changes=changes, port_changes=port_changes)
            )

    a_links: dict[str, LinkDiff] = {}
    for link in a.links:
        ident = _link_identity(link.endpoints, link.port_names)
        a_links[ident] = LinkDiff(
            identity=ident,
            changes={"type": (link.type, link.type), "cable": (link.cable_type, link.cable_type)},
        )
    b_links: dict[str, tuple[str, str]] = {}
    for link in b.links:
        ident = _link_identity(link.endpoints, link.port_names)
        b_links[ident] = (link.type, link.cable_type)

    for ident in sorted(set(a_links) | set(b_links)):
        if ident not in b_links:
            result.links.append(LinkDiff(identity=ident, removed=True))
        elif ident not in a_links:
            result.links.append(LinkDiff(identity=ident, added=True))
        else:
            atype = a_links[ident].changes["type"][0]
            acable = a_links[ident].changes["cable"][0]
            btype, bcable = b_links[ident]
            link_changes: dict[str, tuple[str, str]] = {}
            if atype != btype:
                link_changes["type"] = (atype, btype)
            if acable != bcable:
                link_changes["cable"] = (acable, bcable)
            if link_changes:
                result.links.append(LinkDiff(identity=ident, changes=link_changes))

    for name in sorted(set(a_devs) & set(b_devs)):
        ca, cb = _config_for(a_devs[name]), _config_for(b_devs[name])
        if ca == cb:
            continue
        sa, sb = set(ca), set(cb)
        added = [ln for ln in cb if ln not in sa]
        removed = [ln for ln in ca if ln not in sb]
        if added or removed:
            result.configs.append(ConfigDiff(device=name, added=added, removed=removed))

    return result
