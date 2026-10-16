"""Topology export to standard tooling formats.

These render the *model* (devices, ports, links) rather than the raw XML, so
they are inherently lossy with respect to Packet Tracer metadata — by design.
Round-tripping a lab is done with :mod:`pkt_core.codec`; exporting is for
interoperability.
"""

from __future__ import annotations

from typing import Callable, Iterable

from pkt_core.models import Device, Lab, Link

__all__ = [
    "EXPORTERS",
    "export",
    "to_graphviz",
    "to_netbox",
    "to_containerlab",
    "ExportError",
]


class ExportError(ValueError):
    """An unknown export format was requested."""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _yaml_key(value: str) -> str:
    """Make a device name safe as a YAML mapping key.

    Packet Tracer allows spaces and punctuation in device names
    (``"Power Distribution Device0"``); containerlab node names must be
    identifier-like.
    """
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in value)
    return cleaned.strip("-") or "unnamed"


def _nodes(lab: Lab) -> list[Device]:
    return lab.devices


def _edges(lab: Lab) -> list[Link]:
    return lab.links


def _endpoint_names(lab: Lab) -> dict[str, str]:
    """Map every endpoint identifier a cable may use onto a device name.

    Cables reference devices two ways: ``<FROM_DEVICE_MEM_ADDR>`` (reliably
    equal to the device's ``<DEV_ADDR>``) and ``<FROM>save-ref-id:...``. Only
    the former joins cleanly, so it is keyed first; the raw ``save-ref-id``
    strings are kept as a fallback so exported graphs never lose an edge
    silently.
    """
    names: dict[str, str] = {}
    for dev in _nodes(lab):
        if dev.dev_addr:
            names[dev.dev_addr] = dev.name
    for link in _edges(lab):
        cable = link.cable
        if cable is None:
            continue
        for addr, ref in (
            (cable.from_device_addr, cable.from_ref),
            (cable.to_device_addr, cable.to_ref),
        ):
            if addr and addr in names and ref:
                names.setdefault(ref, names[addr])
    return names


# --------------------------------------------------------------------------
# Graphviz
# --------------------------------------------------------------------------
def to_graphviz(lab: Lab, *, name: str = "topology") -> str:
    """Render the topology as a Graphviz DOT graph.

    Devices are nodes labelled ``name\\nkind model``; links are edges labelled
    with the two port names. Cable-less links (wireless) are drawn dashed.
    """
    lines: list[str] = [
        f'digraph "{_escape(name)}" {{',
        "  graph [rankdir=LR, splines=true];",
        "  node  [shape=box, style=rounded, fontname=\"Helvetica\"];",
        "  edge  [fontname=\"Helvetica\", fontsize=10];",
    ]
    key_of: dict[str, str] = {}
    for i, dev in enumerate(_nodes(lab)):
        key = f"d{i}"
        key_of[dev.name] = key
        label = f"{dev.name}\\n{dev.kind} {dev.model}".strip()
        lines.append(f'  {key} [label="{_escape(label)}"];')

    resolve = _endpoint_names(lab)
    for link in _edges(lab):
        refs = link.endpoints
        if refs is None:
            continue
        src = key_of.get(resolve.get(refs[0], ""), "")
        dst = key_of.get(resolve.get(refs[1], ""), "")
        if not src or not dst:
            continue
        ports = link.port_names
        label = " — ".join(ports) if ports else link.type
        style = "dashed" if not link.cable_type else "solid"
        lines.append(
            f'  {src} -> {dst} [dir=none, style={style}, label="{_escape(label)}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# NetBox
# --------------------------------------------------------------------------
def to_netbox(lab: Lab) -> str:
    """Render devices and interfaces as a NetBox-style JSON inventory.

    This is a plain inventory import, not a NetBox REST payload: device names,
    platforms, interface names, MACs and link peers. Cable-less links are
    omitted because NetBox has no peer to record.
    """
    import json

    devices: list[dict[str, object]] = []
    by_ref: dict[str, str] = {}
    for i, dev in enumerate(_nodes(lab)):
        by_ref[f"save-ref-id:{i}"] = dev.name
        devices.append(
            {
                "name": dev.name,
                "device_type": {"manufacturer": "Cisco", "model": dev.model},
                "device_role": dev.kind,
                "position": {"x": dev.position[0], "y": dev.position[1]},
                "cluster": dev.cluster_id or None,
                "interfaces": [
                    {
                        "name": f"iface{idx}",
                        "type": port.type,
                        "mac_address": port.mac_address or None,
                        "speed": port.bandwidth or None,
                        "enabled": port.full_duplex,
                    }
                    for idx, port in enumerate(dev.ports)
                ],
            }
        )

    resolve = _endpoint_names(lab)
    cables: list[dict[str, object]] = []
    for link in _edges(lab):
        refs = link.endpoints
        if refs is None:
            continue
        ports = link.port_names
        name_a = resolve.get(refs[0], refs[0])
        name_b = resolve.get(refs[1], refs[1])
        cables.append(
            {
                "type": link.cable_type or link.type,
                "a": {"device": name_a, "port": ports[0] if ports else None},
                "b": {"device": name_b, "port": ports[1] if len(ports) > 1 else None},
                "length": link.cable.length if link.cable else None,
            }
        )

    return json.dumps(
        {
            "format": "pkt-core/netbox-inventory",
            "lab": lab.summary(),
            "devices": devices,
            "cables": cables,
        },
        indent=2,
    ) + "\n"


# --------------------------------------------------------------------------
# containerlab
# --------------------------------------------------------------------------
def to_containerlab(lab: Lab, *, topology_name: str = "pkt") -> str:
    """Render the topology as a containerlab topology YAML stub.

    Containerlab runs containers, so this maps Packet Tracer devices onto
    placeholder kinds rather than inventing images. It is a starting point for
    a lab, not a runnable definition.
    """
    lines: list[str] = [
        "name: " + topology_name,
        "topology:",
        "  nodes:",
    ]
    for dev in _nodes(lab):
        kind = _yaml_key(dev.kind.lower()) or "unknown"
        lines.append(f"    {_yaml_key(dev.name)}:")
        lines.append(f"      kind: {kind}")
        lines.append(f"      # packet-tracer model: {dev.model}")
        if dev.position != (0.0, 0.0):
            lines.append(f"      # canvas position: {dev.position[0]:.0f},{dev.position[1]:.0f}")
    lines.append("  links:")
    resolve = _endpoint_names(lab)
    for link in _edges(lab):
        refs = link.endpoints
        if refs is None:
            continue
        ports = link.port_names
        name_a = resolve.get(refs[0], refs[0])
        name_b = resolve.get(refs[1], refs[1])
        a = f"{_yaml_key(name_a)}{':' + ports[0] if ports else ''}"
        b = f"{_yaml_key(name_b)}{':' + ports[1] if len(ports) > 1 else ''}"
        lines.append(f"    - endpoints: [{a}, {b}]")
    return "\n".join(lines) + "\n"


#: Registry used by the CLI.
EXPORTERS: dict[str, Callable[[Lab], str]] = {
    "graphviz": to_graphviz,
    "netbox": to_netbox,
    "containerlab": to_containerlab,
}


def export(lab: Lab, fmt: str) -> str:
    """Render ``lab`` in the named format.

    Raises:
        ExportError: if the format is not registered.
    """
    try:
        fn = EXPORTERS[fmt]
    except KeyError as exc:
        raise ExportError(
            f"unknown export format {fmt!r}; choose from {', '.join(sorted(EXPORTERS))}"
        ) from exc
    return fn(lab)
