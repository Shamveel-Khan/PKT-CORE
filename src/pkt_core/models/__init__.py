"""Typed Packet Tracer object model.

These are **views** over :mod:`pkt_core.xml`'s lossless tree, so writing a
document back out preserves every byte the caller did not touch. Unknown
elements are never dropped: they surface in each model's ``extra_fields``.

    from pkt_core import decode
    from pkt_core.models import Lab

    lab = Lab.from_bytes(decode("lab.pkt").xml)
    for dev in lab.devices:
        print(dev.name, dev.kind, dev.model, dev.position)
    for link in lab.links:
        print(link.endpoints, link.port_names)
"""

from __future__ import annotations

from pkt_core.models.base import PktNode, unknown_children
from pkt_core.models.lab import Cluster, Lab, LabOptions, Network, RunningConfig
from pkt_core.models.network import Cable, Device, Link, Module, Port, PowerState, Workspace
from pkt_core.models.schema import (
    ActivitySection,
    CanvasShape,
    DeviceDetails,
    EnvironmentOption,
    FileEntry,
    PortConfig,
    ScoringNode,
    WirelessConfig,
)
from pkt_core.models.services import (
    AaaClient,
    AaaUser,
    DeviceServices,
    DhcpPool,
    DnsRecord,
    FtpAccount,
)

__all__ = [
    "PktNode",
    "unknown_children",
    "Port",
    "Module",
    "Workspace",
    "Device",
    "Cable",
    "Link",
    "PowerState",
    "RunningConfig",
    "Cluster",
    "LabOptions",
    "Network",
    "Lab",
    "PortConfig",
    "WirelessConfig",
    "DeviceDetails",
    "FileEntry",
    "ScoringNode",
    "EnvironmentOption",
    "CanvasShape",
    "ActivitySection",
    "AaaClient",
    "AaaUser",
    "DhcpPool",
    "DnsRecord",
    "FtpAccount",
    "DeviceServices",
]
