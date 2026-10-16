"""pkt-core — type-safe reader, writer and generator for Cisco Packet Tracer .pkt and .pka files.

Quick start (author a new lab)::

    from pkt_core import Lab

    lab = Lab()  # Clean workspace with bundled models and seed
    r1 = lab.add_device("2911", "R1", 200, 200, install="HWIC-2T")
    sw1 = lab.add_device("2960-24TT", "SW1", 400, 200)
    lab.link(r1, "GigabitEthernet0/0", sw1, "GigabitEthernet0/1")
    lab.save("my_lab.pkt")

Quick start (open and inspect an existing lab)::

    from pkt_core import open_lab

    lab = open_lab("my_lab.pkt")
    for dev in lab.devices:
        print(dev.name, dev.model, dev.position)

Quick start (low-level codec)::

    from pkt_core import decode, encode_bytes

    container = decode("my_lab.pkt")
    print(container.root_tag)  # 'PACKETTRACER5'
    rebuilt = encode_bytes(container.xml, container.format_name)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from pkt_core.builder import (
    Activity,
    ActivityBuilder,
    Lab,
    LabBuilder,
    Layout,
)
from pkt_core.codec.container import (
    DEFAULT_FORMAT,
    Container,
    decode,
    decode_bytes,
    detect_format,
    encode,
    encode_bytes,
    root_tag,
)
from pkt_core.codec.qcompress import qcompress, quncompress
from pkt_core.crypto.keys import BLOCK_SIZE, FORMATS, TAG_SIZE, FormatSpec, get_format
from pkt_core.crypto.primitives import eax_open, eax_seal, eax_verify
from pkt_core.errors import (
    ActivityError,
    CompressionError,
    DeviceNameConflictError,
    DeviceNotFoundError,
    FormatError,
    IntegrityError,
    InvalidCableError,
    LabBuilderError,
    ModuleBayError,
    PacketTracerError,
    TruncatedFileError,
    UnsupportedCipherError,
)

if TYPE_CHECKING:
    from pkt_core.diff import LabDiff
    from pkt_core.models.lab import Lab as LabView


def open_lab(path: str | Path) -> LabView:
    """Open an existing Packet Tracer file (.pkt/.pka) and return a typed inspection view."""
    from pkt_core.models.lab import Lab as LabView

    container = decode(path)
    return LabView.from_bytes(container.xml)


def diff_labs(lab_a: Any, lab_b: Any) -> LabDiff:
    """Semantic comparison between two Packet Tracer labs."""
    from pkt_core.diff import diff_labs as _diff_labs

    return _diff_labs(lab_a, lab_b)


def export(lab: Any, fmt: str = "graphviz") -> str:
    """Render the topology for external tooling (graphviz, netbox, containerlab)."""
    from pkt_core.export import export as _export

    return _export(lab, fmt)


__version__ = "0.2.0"

__all__ = [
    # Top-level builders
    "Lab",
    "LabBuilder",
    "Activity",
    "ActivityBuilder",
    "Layout",
    "open_lab",
    # Container & Codec
    "Container",
    "decode",
    "decode_bytes",
    "encode",
    "encode_bytes",
    "detect_format",
    "root_tag",
    "DEFAULT_FORMAT",
    # Tools
    "diff_labs",
    "export",
    # Key schedule & Crypto
    "FORMATS",
    "FormatSpec",
    "get_format",
    "BLOCK_SIZE",
    "TAG_SIZE",
    "eax_seal",
    "eax_open",
    "eax_verify",
    # Framing
    "qcompress",
    "quncompress",
    # Exceptions
    "PacketTracerError",
    "FormatError",
    "IntegrityError",
    "TruncatedFileError",
    "CompressionError",
    "UnsupportedCipherError",
    "LabBuilderError",
    "DeviceNameConflictError",
    "DeviceNotFoundError",
    "ModuleBayError",
    "InvalidCableError",
    "ActivityError",
    "__version__",
]
