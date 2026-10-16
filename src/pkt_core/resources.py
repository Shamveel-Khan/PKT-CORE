"""Asset management for bundled device templates, seeds, and activity skeletons.

Provides cached access to the internal data files shipped with pkt-core using
the standard library :mod:`importlib.resources`.
"""

from __future__ import annotations

import base64
import functools
import gzip
import importlib.resources as resources
import json
from typing import Any

__all__ = [
    "load_bundled_templates",
    "load_bundled_seed_xml",
    "load_bundled_device_shapes",
    "load_bundled_activity_skeleton",
]


@functools.lru_cache(maxsize=1)
def load_bundled_templates() -> tuple[dict[str, bytes], dict[str, str]]:
    """Load and return the bundled device and module template library.

    Returns:
        A tuple ``(models, modules)`` where:
        - ``models`` maps device model name (e.g. ``"2911"``) to ``<DEVICE>`` XML bytes.
        - ``modules`` maps module model name (e.g. ``"HWIC-2T"``) to ``<SLOT>`` XML string.
    """
    ref = resources.files("pkt_core.data").joinpath("device_templates.json")
    with ref.open("rb") as f:
        t = json.load(f)
    gz = t.get("gz", False)

    def dec(v: str) -> bytes:
        b = base64.b64decode(v)
        return gzip.decompress(b) if gz else b

    models: dict[str, bytes] = {k: dec(v) for k, v in t["models"].items()}
    modules: dict[str, str] = {
        k: dec(v).decode("utf-8") for k, v in t.get("modules", {}).items()
    }
    return models, modules


@functools.lru_cache(maxsize=1)
def load_bundled_seed_xml() -> bytes:
    """Return the raw bytes of the bundled minimal network seed (XML)."""
    ref = resources.files("pkt_core.data").joinpath("network_seed.xml")
    return ref.read_bytes()


@functools.lru_cache(maxsize=1)
def load_bundled_device_shapes() -> dict[str, Any]:
    """Return the bundled device shape configurations used for scoring trees."""
    ref = resources.files("pkt_core.data").joinpath("device_shapes.json")
    b = ref.read_bytes()
    if b[:2] == b"\x1f\x8b":
        b = gzip.decompress(b)
    data: dict[str, Any] = json.loads(b)
    return data


@functools.lru_cache(maxsize=1)
def load_bundled_activity_skeleton() -> str:
    """Return the bundled Packet Tracer activity (.pka) skeleton as XML text."""
    ref = resources.files("pkt_core.data").joinpath("activity_skeleton.xml")
    return ref.read_text(encoding="utf-8")
