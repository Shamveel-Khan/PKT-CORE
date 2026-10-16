"""Tests for pkt_core.resources asset management."""

from __future__ import annotations

from pkt_core.resources import (
    load_bundled_activity_skeleton,
    load_bundled_device_shapes,
    load_bundled_seed_xml,
    load_bundled_templates,
)


def test_load_bundled_templates() -> None:
    models, modules = load_bundled_templates()
    assert isinstance(models, dict)
    assert isinstance(modules, dict)
    assert len(models) >= 100
    assert len(modules) >= 50
    # Core router and switch models must be present
    assert "2911" in models
    assert "2960-24TT" in models
    assert "PC-PT" in models
    assert "HWIC-2T" in modules
    # Values must be bytes / strings
    assert isinstance(models["2911"], bytes)
    assert isinstance(modules["HWIC-2T"], str)


def test_load_bundled_seed_xml() -> None:
    seed = load_bundled_seed_xml()
    assert isinstance(seed, bytes)
    assert b"<PACKETTRACER5>" in seed
    assert b"<PHYSICALWORKSPACE>" in seed
    assert b"<HOMERACK>" in seed


def test_load_bundled_device_shapes() -> None:
    shapes = load_bundled_device_shapes()
    assert isinstance(shapes, dict)
    assert "models" in shapes
    assert "scaffold" in shapes


def test_load_bundled_activity_skeleton() -> None:
    skel = load_bundled_activity_skeleton()
    assert isinstance(skel, str)
    assert "<PACKETTRACER5_ACTIVITY>" in skel
    assert "<INSTRUCTIONS" in skel
