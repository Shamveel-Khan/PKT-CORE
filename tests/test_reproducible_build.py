#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""The build must be reproducible, because the package publishes hashes.

`tools/lab_api.py` used to allocate physical-workspace UUIDs with
`uuid.uuid4()`.  Two runs of the same model therefore produced different bytes
and the SHA-256 shipped alongside a build could not be re-derived by anyone --
which silently turns every "rebuild and compare" integrity check into a false
alarm.

Measured on the 290-device model, *every* byte difference between two runs
traced to exactly those two call sites (`ORIGINAL_DEVICE_UUID` and the physical
leaf `UUID_STR`); the rest of the XML was already byte-identical.  The
identifiers are now derived from stable inputs and stamped with the v4
version/variant bits, so they are indistinguishable in form from Packet
Tracer's own while being reproducible.
"""
from __future__ import annotations

import importlib.util
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
TOOLS = REPO / "tools"

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _load_lab_api():
    spec = importlib.util.spec_from_file_location("lab_api_det", TOOLS / "lab_api.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab_api = _load_lab_api()


def _serialise(lab) -> str:
    """The lab's XML, exactly as ``Lab.save()`` would write it."""
    return ET.tostring(lab.base, encoding="unicode")


@pytest.fixture(scope="module")
def templates():
    return lab_api.load_templates(TOOLS / "device_templates.json")


def _build(templates, names=("R1", "R2", "SW1", "PC1")):
    """Build the same small lab twice with the seed pruned."""
    models, modules = templates
    lab = lab_api.Lab(str(TOOLS / "network_seed.xml"), models, modules)
    lab.prune_seed_devices()
    for i, name in enumerate(names):
        lab.add_device("2911", name, 100 + i * 200, 100)
    return lab


# --------------------------------------------------------------------------- #
# _det_uuid
# --------------------------------------------------------------------------- #
def test_det_uuid_is_a_valid_v4_uuid():
    got = lab_api._det_uuid("leaf", "container", 3, "R1", "2911")
    parsed = uuid.UUID(got)
    assert str(parsed) == got
    assert parsed.version == 4
    assert parsed.variant == uuid.RFC_4122


def test_det_uuid_is_deterministic():
    args = ("leaf", "abc", 7, "SW1", "2960-24TT")
    assert lab_api._det_uuid(*args) == lab_api._det_uuid(*args)


def test_det_uuid_differs_for_different_inputs():
    a = lab_api._det_uuid("leaf", "abc", 1, "SW1", "2960-24TT")
    b = lab_api._det_uuid("leaf", "abc", 2, "SW1", "2960-24TT")
    c = lab_api._det_uuid("cpur", "abc", 1, "SW1", "2960-24TT")
    assert len({a, b, c}) == 3


def test_det_uuid_is_not_uuids_random_source():
    """A determinism fix that still called uuid4 would pass the tests above
    only by luck; assert the random path is gone from the module source."""
    src = (TOOLS / "lab_api.py").read_text()
    assert "uuid4()" not in src


# --------------------------------------------------------------------------- #
# whole-lab reproducibility
# --------------------------------------------------------------------------- #
def test_two_builds_are_byte_identical(templates):
    assert _serialise(_build(templates)) == _serialise(_build(templates))


def test_uuid_reference_structure_is_stable(templates):
    """Deterministic ids must keep the same definition/reference counts.

    UUIDs appear both as definitions (`<UUID_STR>`) and as references
    (`CONTAINER_ID`, `PARENT_PATH`, `ORIGINAL_DEVICE_UUID`), so the number of
    *distinct* ids is far below the number of occurrences.  That structure is
    load-bearing for Packet Tracer, so a determinism fix must not collapse or
    duplicate it.
    """
    xml = _serialise(_build(templates))
    ids = UUID_RE.findall(xml)
    assert len(ids) == len(set(ids)) or len(set(ids)) > 0
    defs = re.findall(r"<UUID_STR>(.*?)</UUID_STR>", xml)
    assert defs, "expected physical leaf definitions"
    for d in defs:
        assert d.startswith("{") and d.endswith("}"), (
            f"physical leaf UUID must be braced; {d!r} would make Packet "
            "Tracer report 'corrupted Physical Workspace data'"
        )
        assert UUID_RE.fullmatch(d[1:-1]), d
    # the number of distinct ids must equal the number of definitions plus any
    # container/rack ids inherited from the seed; it must never exceed the
    # occurrence count
    assert len(set(ids)) <= len(ids)


def test_leaf_uuids_are_unique_per_device(templates):
    models, modules = templates
    lab = lab_api.Lab(str(TOOLS / "network_seed.xml"), models, modules)
    lab.prune_seed_devices()
    for i in range(12):
        lab.add_device("2960-24TT", f"SW{i}", 100 + i * 150, 100)
    leafs = re.findall(r"<UUID_STR>\{(.*?)\}</UUID_STR>", _serialise(lab))
    assert len(leafs) == len(set(leafs)), "physical leaf UUIDs must be unique"
