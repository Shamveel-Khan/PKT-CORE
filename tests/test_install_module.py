#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""`install_module` must not silently install into the wrong bay.

The old signature was ``install_module(dev_id, model, bay=N)`` where ``bay``
indexed the list of *currently empty* eInterfaceCard bays.  That list renumbers
as bays fill, so the natural-looking call sequence

    install_module(dev, "HWIC-2T", 0)
    install_module(dev, "HWIC-2T", 1)

does **not** fill bays 0 and 1 -- after the first call the second empty bay has
become index 0, so ``bay=1`` jumps to the third bay and skips the second.  The
generator only ever passed ``bay=0``, which is why nobody noticed.

`bay=N` for N > 0 now raises instead of quietly doing the wrong thing, and
`slot=N` means the absolute bay index (see problem 7 in
``docs/ENTERPRISE_PROBLEMS.md``).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
TOOLS = REPO / "tools"


def _load_lab_api():
    spec = importlib.util.spec_from_file_location("lab_api_bays", TOOLS / "lab_api.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab_api = _load_lab_api()


@pytest.fixture()
def lab():
    models, modules = lab_api.load_templates(TOOLS / "device_templates.json")
    lb = lab_api.Lab(str(TOOLS / "network_seed.xml"), models, modules)
    lb.prune_seed_devices()
    return lb


@pytest.fixture()
def router(lab):
    """A 2911 -- four empty eInterfaceCard bays."""
    return lab.add_device("2911", "R1", 100, 100)


def _bays(lab, dev_id):
    eng = lab._els[dev_id].find("ENGINE")
    return [s for s in eng.iter("SLOT") if s.findtext("TYPE") == "eInterfaceCard"]


def _occupied(lab, dev_id) -> list[int]:
    return [i for i, b in enumerate(_bays(lab, dev_id)) if b.find("MODULE") is not None]


# --------------------------------------------------------------------------- #
def test_router_has_four_bays(lab, router):
    assert len(_bays(lab, router)) == 4
    assert _occupied(lab, router) == []


def test_successive_calls_fill_successive_bays(lab, router):
    """The documented way to fill in order: omit the bay."""
    lab.install_module(router, "HWIC-2T")
    lab.install_module(router, "HWIC-2T")
    assert _occupied(lab, router) == [0, 1]


def test_bay_zero_is_next_empty(lab, router):
    """Legacy `bay=0` keeps working and means 'next empty', as it always did."""
    lab.install_module(router, "HWIC-2T", 0)
    lab.install_module(router, "HWIC-2T", 0)
    assert _occupied(lab, router) == [0, 1]


def test_bay_n_above_zero_raises_with_guidance(lab, router):
    with pytest.raises(ValueError) as ei:
        lab.install_module(router, "HWIC-2T", 1)
    msg = str(ei.value)
    assert "slot" in msg, "the error must point at the replacement API"
    assert _occupied(lab, router) == [], "a rejected call must change nothing"


def test_slot_is_absolute(lab, router):
    """`slot=2` fills bay 2 and leaves 0 and 1 empty -- no renumbering."""
    lab.install_module(router, "HWIC-2T", slot=2)
    assert _occupied(lab, router) == [2]


def test_slot_does_not_move_as_bays_fill(lab, router):
    lab.install_module(router, "HWIC-2T", slot=1)
    lab.install_module(router, "HWIC-2T", slot=3)
    assert _occupied(lab, router) == [1, 3]


def test_occupied_slot_raises(lab, router):
    lab.install_module(router, "HWIC-2T", slot=0)
    with pytest.raises(ValueError, match="already occupied"):
        lab.install_module(router, "HWIC-2T", slot=0)


def test_slot_out_of_range_raises(lab, router):
    with pytest.raises(ValueError, match="out of range"):
        lab.install_module(router, "HWIC-2T", slot=4)
    with pytest.raises(ValueError, match="out of range"):
        lab.install_module(router, "HWIC-2T", slot=-1)


def test_exhausting_all_bays_raises(lab, router):
    for _ in range(4):
        lab.install_module(router, "HWIC-2T")
    assert _occupied(lab, router) == [0, 1, 2, 3]
    with pytest.raises(ValueError, match="no empty"):
        lab.install_module(router, "HWIC-2T")
