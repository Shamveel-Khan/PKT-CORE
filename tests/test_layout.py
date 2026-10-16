#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Tests for the layout helper (tools/lab_api.Layout) and tools/check_layout.py.

Covers: column pitch selection by name length, the 80-unit hard floor, the
label-inclusive bounding box (hand-computed), page wrap, determinism,
idempotency of tools/repack_layout.py, and the nearest-neighbour aggregation
regression (a device is not its own neighbour).
"""
from __future__ import annotations

import importlib.util
import itertools
import math
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
TOOLS = REPO / "tools"

# delivered artefacts live outside the repo; the migration tool is run against
# them by the maintainer, so tests operate on copies in tmp_path
ARTEFACTS = Path("/home/saoria/filedrop/uploads")
JADGE = ARTEFACTS / "JASDF_AEWC_JADGE.pkt"
JADGE_STD = ARTEFACTS / "JASDF_AEWC_JADGE_standard.pkt"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab_api = _load("lab_api", TOOLS / "lab_api.py")
check_layout = _load("check_layout", TOOLS / "check_layout.py")
repack_layout = _load("repack_layout", TOOLS / "repack_layout.py")


# --------------------------------------------------------------------------- #
# sizing model: pitch selection and label-inclusive boxes
# --------------------------------------------------------------------------- #
def test_column_pitch_by_name_length():
    assert lab_api.column_pitch("R1") == 200            # <= 16 chars
    assert lab_api.column_pitch("A" * 16) == 200
    assert lab_api.column_pitch("A" * 17) == 260        # 17..24
    assert lab_api.column_pitch("A" * 24) == 260
    assert lab_api.column_pitch("A" * 25) == 320        # >= 25
    assert lab_api.column_pitch("Power Distribution Device0") == 320


def test_device_box_is_label_inclusive():
    # hand-computed: width = max(icon_w, 7*len(name)+16, 7*len(model)+16) + 28
    #             height = icon_h + 2*18 + 28
    w, h = lab_api.device_box("server", "SYSLOG-SVR", "Server-PT")
    assert w == max(30, 7 * 10 + 16, 7 * 9 + 16) + 28 == 114
    assert h == 48 + 2 * 18 + 28 == 112

    w, h = lab_api.device_box("router", "CRC-NORTH-RTR-02", "ISR4331")
    assert w == max(52, 7 * 16 + 16, 7 * 7 + 16) + 28 == 156
    assert h == 44 + 2 * 18 + 28 == 108

    # long names dominate the box even for tiny icons
    long_name = "Power Distribution Device0"          # 26 characters
    long_model = "Power Distribution Device"          # 25 characters
    w, h = lab_api.device_box("pdd", long_name, long_model)
    assert w == max(40, 7 * len(long_name) + 16,
                    7 * len(long_model) + 16) + 28 == 226
    assert h == 40 + 2 * 18 + 28 == 104

    # the label-inclusive width always covers the name label
    for name in ("R1", "CRC-CENTRAL-DISPLAY-SVR", "Power Distribution Device0"):
        bw, _ = lab_api.device_box("default", name, "x")
        assert bw >= 7 * len(name) + 16


def test_label_box_overlaps_are_hand_traceable():
    """The exact tie that separates overlap counts is pinned here.

    Two devices whose x-tie is exact (dx*2 == w_a + w_b == 270):
    ``SYSLOG-SVR``/``CRC-NORTH-RTR-02`` and ``COP-SERVER``/``CRC-NORTH-RTR-02``.
    Strict (open) overlap says "boxes that merely touch do not collide" -> 111
    overlapping pairs in the enterprise artefact; counting the boundary as
    overlap -> 113.  The arithmetic below is what the checker computes."""
    wa, ha = lab_api.device_box("server", "SYSLOG-SVR", "Server-PT")
    wb, hb = lab_api.device_box("router", "CRC-NORTH-RTR-02", "ISR4331")
    # enterprise artefact coordinates
    xa, ya = 305.0, 1910.0
    xb, yb = 440.0, 1880.0
    dx2, dy2 = abs(xa - xb) * 2, abs(ya - yb) * 2
    assert (wa, ha, wb, hb) == (114, 112, 156, 108)
    assert dx2 == wa + wb == 270            # exact tie on x
    assert dy2 == 60 < ha + hb == 220       # inside on y
    assert not (dx2 < wa + wb and dy2 < ha + hb)   # strict: not an overlap
    assert dx2 <= wa + wb and dy2 <= ha + hb       # inclusive: touching


# --------------------------------------------------------------------------- #
# Layout: floor, determinism, wrap
# --------------------------------------------------------------------------- #
def _pairwise(places):
    return [(a, b) for a, b in itertools.combinations(places, 2)]


def test_layout_enforces_floor_and_label_boxes():
    lay = lab_api.Layout()
    names = [("R%d" % i, "2911") for i in range(30)]
    names += [("SVR-NAME-%02d" % i, "Server-PT") for i in range(20)]
    names += [("Power Distribution Device%d" % i, "Power Distribution Device")
              for i in range(10)]
    places = [lay.place(n, m) for n, m in names]
    for a, b in _pairwise(places):
        dist = math.hypot(a.x - b.x, a.y - b.y)
        assert dist >= lab_api.FLOOR, (a.name, b.name, dist)
        assert not (abs(a.x - b.x) * 2 < a.w + b.w
                    and abs(a.y - b.y) * 2 < a.h + b.h), (a.name, b.name)


def test_layout_pitch_respects_long_names():
    lay = lab_api.Layout()
    a = lay.place("A" * 30, "2911")
    b = lay.place("B" * 30, "2911")
    assert b.x - a.x >= lab_api.column_pitch("A" * 30) == 320


def test_layout_is_deterministic():
    def run():
        lay = lab_api.Layout()
        return [(p.name, p.x, p.y) for p in (
            lay.place("R%d" % i, "2911", group="g%d" % (i % 3))
            for i in range(40))]
    assert run() == run()


def test_layout_wraps_to_second_page_column():
    # small canvas so a single band must wrap into x + 3900
    lay = lab_api.Layout(x_min=60, y_min=60, x_max=3860, y_max=600)
    places = [lay.place("R%03d" % i, "2911") for i in range(80)]
    pages = {p.page for p in places}
    assert 1 in pages, "expected at least one wrap into page column 1"
    for p in places:
        assert 60 <= p.y <= 600
        assert 60 <= p.x <= 3860 + 3900
        if p.page == 1:
            assert p.x >= 60 + 3900 - 200        # second column at +3900
    for a, b in _pairwise(places):
        assert math.hypot(a.x - b.x, a.y - b.y) >= lab_api.FLOOR


def test_layout_reserve_keeps_explicit_coordinates():
    lay = lab_api.Layout()
    lay.reserve("EXPLICIT", "2911", 500, 500)
    assert lay.placements[0].x == 500 and lay.placements[0].y == 500
    # later packing must clear the reserved box
    for i in range(10):
        p = lay.place("R%d" % i, "2911")
        assert math.hypot(p.x - 500, p.y - 500) >= lab_api.FLOOR


# --------------------------------------------------------------------------- #
# check_layout: NN aggregation regression
# --------------------------------------------------------------------------- #
def test_nn_min_positive_when_no_duplicates():
    """A device is not its own neighbour: with no coincident positions the
    nearest-neighbour minimum must be strictly positive."""
    devs = [lab_api.Device(f"D{i}", "2911", "router",
                           100.0 + 130 * i, 100.0 + 70 * (i % 5))
            for i in range(12)]
    # no two devices share a position
    assert len({(d.x, d.y) for d in devs}) == len(devs)
    rep = check_layout.analyse(devs)
    assert rep["nn"]["min"] > 0
    assert rep["coincident"] == 0


def test_nn_min_zero_only_on_coincident_pair():
    devs = [lab_api.Device("A", "2911", "router", 100.0, 100.0),
            lab_api.Device("B", "2911", "router", 100.0, 100.0),
            lab_api.Device("C", "2911", "router", 900.0, 900.0)]
    rep = check_layout.analyse(devs)
    assert rep["nn"]["min"] == 0.0
    assert rep["coincident"] == 1


def test_nn_last_device_is_counted():
    # the regression: the final device of the list used to fall out of the
    # forward-only pair scan and be reported as min 0.0
    devs = [lab_api.Device(f"D{i}", "2911", "router", 100.0 + 500 * i, 100.0)
            for i in range(4)]
    rep = check_layout.analyse(devs)
    assert rep["nn"]["min"] == pytest.approx(500.0)
    assert rep["nn"]["median"] == pytest.approx(500.0)


def test_check_layout_flags_overlap_and_off_page():
    good = [lab_api.Device(f"D{i}", "2911", "router",
                           200.0 + 300 * i, 200.0) for i in range(5)]
    rep = check_layout.analyse(good)
    assert not rep["violations"]
    bad = good + [lab_api.Device("NEAR", "2911", "router",
                                 good[0].x + 30, good[0].y)]
    rep = check_layout.analyse(bad)
    assert rep["violations"]
    assert rep["pairs_le_40"], "30 units is inside the icon size"
    assert rep["pairs_lt_80"]
    off = good + [lab_api.Device("FAR", "2911", "router", 9000.0, 9000.0)]
    rep = check_layout.analyse(off)
    assert rep["violations"]
    assert rep["off_page"]


# --------------------------------------------------------------------------- #
# repack_layout: idempotency and position-only rewriting
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def templates():
    return lab_api.load_templates(str(TOOLS / "device_templates.json"))


def _build_lab(path: Path, templates, n: int = 12) -> None:
    models, modules = templates
    lab = lab_api.Lab(str(TOOLS / "network_seed.xml"), models, modules)
    lab.prune_seed_devices()
    for i in range(n):
        lab.add_device("2911", f"R{i}", 100 + (i % 5) * 30,
                       100 + (i // 5) * 30)
        lab.add_device("Server-PT", f"SVR{i}", 200 + (i % 5) * 30,
                       150 + (i // 5) * 30)
    lab.save(str(path))


def test_repack_is_idempotent(tmp_path, templates):
    src = tmp_path / "lab.pkt"
    _build_lab(src, templates)
    a = tmp_path / "a.pkt"
    b = tmp_path / "b.pkt"
    repack_layout.repack_file(src, a)
    repack_layout.repack_file(a, b)
    assert a.read_bytes() == b.read_bytes(), "repack must be a fixed point"


def test_repack_rewrites_only_coordinates(tmp_path, templates):
    src = tmp_path / "lab.pkt"
    _build_lab(src, templates)
    out = tmp_path / "out.pkt"
    rep = repack_layout.repack_file(src, out)
    assert rep["positions_only"], "only LOGICAL X/Y may change"
    assert rep["power_before"] == rep["power_after"]
    # and the result is actually cleaner than the deliberately overlapping input
    assert not rep["after"]["violations"]
    assert rep["after"]["pairs_lt_80"] == []
    assert rep["after"]["label_box_overlaps"] == []


def test_repack_cli(tmp_path, templates):
    src = tmp_path / "lab.pkt"
    _build_lab(src, templates)
    out = tmp_path / "out.pkt"
    rc = repack_layout.main([str(src), str(out)])
    assert rc == 0
    assert out.exists()
    rc = check_layout.main([str(out)])
    assert rc == 0


# --------------------------------------------------------------------------- #
# delivered enterprise artefacts: migrate a COPY and verify the result
# --------------------------------------------------------------------------- #
needs_artefacts = pytest.mark.skipif(
    not (JADGE.exists() and JADGE_STD.exists()),
    reason="delivered .pkt artefacts not available")


@needs_artefacts
@pytest.mark.parametrize("src,engine_power,ports", [
    (JADGE, 290, 2454),
    (JADGE_STD, 199, 1721),
])
def test_enterprise_artefact_after_repack(tmp_path, src, engine_power, ports):
    """Repack a copy of the shipped artefact and assert the contract:
    zero pairs <= 40, zero below the floor, no label-box overlaps, inside the
    3900x3900 page -- and the power fix survives byte-for-byte."""
    copy = tmp_path / src.name
    shutil.copyfile(src, copy)
    out = tmp_path / ("repacked-" + src.name)
    rep = repack_layout.repack_file(copy, out)

    # power preservation proof
    assert rep["power_before"] == rep["power_after"]
    assert rep["power_after"]["true"] == engine_power
    assert rep["power_after"]["false"] == 0
    assert rep["positions_only"]

    # port-level POWER must also be untouched and all true
    xml = lab_api.pt9.decode_bytes(out.read_bytes(), "pkt").decode("utf-8")
    import re as _re
    port_powers = _re.findall(r"<PORT>.*?<POWER>([^<]*)</POWER>", xml, _re.S)
    assert len(port_powers) == ports
    assert all(p.strip() == "true" for p in port_powers)

    after = rep["after"]
    assert after["pairs_le_40"] == []
    assert after["pairs_lt_80"] == []
    assert after["label_box_overlaps"] == []
    assert after["off_page"] == []
    assert after["nn"]["min"] >= lab_api.FLOOR
    b = after["bbox"]
    assert 0 <= b["x_min"] and b["x_max"] <= 3900
    assert 0 <= b["y_min"] and b["y_max"] <= 3900


@needs_artefacts
def test_enterprise_artefact_nn_min_positive():
    """The NN aggregation must never invent a coincident pair."""
    for src in (JADGE, JADGE_STD):
        xml = lab_api.pt9.decode_bytes(src.read_bytes(), "pkt").decode("utf-8")
        rep = check_layout.analyse(lab_api.parse_devices(xml))
        if rep["coincident"] == 0:
            assert rep["nn"]["min"] > 0
