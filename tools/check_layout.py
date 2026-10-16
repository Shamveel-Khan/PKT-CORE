#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""check_layout.py -- reproduce and gate against device/label overlap in labs.

Reads a Packet Tracer ``.pkt``/``.pka`` save (or a raw decoded XML file) and
reports the geometry of every device in its ``NETWORK/DEVICES`` table:

  * every pair closer than the 80-unit hard floor (also counted at the
    40-unit icon size and 120-unit "comfortable" mark),
  * label-inclusive axis-aligned bounding box overlaps (PT draws the model
    caption above and the device name below each icon, so boxes that overlap
    mean colliding *text*, not just colliding icons),
  * the label-inclusive bounding box of the whole lab,
  * nearest-neighbour min / p25 / median (human-authored corpus: 50.2 / 88.4
    / 125.7, zero pairs at or below 40),
  * devices outside the Packet Tracer page (3900x3900 at 100 % zoom; the
    packer wraps overflow into page columns at +3900 in X).

Exit status is non-zero when any violation exists, so the tool is usable as a
CI gate::

    python3 tools/check_layout.py lab.pkt          # 0 = clean
    python3 tools/check_layout.py --json lab.pkt   # machine-readable

The geometry model (icon sizes, label width, 80-unit floor) is shared with the
packer in ``tools/lab_api.Layout`` so the checker and the layout helper can
never disagree about what "overlapping" means.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))            # pt9
sys.path.insert(0, str(ROOT / "tools"))  # lab_api
import lab_api  # noqa: E402

# geometry constants mirrored from lab_api (re-derived there, documented here)
FLOOR = 80          # hard floor, centre-to-centre
ICON_SIZE = 40      # "icon overlap" mark
COMFORT = 120       # human-authored comfortable mark
PAGE = 3900         # PT stock page at 100 % zoom
CANVAS_MIN = 60
CANVAS_MAX = 3860


def load_devices(path: Path) -> list[lab_api.Device]:
    """Return the devices of a lab file (.pkt/.pka) or decoded XML file."""
    raw = path.read_bytes()
    if raw[:1] == b"<" or raw.lstrip()[:1] == b"<":
        xml = raw
    else:
        fmt = "pka" if path.suffix.lower() == ".pka" else "pkt"
        xml = lab_api.pt9.decode_bytes(raw, fmt)
    return lab_api.parse_devices(xml)


def _percentile(sorted_vals: list[float], q: float) -> float:
    """Linear-interpolated percentile of an already sorted, non-empty list."""
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = q * (len(sorted_vals) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def _page_column(x: float) -> int:
    """Page-column index of an x coordinate (0 = primary page)."""
    return int((x - CANVAS_MIN) // PAGE) if x >= CANVAS_MIN else -1


def on_page(x: float, y: float, allow_wrap: bool = False) -> bool:
    """True when (x, y) lies inside the PT page.

    The stock page is 3900x3900 at 100 % zoom.  By default a device must sit
    on the primary page (0..3900 in both axes).  With ``allow_wrap`` the
    packer's overflow strategy is accepted too: further page columns at
    +3900 in X, each 3900 wide and 3900 tall."""
    if y < 0 or y > PAGE:
        return False
    if x < 0:
        return False
    if allow_wrap:
        return (x % PAGE) <= PAGE
    return x <= PAGE


def analyse(devices: list[lab_api.Device]) -> dict[str, Any]:
    """Compute the full layout report for a device list."""
    n = len(devices)
    pairs_40: list[dict[str, Any]] = []
    pairs_80: list[dict[str, Any]] = []
    pairs_120: list[dict[str, Any]] = []
    label_hits: list[dict[str, Any]] = []
    label_touch: list[dict[str, Any]] = []
    # per-device nearest-neighbour distance; a device is not its own neighbour,
    # so each entry starts at +inf and is lowered only by *other* devices
    nn: list[float] = [math.inf] * n
    off_page: list[dict[str, Any]] = []
    label_off_page: list[dict[str, Any]] = []

    # label-inclusive boxes (centred on the device coordinate)
    boxes = [lab_api.device_box(d.kind, d.name, d.model) for d in devices]

    for i, d in enumerate(devices):
        if not on_page(d.x, d.y):
            off_page.append({"name": d.name, "x": d.x, "y": d.y,
                             "page": _page_column(d.x)})
        # a device counts as off-page when its *label box* clips the page edge,
        # which is what a user actually sees; reported separately from the
        # centre-outside-page count above
        w, h = boxes[i]
        if not (on_page(d.x - w / 2, d.y - h / 2)
                and on_page(d.x + w / 2, d.y + h / 2)):
            label_off_page.append({"name": d.name, "x": d.x, "y": d.y})
        best = math.inf
        for j in range(i + 1, n):
            e = devices[j]
            dist = math.hypot(d.x - e.x, d.y - e.y)
            # a device is not its own neighbour: track both endpoints so every
            # device gets a true nearest neighbour (including the last one)
            best = min(best, dist)
            nn[j] = min(nn[j], dist)
            rec = {"a": d.name, "b": e.name, "dist": round(dist, 1),
                   "ax": d.x, "ay": d.y, "bx": e.x, "by": e.y}
            if dist <= ICON_SIZE:
                pairs_40.append(rec)
            if dist < FLOOR:
                pairs_80.append(rec)
            if dist <= COMFORT:
                pairs_120.append(rec)
            wa, ha = boxes[i]
            wb, hb = boxes[j]
            dx2 = abs(d.x - e.x) * 2
            dy2 = abs(d.y - e.y) * 2
            if dx2 < wa + wb and dy2 < ha + hb:
                label_hits.append({"a": d.name, "b": e.name,
                                   "dist": round(dist, 1)})
            elif dx2 <= wa + wb and dy2 <= ha + hb:
                # boxes exactly touching on at least one axis: labels are a
                # gutter apart but the pair is worth reporting so the overlap
                # count stays traceable under any boundary convention
                label_touch.append({"a": d.name, "b": e.name,
                                    "dist": round(dist, 1)})
        if n > 1:
            nn[i] = best

    # devices that never met a partner above are single-device labs; drop them
    nn_sorted = sorted(v for v in nn if v < math.inf)
    xs = [d.x for d in devices]
    ys = [d.y for d in devices]
    # label-inclusive bbox: extend each centre by its half-box
    lx0 = min(d.x - boxes[i][0] / 2 for i, d in enumerate(devices)) if n else 0.0
    lx1 = max(d.x + boxes[i][0] / 2 for i, d in enumerate(devices)) if n else 0.0
    ly0 = min(d.y - boxes[i][1] / 2 for i, d in enumerate(devices)) if n else 0.0
    ly1 = max(d.y + boxes[i][1] / 2 for i, d in enumerate(devices)) if n else 0.0

    violations = bool(pairs_40 or pairs_80 or label_hits or off_page
                      or label_off_page)
    return {
        "devices": n,
        "pairs_le_40": pairs_40,
        "pairs_lt_80": pairs_80,
        "pairs_le_120": pairs_120,
        "label_box_overlaps": label_hits,
        "label_box_touching": label_touch,
        "off_page": off_page,
        "label_off_page": label_off_page,
        "coincident": sum(1 for r in pairs_40 if r["dist"] == 0),
        "bbox": {"x_min": min(xs) if n else 0.0,
                 "y_min": min(ys) if n else 0.0,
                 "x_max": max(xs) if n else 0.0,
                 "y_max": max(ys) if n else 0.0},
        "label_bbox": {"x_min": lx0, "y_min": ly0, "x_max": lx1, "y_max": ly1},
        "nn": {"min": nn_sorted[0] if nn_sorted else 0.0,
               "p25": round(_percentile(nn_sorted, 0.25), 1) if nn_sorted else 0.0,
               "median": round(_percentile(nn_sorted, 0.50), 1) if nn_sorted else 0.0},
        "violations": violations,
    }


def format_report(path: Path, rep: dict[str, Any]) -> str:
    b = rep["bbox"]
    lb = rep["label_bbox"]
    nn = rep["nn"]
    out = [
        f"== {path.name}: {rep['devices']} devices ==",
        f"  bbox (centres)        : X [{b['x_min']:.0f} .. {b['x_max']:.0f}]"
        f"  Y [{b['y_min']:.0f} .. {b['y_max']:.0f}]",
        f"  bbox (label-inclusive): X [{lb['x_min']:.0f} .. {lb['x_max']:.0f}]"
        f"  Y [{lb['y_min']:.0f} .. {lb['y_max']:.0f}]",
        f"  nearest neighbour     : min {nn['min']:.1f}"
        f"  p25 {nn['p25']:.1f}  median {nn['median']:.1f}",
        f"  pairs <= {ICON_SIZE} / < {FLOOR} / <= {COMFORT}: "
        f"{len(rep['pairs_le_40'])} / {len(rep['pairs_lt_80'])}"
        f" / {len(rep['pairs_le_120'])}",
        f"  label box overlaps    : {len(rep['label_box_overlaps'])}"
        f"  (plus {len(rep['label_box_touching'])} exactly touching)",
        f"  off-page devices      : {len(rep['off_page'])} (centre outside page)"
        f"  {len(rep['label_off_page'])} (label box clips page edge)",
        f"  coincident pairs      : {rep['coincident']}",
    ]
    if rep["pairs_lt_80"]:
        out.append("  -- pairs under the %d-unit floor --" % FLOOR)
        for rec in rep["pairs_lt_80"]:
            out.append("     %-24s %-24s d=%.1f  (%.0f,%.0f)-(%.0f,%.0f)"
                       % (rec["a"], rec["b"], rec["dist"], rec["ax"], rec["ay"],
                          rec["bx"], rec["by"]))
    if rep["label_box_overlaps"]:
        out.append("  -- label-inclusive box overlaps --")
        for rec in rep["label_box_overlaps"]:
            out.append("     %-24s %-24s d=%.1f"
                       % (rec["a"], rec["b"], rec["dist"]))
    if rep["off_page"]:
        out.append("  -- off-page devices --")
        for rec in rep["off_page"]:
            out.append("     %-24s (%.0f, %.0f) page-column %d"
                       % (rec["name"], rec["x"], rec["y"], rec["page"]))
    out.append("  result: " + ("VIOLATIONS" if rep["violations"] else "OK"))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", type=Path,
                    help=".pkt/.pka save or decoded XML file")
    ap.add_argument("--json", action="store_true",
                    help="emit the report as JSON")
    args = ap.parse_args(argv)

    status = 0
    for path in args.files:
        try:
            devices = load_devices(path)
        except Exception as exc:                       # noqa: BLE001
            print(f"{path}: cannot read devices: {exc}", file=sys.stderr)
            status = 1
            continue
        rep = analyse(devices)
        if args.json:
            print(json.dumps({"file": str(path), **rep}, indent=2))
        else:
            print(format_report(path, rep))
        if rep["violations"]:
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
