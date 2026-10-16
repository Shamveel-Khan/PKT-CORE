#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""repack_layout.py -- migrate a generated lab to non-overlapping placement.

Rewrites ONLY the ``WORKSPACE/LOGICAL/X,Y`` coordinates of every device in a
``.pkt``/``.pka`` save (or a decoded XML file), repositioning them with the
label-inclusive greedy packer in ``tools/lab_api.Layout``.  Everything else in
the file -- device power state, IOS running-configs, services, cabling,
physical workspace, save-ref-ids -- is preserved byte-for-byte.

Guarantees
----------
* **Idempotent**: placement is a pure function of (name, model, document order,
  semantic tier), none of which the rewrite touches, so running the tool twice
  produces byte-identical output.
* **Position-only diff**: after writing, the tool compares the input and output
  XML with every LOGICAL X/Y masked out; anything other than a coordinate
  change is an error and the output is reported as unverified.  This is what
  protects other fixes (e.g. device power) from being clobbered.
* **Floor**: no two device centres land closer than 80 units, and no two
  label-inclusive boxes overlap (PT draws the model caption above and the
  device name below each icon).

Usage
-----
    python3 tools/repack_layout.py lab.pkt             # rewrite in place
    python3 tools/repack_layout.py lab.pkt out.pkt     # write a new file
    python3 tools/repack_layout.py --dry-run lab.pkt   # report only

The tool prints the before/after overlap metrics (see tools/check_layout.py).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))            # pt9
sys.path.insert(0, str(ROOT / "tools"))  # lab_api, check_layout
import lab_api  # noqa: E402
import check_layout  # noqa: E402

# X/Y inside a device's logical workspace -- the only text this tool edits
_LOGICAL_XY = re.compile(
    r"(<WORKSPACE>\s*<LOGICAL>\s*<X>)[^<]*(</X>\s*<Y>)[^<]*(</Y>)", re.S)
_DEVICE = re.compile(r"<DEVICE>.*?</DEVICE>", re.S)
_TYPE_MODEL = re.compile(r'<TYPE[^>]*model="([^"]*)"')
_NAME = re.compile(r"<NAME[^>]*>(.*?)</NAME>", re.S)

# semantic tiers of the JASDF/JADGE model, derived from device names so that
# repacking keeps each tier in its own horizontal band (topology stays
# readable).  The mapping lives in lab_api.tier_for_name so the enterprise
# generator and this tool can never disagree about it.
_DEFAULT_TIER = "misc"


def tier_for_name(name: str) -> str:
    """Map a device name onto a semantic tier band."""
    return lab_api.tier_for_name(name)


def _mask_coordinates(xml: str) -> str:
    """Replace every LOGICAL X/Y value with a placeholder."""
    return _LOGICAL_XY.sub(r"\1@\2@\3", xml)


def _engine_power_counts(xml: str) -> dict[str, int]:
    """Count device-level <ENGINE><POWER> states (port POWER excluded)."""
    root = lab_api.ET.fromstring(xml)
    devs = root.find("NETWORK/DEVICES")
    counts = {"true": 0, "false": 0, "absent": 0}
    if devs is None:
        return counts
    for d in devs.findall("DEVICE"):
        eng = d.find("ENGINE")
        if eng is None:
            counts["absent"] += 1
            continue
        p = eng.find("POWER")
        if p is None or p.text is None or not p.text.strip():
            counts["absent"] += 1
        elif p.text.strip().lower() == "true":
            counts["true"] += 1
        else:
            counts["false"] += 1
    return counts


def _read(path: Path) -> tuple[str, str, bool]:
    """Return (xml_text, container_format, is_container)."""
    raw = path.read_bytes()
    if raw[:1] == b"<" or raw.lstrip()[:1] == b"<":
        return raw.decode("utf-8"), "pkt", False
    fmt = "pka" if path.suffix.lower() == ".pka" else "pkt"
    return lab_api.pt9.decode_bytes(raw, fmt).decode("utf-8"), fmt, True


def _write(path: Path, xml: str, fmt: str, container: bool) -> None:
    data = (lab_api.pt9.encode_bytes(xml.encode("utf-8"), fmt) if container
            else xml.encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def repack_xml(xml: str) -> tuple[str, list[tuple[str, int, int]]]:
    """Return (new_xml, [(name, x, y), ...]) with every device repositioned.

    Devices are visited in document order and handed to ``lab_api.Layout``,
    grouped by :func:`tier_for_name`, so the output depends only on the device
    table -- never on the coordinates being replaced (idempotency)."""
    layout = lab_api.Layout()
    moves: list[tuple[str, int, int]] = []

    def repl(m: re.Match[str]) -> str:
        blk = m.group(0)
        name_m = _NAME.search(blk)
        model_m = _TYPE_MODEL.search(blk)
        name = name_m.group(1) if name_m else ""
        model = model_m.group(1) if model_m else ""
        if not _LOGICAL_XY.search(blk):
            return blk
        p = layout.place(name, model, group=tier_for_name(name))
        moves.append((name, p.x, p.y))
        return _LOGICAL_XY.sub(
            lambda mm: (mm.group(1) + str(p.x) + mm.group(2) + str(p.y)
                        + mm.group(3)), blk, count=1)

    return _DEVICE.sub(repl, xml), moves


def repack_file(src: Path, dst: Path, dry_run: bool = False) -> dict[str, Any]:
    """Repack ``src`` into ``dst`` and return the before/after report."""
    xml, fmt, container = _read(src)
    before = check_layout.analyse(lab_api.parse_devices(xml))
    power_before = _engine_power_counts(xml)

    new_xml, moves = repack_xml(xml)
    after = check_layout.analyse(lab_api.parse_devices(new_xml))
    power_after = _engine_power_counts(new_xml)

    # position-only guarantee: everything except LOGICAL X/Y must be identical
    positions_only = _mask_coordinates(xml) == _mask_coordinates(new_xml)
    power_ok = power_before == power_after
    if not (positions_only and power_ok):
        raise RuntimeError(
            "refusing to write %s: rewrite is not a pure position edit "
            "(positions_only=%s, power %s -> %s)"
            % (dst, positions_only, power_before, power_after))
    if not dry_run and src != dst:
        _write(dst, new_xml, fmt, container)
    elif not dry_run:
        _write(dst, new_xml, fmt, container)

    return {
        "src": str(src), "dst": str(dst), "moves": len(moves),
        "before": before, "after": after,
        "positions_only": positions_only,
        "power_before": power_before, "power_after": power_after,
        "changed": xml != new_xml,
    }


def _summary(label: str, rep: dict[str, Any]) -> str:
    b = rep["bbox"]
    return ("%-8s devices=%d pairs<=40/<80/<=120=%d/%d/%d "
            "label-overlaps=%d off-page=%d nn(min/p25/med)=%.1f/%.1f/%.1f "
            "bbox=X[%.0f..%.0f] Y[%.0f..%.0f]"
            % (label, rep["devices"],
               len(rep["pairs_le_40"]), len(rep["pairs_lt_80"]),
               len(rep["pairs_le_120"]), len(rep["label_box_overlaps"]),
               len(rep["off_page"]), rep["nn"]["min"], rep["nn"]["p25"],
               rep["nn"]["median"], b["x_min"], b["x_max"],
               b["y_min"], b["y_max"]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("src", type=Path, help="input .pkt/.pka or decoded XML")
    ap.add_argument("dst", nargs="?", type=Path, default=None,
                    help="output path (default: rewrite src in place)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report metrics without writing")
    args = ap.parse_args(argv)
    dst = args.dst or args.src

    try:
        rep = repack_file(args.src, dst, dry_run=args.dry_run)
    except Exception as exc:                          # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"repack: {rep['src']} -> {rep['dst']}  ({rep['moves']} devices)")
    print("  " + _summary("before", rep["before"]))
    print("  " + _summary("after ", rep["after"]))
    print("  position-only diff : %s" % ("yes" if rep["positions_only"] else "NO"))
    print("  engine POWER       : %s -> %s"
          % (rep["power_before"], rep["power_after"]))
    print("  coordinates changed: %s" % ("yes" if rep["changed"] else "no (already packed)"))
    if args.dry_run:
        print("  dry-run: nothing written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
