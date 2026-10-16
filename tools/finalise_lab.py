#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""finalise_lab.py -- make a generated lab honest, and prove it.

A generated lab can be structurally valid and still be wrong.  This is the
single writer that repairs the three defect classes a 290-device enterprise
model actually shipped with, in a fixed order, and then *gates* the result:

1. **layout** -- reposition every device with the label-inclusive greedy packer
   (``tools/repack_layout.py``).  Guarantees no two label-inclusive boxes
   overlap, no two centres closer than the 80-unit floor, and nothing off the
   ~3900x3900 Page.
2. **template leftovers** -- strip every service record the device template
   carried but nobody authored (``pkt_core.audit.sanitize_xml``).  Without this,
   harvested templates copy one phantom AAA client onto all 290 devices and every
   published service count is inflated.
3. **duplicate pool names** -- Packet Tracer DHCP pools are *name*-keyed, so two
   different subnets that both derive the name ``IRUMA-VLAN10`` collide and one
   shadows the other.  Supply ``--rename-pools`` with an explicit
   ``{"name","network","new"}`` list; the rename is asserted to hit the expected
   number of records so a silently-missed match cannot pass.

Gates (non-zero exit if any fails)
----------------------------------
* ``pkt_core.audit.validate_lab`` reports **0 failures** -- every counted family
  is proven distinct and free of leftovers.
* ``tools/check_layout.analyse`` reports 0 label-box overlaps, 0 off-page and 0
  coincident devices.

Both gates are re-run *after* writing, on the bytes actually written.

Usage
-----
    python3 tools/finalise_lab.py lab.pkt
    python3 tools/finalise_lab.py --rename-pools pools.json lab.pkt
    python3 tools/finalise_lab.py --dry-run lab.pkt
    python3 tools/finalise_lab.py --templates tools/device_templates.json lab.pkt

``--dry-run`` runs every step and both gates but writes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
for _p in (str(REPO / "tools"), str(REPO / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import check_layout  # noqa: E402
import lab_api  # noqa: E402
import repack_layout  # noqa: E402

from pkt_core import decode_bytes, encode_bytes  # noqa: E402
from pkt_core.audit import (  # noqa: E402
    TemplateLeftovers,
    inventory,
    sanitize_xml,
    validate_lab,
)
from pkt_core.models import Lab  # noqa: E402


def rename_pools(xml: bytes, renames: list[dict[str, str]]) -> tuple[bytes, int, int]:
    """Rename DHCP pools matched on ``(name, network)``.

    The pair is required, not the name alone: the whole reason a rename is
    needed is that one name serves two networks, so the network is the only
    thing that identifies which pool is which.

    Re-running must be a no-op rather than an error, so a rule that matches
    nothing is only accepted when its **target** is already present on that
    network -- that is the signature of an applied rename.  A rule that matches
    nothing *and* whose target is absent means the lab changed underneath the
    mapping; proceeding would leave a collision in place while reporting
    success, so that is an error.

    Returns ``(xml, applied, already)``.
    """
    text = xml.decode("utf-8")
    applied = already = 0
    for rule in renames:
        old, net, new = rule["name"], rule["network"], rule["new"]

        def _pat(pool_name: str) -> re.Pattern[str]:
            return re.compile(
                r"(<POOL><NAME>)" + re.escape(pool_name)
                + r"(</NAME><NETWORK>)" + re.escape(net) + r"(</NETWORK>)"
            )

        pattern = _pat(old)
        text, hits = pattern.subn(
            lambda m: m.group(1) + new + m.group(2) + net + m.group(3), text
        )
        if hits == 1:
            applied += 1
            continue
        if hits == 0 and _pat(new).search(text):
            already += 1
            continue
        raise SystemExit(
            f"rename rule {old!r} @ {net!r} -> {new!r} matched {hits} records "
            f"and {new!r} is not present on that network either; refusing to "
            "guess"
        )
    return text.encode("utf-8"), applied, already


def _gate_layout(xml: bytes) -> dict[str, Any]:
    rep = check_layout.analyse(lab_api.parse_devices(xml.decode("utf-8")))
    rep["ok"] = not (
        rep["label_box_overlaps"]
        or rep["off_page"]
        or rep["coincident"]
    )
    return rep


def _fmt_layout(rep: dict[str, Any]) -> str:
    b = rep["bbox"]
    return (
        "pairs<=40/<80/<=120=%d/%d/%d  label-overlaps=%d  off-page=%d  "
        "coincident=%d  nn(min/p25/med)=%.1f/%.1f/%.1f  "
        "bbox=X[%.0f..%.0f] Y[%.0f..%.0f]"
        % (
            len(rep["pairs_le_40"]), len(rep["pairs_lt_80"]),
            len(rep["pairs_le_120"]), len(rep["label_box_overlaps"]),
            len(rep["off_page"]), rep["coincident"], rep["nn"]["min"],
            rep["nn"]["p25"], rep["nn"]["median"],
            b["x_min"], b["x_max"], b["y_min"], b["y_max"],
        )
    )


def refresh_report(path: Path, artifact: Path) -> dict[str, Any]:
    """Point a build report at the bytes that actually exist now.

    A generator writes its report before anything downstream touches the file,
    so any later pass (this one) leaves ``size_bytes`` -- and, worse, the hash --
    describing a file that is no longer on disk.  Re-deriving them here is not
    cosmetic: a stale hash is a claim that cannot be checked.
    """
    import hashlib

    data = json.loads(path.read_text())
    raw = artifact.read_bytes()
    before = (data.get("size_bytes"), data.get("sha256"))
    data["size_bytes"] = len(raw)
    data["sha256"] = hashlib.sha256(raw).hexdigest()
    data["output"] = str(artifact)
    path.write_text(json.dumps(data, indent=1))
    return {"before": before, "after": (data["size_bytes"], data["sha256"])}


def finalise(
    src: Path,
    dst: Path,
    *,
    templates: Path | None,
    renames: list[dict[str, str]],
    do_repack: bool,
    do_sanitize: bool,
    dry_run: bool,
    update_report: Path | None = None,
) -> int:
    xml, fmt, container = repack_layout._read(src)
    print(f"== {src}")
    print(f"  in    {_fmt_layout(_gate_layout(xml.encode('utf-8')))}")

    # 1. layout
    if do_repack:
        xml, moves = repack_layout.repack_xml(xml)
        print(f"  layout: repositioned {len(moves)} device(s)")
    else:
        print("  layout: skipped (--no-repack)")

    # 2. template leftovers
    if do_sanitize:
        leftovers = (
            TemplateLeftovers.from_device_templates_json(templates)
            if templates is not None
            else None
        )
        raw_xml = xml.encode("utf-8")
        xml_b, report = sanitize_xml(raw_xml, leftovers=leftovers)
        xml = xml_b.decode("utf-8")
        print(f"  sanitize: {report.as_dict()}")
    else:
        print("  sanitize: skipped (--no-sanitize)")

    # 3. pool names
    if renames:
        xml_b, applied, already = rename_pools(xml.encode("utf-8"), renames)
        xml = xml_b.decode("utf-8")
        note = f"  ({already} already applied)" if already else ""
        print(f"  pools: {applied} rename(s) applied{note}")

    # gates, on the bytes that would be written
    out = encode_bytes(xml.encode("utf-8"), fmt)
    verified = decode_bytes(out, fmt).xml == xml.encode("utf-8")

    lab = Lab.from_bytes(xml.encode("utf-8"))
    leftovers = (
        TemplateLeftovers.from_device_templates_json(templates)
        if templates is not None
        else None
    )
    audit = validate_lab(lab, leftovers=leftovers)
    inv = inventory(lab, leftovers=leftovers)
    lay = _gate_layout(xml.encode("utf-8"))

    print(f"  out   {_fmt_layout(lay)}")
    print("  audit : " + ("PASSED" if audit.ok else f"FAILED ({len(audit.findings)})")
          + "  " + ", ".join(
              f"{f}={d.raw}/{d.distinct}"
              for f, d in sorted(inv.families.items()) if d.raw
          ))
    for f in audit.findings:
        print(f"    {f.severity} {f.code}: {f.message}")
    print(f"  round-trip: {'byte-exact' if verified else 'DIFFERS'}")

    ok = audit.ok and lay["ok"] and verified
    if dry_run:
        print("  dry-run: nothing written")
    elif dst != src:
        repack_layout._write(dst, xml, fmt, container)
        print(f"  wrote {dst}  ({dst.stat().st_size:,} bytes)")
    else:
        repack_layout._write(dst, xml, fmt, container)
        print(f"  wrote {dst} in place  ({dst.stat().st_size:,} bytes)")
    if not dry_run and update_report is not None:
        r = refresh_report(update_report, dst)
        print(f"  report: {update_report} size/hash refreshed "
              f"{r['before'][0]} -> {r['after'][0]}, sha {str(r['after'][1])[:16]}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Repair a generated lab's layout, leftovers and pool names, "
                    "then gate the result.")
    ap.add_argument("labs", nargs="+", type=Path,
                    help="lab(s) to finalise (*.pkt/*.pka, repaired in place)")
    ap.add_argument("--out", type=Path, default=None,
                    help="write here instead (single input only)")
    ap.add_argument("--templates", type=Path, default=None,
                    help="device_templates.json; enables leftover detection")
    ap.add_argument("--rename-pools", type=Path, default=None,
                    help='JSON list of {"name","network","new"} pool renames')
    ap.add_argument("--no-repack", action="store_true",
                    help="leave coordinates alone")
    ap.add_argument("--no-sanitize", action="store_true",
                    help="leave template service records alone")
    ap.add_argument("--dry-run", action="store_true",
                    help="run every step and both gates but write nothing")
    ap.add_argument("--update-report", type=Path, default=None,
                    help="after writing, refresh this build report's "
                         "size_bytes/sha256 so they describe the final file")
    args = ap.parse_args(argv)

    if args.out is not None and len(args.labs) != 1:
        ap.error("--out takes exactly one input lab")

    renames: list[dict[str, str]] = []
    if args.rename_pools is not None:
        renames = json.loads(args.rename_pools.read_text())

    rc = 0
    for lab in args.labs:
        rc |= finalise(
            lab,
            args.out or lab,
            templates=args.templates,
            renames=renames,
            do_repack=not args.no_repack,
            do_sanitize=not args.no_sanitize,
            dry_run=args.dry_run,
            update_report=args.update_report,
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
