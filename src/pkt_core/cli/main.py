"""``pkt`` — command-line interface for Packet Tracer container files.

A deliberately thin consumer of :mod:`pkt_core`. Nothing here contains format
logic; if a behaviour needs to know about cipher or framing details it belongs in
the library, not in this module.

    pkt info   lab.pkt
    pkt unpack lab.pkt -o out/
    pkt pack   out/lab.xml -o lab.pkt
    pkt diff   a.pkt b.pkt
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Sequence

from pkt_core import (
    DEFAULT_FORMAT,
    FORMATS,
    Container,
    PacketTracerError,
    decode,
    decode_bytes,
    encode,
    encode_bytes,
    root_tag,
)
from pkt_core.audit import TemplateLeftovers, validate_lab
from pkt_core.diff import diff_labs
from pkt_core.export import EXPORTERS, export
from pkt_core.models import Lab, RunningConfig

__all__ = ["main", "cmd_info", "cmd_unpack", "cmd_pack", "cmd_diff", "cmd_export", "cmd_audit"]

_PROG = "pkt"


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------
def _load(path: Path) -> Container:
    return decode(path)


def _xml_text(xml: bytes) -> list[str]:
    return xml.decode("utf-8", "replace").splitlines(keepends=True)


# --------------------------------------------------------------------------
# pkt info
# --------------------------------------------------------------------------
def cmd_info(args: argparse.Namespace) -> int:
    """Decrypt just enough to describe the file."""
    path: Path = args.file
    raw = path.read_bytes()
    container = decode_bytes(raw, verify_tag=not args.no_verify)

    print(f"file        : {path}")
    print(f"size        : {len(raw):,} bytes")
    print(f"format      : {container.format_name}")
    print(f"cipher      : {container.spec.cipher}")
    print(f"key byte    : 0x{container.spec.key_byte:02x}  (repeated x16)")
    print(f"iv byte     : 0x{container.spec.iv_byte:02x}  (repeated x16)")
    print(f"root tag    : {container.root_tag}")
    print(f"kind        : {'scored activity (.pka)' if container.is_activity else 'network lab (.pkt)'}")
    print(f"xml bytes   : {len(container.xml):,}")
    if args.json:
        print(json.dumps({
            "path": str(path),
            "size": len(raw),
            "format": container.format_name,
            "cipher": container.spec.cipher,
            "key_byte": f"0x{container.spec.key_byte:02x}",
            "iv_byte": f"0x{container.spec.iv_byte:02x}",
            "root_tag": container.root_tag,
            "is_activity": container.is_activity,
            "xml_bytes": len(container.xml),
        }, indent=2))
    return 0


# --------------------------------------------------------------------------
# pkt unpack
# --------------------------------------------------------------------------
def _safe_name(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value).strip("_") or "unnamed"


def cmd_unpack(args: argparse.Namespace) -> int:
    """Unpack a container into XML, device configs and a topology graph.

    Produces:

    ``<stem>.xml``           the complete inner document, byte-exact
    ``<stem>.container.json`` container metadata (format, cipher, keys, root)
    ``configs/<device>.cfg``  each device's IOS running configuration
    ``topology.dot``          Graphviz rendering of the network
    ``topology.json``         device/link inventory for tooling
    """
    path: Path = args.file
    container = _load(path)

    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = path.stem if not path.name.lower().endswith(".pkt.pka") else path.name[:-8]

    xml_path = out_dir / f"{stem}.xml"
    xml_path.write_bytes(container.xml)

    meta = {
        "source_file": path.name,
        "source_size": path.stat().st_size,
        "format": container.format_name,
        "cipher": container.spec.cipher,
        "key_byte": f"0x{container.spec.key_byte:02x}",
        "iv_byte": f"0x{container.spec.iv_byte:02x}",
        "root_tag": container.root_tag,
        "is_activity": container.is_activity,
        "xml_bytes": len(container.xml),
    }
    meta_path = out_dir / f"{stem}.container.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    lab = Lab.from_bytes(container.xml)

    # per-device IOS running configuration
    cfg_dir = out_dir / "configs"
    written_cfgs = 0
    if args.configs:
        cfg_dir.mkdir(exist_ok=True)
        for dev in lab.devices:
            engine = dev.element.find("ENGINE")
            if engine is None:
                continue
            node = engine.find("RUNNINGCONFIG")
            if node is None:
                continue
            lines = RunningConfig.from_element(node).lines
            if not lines:
                continue
            # raw bytes on purpose: config text carries ^C banner delimiters
            (cfg_dir / f"{_safe_name(dev.name)}.cfg").write_bytes(b"\n".join(lines) + b"\n")
            written_cfgs += 1

    # topology graph + inventory
    if args.topology:
        from pkt_core.export import to_graphviz, to_netbox

        (out_dir / "topology.dot").write_text(to_graphviz(lab), encoding="utf-8")
        (out_dir / "topology.json").write_text(to_netbox(lab), encoding="utf-8")

    print(f"xml      -> {xml_path}  ({len(container.xml):,} bytes)")
    print(f"meta     -> {meta_path}")
    if args.configs:
        print(f"configs  -> {cfg_dir}/  ({written_cfgs} device configs)")
    if args.topology:
        print(f"topology -> {out_dir / 'topology.dot'}, {out_dir / 'topology.json'}")
    print(f"kind     : {'scored activity' if container.is_activity else 'network lab'}")
    print(f"network  : {len(lab.devices)} devices, {len(lab.links)} links")
    return 0


# --------------------------------------------------------------------------
# pkt pack
# --------------------------------------------------------------------------
def cmd_pack(args: argparse.Namespace) -> int:
    """Re-serialise XML back into a container."""
    src: Path = args.file
    xml = src.read_bytes()

    detected = root_tag(xml)
    if args.output.exists() and not args.force:
        print(f"error: {args.output} exists (use --force to overwrite)", file=sys.stderr)
        return 1

    encode(args.output, xml, args.format, level=args.level)
    out_size = args.output.stat().st_size
    print(f"xml   : {len(xml):,} bytes  (root <{detected}>)")
    print(f"format: {args.format}")
    print(f"wrote -> {args.output}  ({out_size:,} bytes)")

    if args.verify:
        again = decode(args.output)
        if again.xml != xml:
            print("error: round-trip verification FAILED", file=sys.stderr)
            return 1
        print("round-trip: OK (decoded bytes match the input XML exactly)")
    return 0


# --------------------------------------------------------------------------
# pkt diff
# --------------------------------------------------------------------------
def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two containers semantically.

    Devices and links are matched by name / endpoint identity, so reordering the
    document is not reported as a change. Exit status is 0 when the two are
    semantically identical, 1 when they differ — script-friendly.
    """
    a = _load(args.file_a)
    b = _load(args.file_b)

    print(f"{'field':<12} {'A':<28} {'B':<28}")
    print("-" * 70)
    same_container = True
    for name, va, vb in (
        ("format", a.format_name, b.format_name),
        ("root tag", a.root_tag, b.root_tag),
        ("xml bytes", f"{len(a.xml):,}", f"{len(b.xml):,}"),
    ):
        mark = " " if va == vb else "*"
        if va != vb:
            same_container = False
        print(f"{mark}{name:<11} {va:<28} {vb:<28}")

    diff = diff_labs(Lab.from_bytes(a.xml), Lab.from_bytes(b.xml))
    lines = diff.summary_lines()

    if diff.identical and same_container and a.xml == b.xml:
        print("\nDocuments are identical.")
        return 0

    if diff.identical:
        print("\nNo semantic network differences (documents differ only in layout/metadata).")
        return 0 if same_container else 1

    print(f"\n{len(lines)} semantic difference(s):")
    for line in lines:
        print(f"  {line}")

    if args.unified:
        text_a = _xml_text(a.xml)
        text_b = _xml_text(b.xml)
        sys.stdout.writelines(
            difflib.unified_diff(
                text_a, text_b,
                fromfile=str(args.file_a), tofile=str(args.file_b),
                n=args.context,
            )
        )
    return 1


def cmd_export(args: argparse.Namespace) -> int:
    """Render the topology for external tooling."""
    container = _load(args.file)
    lab = Lab.from_bytes(container.xml)
    rendered = export(lab, args.format)

    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote -> {args.output}  ({args.format})")
    else:
        sys.stdout.write(rendered)
    return 0


# --------------------------------------------------------------------------
# pkt audit
# --------------------------------------------------------------------------
def cmd_audit(args: argparse.Namespace) -> int:
    """Report service counts and prove every counted item distinct.

    This is the documented command behind the published service figures: it
    prints raw *and* distinct counts per family, flags template leftovers and
    fails (exit 1) on any duplicate.  ``--templates`` classifies records a
    harvested device template carried (never authored) as leftovers.
    """
    container = _load(args.file)
    lab = Lab.from_bytes(container.xml)
    leftovers = (
        TemplateLeftovers.from_device_templates_json(args.templates)
        if args.templates is not None
        else None
    )
    report = validate_lab(lab, leftovers=leftovers)
    if args.json:
        payload = report.inventory.as_dict()
        payload["findings"] = [
            {"severity": f.severity, "code": f.code, "message": f.message}
            for f in report.findings
        ]
        payload["ok"] = report.ok
        print(json.dumps(payload, indent=2))
    else:
        print(report.summary())
    return 0 if report.ok else 1


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=_PROG,
        description="Read, write and compare Cisco Packet Tracer .pkt/.pka containers.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("info", help="describe a container")
    p.add_argument("file", type=Path)
    p.add_argument("--no-verify", action="store_true", help="skip AEAD tag check")
    p.add_argument("--json", action="store_true", help="also print machine-readable output")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser(
        "unpack",
        help="extract XML, device configs and a topology graph",
    )
    p.add_argument("file", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True, help="output directory")
    p.add_argument(
        "--configs", action="store_true", default=True,
        help="write per-device IOS running configs (default on)",
    )
    p.add_argument(
        "--no-configs", dest="configs", action="store_false",
        help="skip per-device IOS running configs",
    )
    p.add_argument(
        "--topology", action="store_true", default=True,
        help="write topology.dot and topology.json (default on)",
    )
    p.add_argument(
        "--no-topology", dest="topology", action="store_false",
        help="skip the topology graph",
    )
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("pack", help="build a container from XML")
    p.add_argument("file", type=Path, help="input XML file")
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--format", default=DEFAULT_FORMAT, choices=sorted(FORMATS))
    p.add_argument("--level", type=int, default=-1, help="zlib level (-1 default)")
    p.add_argument("--force", action="store_true", help="overwrite the output")
    p.add_argument("--verify", action="store_true", help="decode again and compare")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("export", help="render topology for external tooling")
    p.add_argument("file", type=Path)
    p.add_argument("--format", default="graphviz", choices=sorted(EXPORTERS))
    p.add_argument("-o", "--output", type=Path, help="write to file instead of stdout")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("diff", help="compare two containers")
    p.add_argument("file_a", type=Path)
    p.add_argument("file_b", type=Path)
    p.add_argument("-u", "--unified", action="store_true", help="emit a unified XML diff")
    p.add_argument("-C", "--context", type=int, default=3)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser(
        "audit",
        help="count services and prove each counted item distinct",
    )
    p.add_argument("file", type=Path)
    p.add_argument(
        "--templates",
        type=Path,
        default=None,
        help="device_templates.json: classify template-carried records as leftovers",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_audit)

    return ap


def main(argv: Sequence[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        return int(args.func(args))
    except PacketTracerError as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
