"""Scoring tree generation for Packet Tracer activities (.pka).

Packet Tracer validates scoring trees against the network's item model.
This module generates <INITIALSETUP> and <COMPARISONS> scoring trees either by
cloning complete device nodes from a reference activity or by retargeting
harvested device shapes.
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "SCAFFOLD_NAMES",
    "from_template",
    "derive_values",
    "harvest_shapes",
    "save_shapes",
    "load_shapes",
    "from_shapes",
]

SCAFFOLD_NAMES: frozenset[str] = frozenset(
    {
        "Instruction",
        "Resource",
        "ConnectivityTests",
        "CodeTesting",
        "Remote Network",
        "Remote Networks",
        "Encircling Tests",
    }
)


def _section(xml: str, tag: str) -> str:
    a = xml.find(f"<{tag}>")
    b = xml.find(f"</{tag}>", a) + len(f"</{tag}>")
    return xml[a:b]


def _net_node(root: ET.Element) -> ET.Element:
    node = root.find("NODE")
    if node is None:
        raise ValueError("Root element has no child <NODE>")
    return node


def _device_nodes(net_node: ET.Element) -> list[ET.Element]:
    out: list[ET.Element] = []
    for c in net_node:
        if c.tag == "NODE":
            nm = c.findtext("NAME") or ""
            if nm not in SCAFFOLD_NAMES:
                out.append(c)
    return out


def from_template(
    template_xml: str | bytes,
    devices: list[str] | set[str] | None = None,
    overrides: Mapping[str, Mapping[str, Any]] | None = None,
    rename: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Clone complete device nodes from a template activity XML.

    Args:
        template_xml: Raw XML string or bytes of an activity containing device nodes.
        devices: Specific device names to keep (defaults to all in template).
        overrides: {device_name: {item_id: value}} to set expected values.
        rename: {old_name: new_name} device renames.

    Returns:
        A tuple of (initialsetup_xml, comparisons_xml).
    """
    if isinstance(template_xml, bytes):
        template_xml = template_xml.decode("utf-8", "replace")
    rename_map = rename or {}
    override_map = overrides or {}

    def build(tag: str, with_scaffold: bool) -> str:
        seg = _section(template_xml, tag)
        root = ET.fromstring(seg)
        net = _net_node(root)
        devs = _device_nodes(net)
        kept: list[ET.Element] = []
        if with_scaffold:
            for c in net:
                if c.tag == "NODE" and c not in devs:
                    kept.append(c)
        for d in devs:
            nm = d.findtext("NAME") or ""
            if devices is not None and nm not in devices:
                continue
            clone = ET.fromstring(ET.tostring(d))
            new_name = rename_map.get(nm, nm)
            for e in clone.iter("NAME"):
                if e.text == nm:
                    e.text = new_name
            for e in clone.iter("ID"):
                if e.text == nm:
                    e.text = new_name
            for e in clone.iter("NODE"):
                lbl = e.findtext("NAME")
                idn = e.findtext("ID")
                for key, val in override_map.get(new_name, {}).items():
                    if lbl == key or idn == key:
                        for nmel in e.iter("NAME"):
                            if nmel.text == lbl:
                                nmel.set("nodeValue", str(val))
            kept.append(clone)
        for c in list(net):
            net.remove(c)
        for c in kept:
            net.append(c)
        body = ET.tostring(net, encoding="unicode")
        if tag == "INITIALSETUP":
            return f"<INITIALSETUP>{body}<LOAD_INIT_TREE>true</LOAD_INIT_TREE></INITIALSETUP>"
        return f"<COMPARISONS>{body}</COMPARISONS>"

    return build("INITIALSETUP", with_scaffold=False), build(
        "COMPARISONS", with_scaffold=True
    )


def derive_values(answer_xml: str | bytes) -> dict[str, dict[str, str]]:
    """Return {device_name: {item_id: expected_value}} from a decoded answer network."""
    if isinstance(answer_xml, bytes):
        answer_xml = answer_xml.decode("utf-8", "replace")
    out: dict[str, dict[str, str]] = {}
    for m in re.finditer(r"<DEVICE>.*?</DEVICE>", answer_xml, re.S):
        blk = m.group(0)
        nm = re.search(r"<NAME[^>]*>([^<]*)</NAME>", blk)
        if not nm:
            continue
        name = nm.group(1)
        vals: dict[str, str] = {}
        model = re.search(r'<TYPE[^>]*model="([^"]*)"', blk)
        if model:
            vals["Device Model"] = model.group(1)
        rc = re.search(r"<RUNNINGCONFIG>(.*?)</RUNNINGCONFIG>", blk, re.S)
        if rc:
            for line in re.findall(r"<LINE>(.*?)</LINE>", rc.group(1), re.S):
                line = (
                    line.replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&")
                )
                ma = re.match(r"\s*ip address (\S+) (\S+)", line)
                if ma:
                    vals["IP Address"] = ma.group(1)
                    vals["Subnet Mask"] = ma.group(2)
                if re.match(r"\s*no shutdown", line):
                    vals["Port Up"] = "1"
        ip = re.search(r"<IP>([^<]*)</IP>", blk)
        gw = re.search(r"<PORT_GATEWAY>([^<]*)</PORT_GATEWAY>", blk)
        if ip and ip.group(1):
            vals["IP Address"] = ip.group(1)
        if gw and gw.group(1):
            vals["Default Gateway"] = gw.group(1)
        out[name] = vals
    return out


def _model_of(comp_node: ET.Element) -> str | None:
    for e in comp_node.iter("NODE"):
        if e.findtext("ID") == "Device Model":
            nm = e.find("NAME")
            return nm.get("nodeValue") if nm is not None else None
    return None


def harvest_shapes(activity_xmls: list[str | bytes]) -> dict[str, Any]:
    """Harvest shape definitions from decoded activity XMLs."""
    scaffold: list[str] = []
    scaffold_seen: set[str] = set()
    models: dict[str, dict[str, str | None]] = {}
    for xml in activity_xmls:
        if isinstance(xml, bytes):
            xml = xml.decode("utf-8", "replace")
        try:
            init_root = ET.fromstring(_section(xml, "INITIALSETUP"))
            comp_root = ET.fromstring(_section(xml, "COMPARISONS"))
        except ET.ParseError:
            continue
        inet, cnet = init_root.find("NODE"), comp_root.find("NODE")
        if inet is None or cnet is None:
            continue
        init_by_name = {c.findtext("NAME"): c for c in inet if c.tag == "NODE"}
        for c in cnet:
            if c.tag != "NODE":
                continue
            nm = c.findtext("NAME") or ""
            if nm in SCAFFOLD_NAMES:
                if nm not in scaffold_seen:
                    scaffold.append(ET.tostring(c, encoding="unicode"))
                    scaffold_seen.add(nm)
                continue
            model = _model_of(c)
            if not model or model in models:
                continue
            inode = init_by_name.get(nm)
            models[model] = {
                "init": (
                    ET.tostring(inode, encoding="unicode")
                    if inode is not None
                    else None
                ),
                "comp": ET.tostring(c, encoding="unicode"),
            }
    return {"scaffold": scaffold, "models": models}


def save_shapes(shapes: Mapping[str, Any], path: str | Path) -> None:
    import gzip

    with open(path, "wb") as f:
        f.write(gzip.compress(json.dumps(shapes).encode("utf-8"), 9))


def load_shapes(path: str | Path) -> dict[str, Any]:
    import gzip

    b = Path(path).read_bytes()
    if b[:2] == b"\x1f\x8b":
        b = gzip.decompress(b)
    data: dict[str, Any] = json.loads(b)
    return data


def _retarget(
    node_xml: str, name: str, overrides: Mapping[str, Any] | None
) -> str:
    el = ET.fromstring(node_xml)
    old = el.findtext("NAME")
    for e in el.iter("NAME"):
        if e.text == old:
            e.text = name
    for e in el.iter("ID"):
        if e.text == old:
            e.text = name
    for e in el.iter("NODE"):
        lbl, idn = e.findtext("NAME"), e.findtext("ID")
        for key, val in (overrides or {}).items():
            if lbl == key or idn == key:
                for nmel in e.iter("NAME"):
                    if nmel.text == lbl:
                        nmel.set("nodeValue", str(val))
    return ET.tostring(el, encoding="unicode")


def from_shapes(
    spec: list[dict[str, Any]], shapes: Mapping[str, Any]
) -> tuple[str, str]:
    """Build (initialsetup_xml, comparisons_xml) from harvested shapes."""
    init_nodes: list[str] = []
    comp_nodes: list[str] = []
    missing: list[str] = []
    models_dict = shapes.get("models", {})
    for d in spec:
        model = d["model"]
        if model not in models_dict:
            missing.append(model)
            continue
        sh = models_dict[model]
        if sh.get("init"):
            init_nodes.append(
                _retarget(sh["init"], d["name"], d.get("overrides"))
            )
        comp_nodes.append(_retarget(sh["comp"], d["name"], d.get("overrides")))
    net_open = (
        '<NODE><NAME checkType="0" eclass="8" headNode="true" '
        'incorrectFeedback="" nodeValue="" obfuscateName="false" overrideDBGrading="false" '
        'variableEnabled="false" variableName="">Network</NAME><ID>Network</ID>'
        "<COMPONENTS></COMPONENTS><POINTS></POINTS>"
    )
    net_close = "</NODE>"
    initialsetup = (
        f"<INITIALSETUP>{net_open}{''.join(init_nodes)}{net_close}"
        "<LOAD_INIT_TREE>true</LOAD_INIT_TREE></INITIALSETUP>"
    )
    comparisons = (
        f"<COMPARISONS>{net_open}{''.join(shapes.get('scaffold', []))}{''.join(comp_nodes)}{net_close}</COMPARISONS>"
    )
    if missing:
        print(
            f"scoring: no shape for {sorted(set(missing))} (not graded)",
            file=sys.stderr,
        )
    return initialsetup, comparisons
