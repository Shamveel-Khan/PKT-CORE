"""Lab builder: programmatically construct Cisco Packet Tracer labs (.pkt).

Supports placing devices, configuring IOS commands, assigning IP addresses,
installing modular cards (e.g. HWIC-2T), cabling copper and serial links,
and physical workspace scene graph placement without Packet Tracer.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pkt_core.builder.layout import Layout, kind_for_model
from pkt_core.codec import decode_bytes, encode
from pkt_core.errors import (
    DeviceNameConflictError,
    DeviceNotFoundError,
    InvalidCableError,
    ModuleBayError,
)
from pkt_core.resources import load_bundled_seed_xml, load_bundled_templates

if TYPE_CHECKING:
    from pkt_core.models.lab import Lab as LabView


# --------------------------------------------------------------------------- #
# Harvesting device / module templates from existing .pkt files
# --------------------------------------------------------------------------- #
def _iter_devices(xml: bytes) -> Iterable[re.Match[bytes]]:
    return re.finditer(rb"<DEVICE>.*?</DEVICE>", xml, re.S)


# engine-level <POWER> sits directly after <NAME> (child index 2 of <ENGINE>);
# per-port <PORT><POWER> follows <TYPE> and must never be touched here.
_ENG_POWER_RE = re.compile(
    rb"(<NAME[^>]*>.*?</NAME>\s*)<POWER>([^<]*)</POWER>", re.S
)
_ENG_NAME_RE = re.compile(rb"(<NAME[^>]*>.*?</NAME>)", re.S)


def normalise_device_power(blk: bytes) -> tuple[bytes, bool]:
    """Force a harvested <DEVICE> block's <ENGINE><POWER> to "true".

    Harvested templates are taken verbatim from donor saves, so a device that
    happened to be switched off in the donor poisons every lab built from that
    model (see docs/POWER_INVESTIGATION.md: the 3650-24PS template shipped
    <POWER>false</POWER> and took the whole aggregation layer down with it).
    Returns (block, was_off) where was_off records that the donor save had the
    device off (absent counts as off too -- PT never omits the element). Only
    the device-level element is rewritten; <PORT><POWER> is left as harvested.
    """
    state = {"off": False}

    def repl(m: re.Match[bytes]) -> bytes:
        if m.group(2).strip().lower() != b"true":
            state["off"] = True
        return m.group(1) + b"<POWER>true</POWER>"

    new, n = _ENG_POWER_RE.subn(repl, blk, count=1)
    if n == 0:
        new = _ENG_NAME_RE.sub(rb"\1\n     <POWER>true</POWER>", blk, count=1)
        if new != blk:
            state["off"] = True  # PT never omits <POWER>: absent is a defect
    return new, state["off"]


def load_templates(path: str | Path) -> tuple[dict[str, bytes], dict[str, str]]:
    """Load an external device/module template library (gzip+base64 JSON).

    For the bundled template library, use :func:`pkt_core.resources.load_bundled_templates`
    or omit template parameters when instantiating :class:`Lab`.
    """
    import base64
    import gzip
    import json

    with open(path, "r", encoding="utf-8") as f:
        t = json.load(f)
    gz = t.get("gz", False)

    def dec(v: str) -> bytes:
        b = base64.b64decode(v)
        return gzip.decompress(b) if gz else b

    return (
        {k: dec(v) for k, v in t["models"].items()},
        {k: dec(v).decode("utf-8") for k, v in t.get("modules", {}).items()},
    )


def harvest_models(
    saves_dir: str | Path, wanted: set[str] | None = None
) -> dict[str, bytes]:
    """Return {model: <DEVICE> bytes} taking the first instance of each model."""
    import glob

    out: dict[str, bytes] = {}
    files = sorted(
        glob.glob(os.path.join(str(saves_dir), "**", "*.pkt"), recursive=True),
        key=os.path.getsize,
    )
    for f in files:
        if wanted and wanted <= set(out):
            break
        try:
            raw = Path(f).read_bytes()
            xml = decode_bytes(raw, "pkt", verify_tag=False).xml
        except Exception:
            continue
        for m in _iter_devices(xml):
            mm = re.search(rb'<TYPE[^>]*model="([^"]*)"', m.group(0))
            if not mm:
                continue
            model = mm.group(1).decode("utf-8", "replace")
            if (wanted is None or model in wanted) and model not in out:
                blk, _was_off = normalise_device_power(m.group(0))
                out[model] = blk
    return out


def harvest_modules(
    saves_dir: str | Path, wanted: set[str]
) -> dict[str, str]:
    """Return {module_model: <SLOT> xml str} for modules found in devices."""
    import glob

    out: dict[str, str] = {}
    for f in sorted(
        glob.glob(os.path.join(str(saves_dir), "**", "*.pkt"), recursive=True),
        key=os.path.getsize,
    ):
        if wanted <= set(out):
            break
        try:
            raw = Path(f).read_bytes()
            xml = (
                decode_bytes(raw, "pkt", verify_tag=False)
                .xml.decode("utf-8", "replace")
            )
        except Exception:
            continue
        for model in set(re.findall(r"<MODEL>([^<]+)</MODEL>", xml)) & wanted:
            if model in out:
                continue
            i = xml.find(f"<MODEL>{model}</MODEL>")
            a = xml.rfind("<SLOT>", 0, i)
            b = xml.find("</SLOT>", i) + len("</SLOT>")
            if a >= 0 and b > a:
                out[model] = xml[a:b]
    return out


def _det_uuid(*parts: object) -> str:
    """Return a *deterministic* RFC-4122 v4 UUID for reproducible builds."""
    digest = hashlib.sha256(
        "\x00".join(str(p) for p in parts).encode("utf-8")
    ).digest()
    b = bytearray(digest[:16])
    b[6] = (b[6] & 0x0F) | 0x40  # version 4
    b[8] = (b[8] & 0x3F) | 0x80  # RFC 4122 variant
    return str(uuid.UUID(bytes=bytes(b)))


_MODEL_ALIASES: dict[str, str] = {
    "router_2901": "2901",
    "router-2901": "2901",
    "router2901": "2901",
    "router_2911": "2911",
    "router-2911": "2911",
    "router2911": "2911",
    "router_1941": "1941",
    "router-1941": "1941",
    "router1941": "1941",
    "router_1841": "1841",
    "router-1841": "1841",
    "router1841": "1841",
    "router_2811": "2811",
    "router-2811": "2811",
    "router2811": "2811",
    "router_4321": "ISR4321",
    "router-4321": "ISR4321",
    "isr_4321": "ISR4321",
    "4321": "ISR4321",
    "router_4331": "ISR4331",
    "router-4331": "ISR4331",
    "isr_4331": "ISR4331",
    "4331": "ISR4331",
    "switch_2960": "2960-24TT",
    "switch-2960": "2960-24TT",
    "switch2960": "2960-24TT",
    "2960": "2960-24TT",
    "switch_2950": "2950-24",
    "switch-2950": "2950-24",
    "switch2950": "2950-24",
    "2950": "2950-24",
    "switch_3560": "3560-24PS",
    "switch-3560": "3560-24PS",
    "switch3560": "3560-24PS",
    "3560": "3560-24PS",
    "switch_3650": "3650-24PS",
    "switch-3650": "3650-24PS",
    "switch3650": "3650-24PS",
    "3650": "3650-24PS",
    "pc": "PC-PT",
    "pc_pt": "PC-PT",
    "server": "Server-PT",
    "server_pt": "Server-PT",
    "laptop": "Laptop-PT",
    "laptop_pt": "Laptop-PT",
}


class Lab:
    """High-level builder for constructing and modifying Packet Tracer labs.

    Example::

        from pkt_core import Lab

        lab = Lab()  # Uses bundled seed and templates; starts clean
        r1 = lab.add_device("2911", "R1", 200, 200, install="HWIC-2T")
        sw1 = lab.add_device("2960-24TT", "SW1", 400, 200)
        lab.link(r1, "GigabitEthernet0/0", sw1, "GigabitEthernet0/1")
        lab.save("my_lab.pkt")
    """

    def __init__(
        self,
        seed: str | Path | bytes | None = None,
        models: dict[str, bytes] | None = None,
        modules: dict[str, str] | None = None,
        *,
        auto_prune_seed: bool | None = None,
    ) -> None:
        """Initialize a new Lab builder.

        Args:
            seed: Path to a seed .pkt / XML file, raw XML bytes, or None to use
                the bundled minimal network seed.
            models: Mapping of device model name to XML bytes. Defaults to bundled.
            modules: Mapping of module model name to XML string. Defaults to bundled.
            auto_prune_seed: When True, devices inherited from the seed network
                are dropped immediately. If seed is None, defaults to True.
        """
        if models is None or modules is None:
            b_models, b_modules = load_bundled_templates()
            self.models = models if models is not None else b_models
            self.modules = modules if modules is not None else b_modules
        else:
            self.models = models
            self.modules = modules

        is_default_seed = seed is None
        if seed is None:
            xml_bytes = load_bundled_seed_xml()
        elif isinstance(seed, (str, Path)):
            path = Path(seed)
            raw = path.read_bytes()
            if path.suffix.lower() in (".pkt", ".pka"):
                xml_bytes = decode_bytes(raw, "pkt").xml
            else:
                xml_bytes = raw
        elif isinstance(seed, bytes):
            xml_bytes = seed
        else:
            raise TypeError(f"seed must be a path, bytes, or None; got {type(seed)}")

        self.base: ET.Element = ET.fromstring(xml_bytes)
        net = self.base.find("NETWORK")
        if net is None:
            raise ValueError("Seed XML is missing root <NETWORK> element")
        self.net: ET.Element = net

        devs = self.net.find("DEVICES")
        if devs is None:
            devs = ET.SubElement(self.net, "DEVICES")
        self.devs: ET.Element = devs

        self._pw = self.base.find("PHYSICALWORKSPACE")
        self._wsroot = self._pw.find("NODE") if self._pw is not None else None

        existing = self.devs.findall("DEVICE")
        self._donor_cpur: ET.Element | None = None
        donor_pp: str | None = None
        donor_cid: str | None = None
        if existing:
            dc = existing[0].find("WORKSPACE/PHYSICAL_CPUR")
            if dc is not None:
                self._donor_cpur = copy.deepcopy(dc)
                donor_pp = dc.findtext("PARENT_PATH")
                donor_cid = dc.findtext("CONTAINER_ID")

        self._PP = donor_pp or (
            self._pw.findtext("HOMERACK") if self._pw is not None else None
        )
        self._CID: str | None = None
        self._rack = self._find_container(donor_cid)
        if self._rack is None or not self._PP or not self._CID:
            raise ValueError(
                "seed has no usable physical workspace (need HOMERACK + a Rack container)"
            )

        self._initial_devs = list(existing)
        self._n = 0
        self._pos = 4
        self._mac = 0x2000
        self._els: dict[str, ET.Element] = {}

        # Default seed starts clean so the user doesn't have leftover SW1/R1/PC-A
        should_prune = (
            auto_prune_seed if auto_prune_seed is not None else is_default_seed
        )
        if should_prune and self._initial_devs:
            self.prune_seed_devices()

    # -- physical workspace helpers ---------------------------------------- #
    def _find_container(self, cid: str | None) -> ET.Element | None:
        """Find the container NODE (the Rack) and set self._CID to its UUID."""
        root = self._wsroot
        if root is None:
            return None
        rack = None
        for n in root.iter("NODE"):
            u = n.findtext("UUID_STR")
            if cid and u == cid:
                self._CID = cid
                return n
            if rack is None and (
                n.findtext("TYPE") == "4"
                or "rack" in (n.findtext("NAME") or "").lower()
            ):
                rack = n
        if rack is not None:
            self._CID = rack.findtext("UUID_STR")
        return rack

    def _add_leaf(self, name: str, leaf: str, x: int = 0) -> None:
        if self._rack is None:
            return
        ch = self._rack.find("CHILDREN")
        if ch is None:
            ch = ET.SubElement(self._rack, "CHILDREN")
        el = ET.fromstring(
            f'<NODE><X>{x}</X><Y>0</Y><TYPE>6</TYPE><NAME translate="true">{name}</NAME>'
            "<SX>1</SX><SY>1</SY><W>0</W><H>0</H><D>0</D>"
            "<PATH isanim=\"false\">../art/Background/grid_100x100.png</PATH><CHILDREN/>"
            "<MANUAL_SCALING>false</MANUAL_SCALING><SCALED_PIXMAP_WIDTH>0</SCALED_PIXMAP_WIDTH>"
            "<SCALED_PIXMAP_HEIGHT>0</SCALED_PIXMAP_HEIGHT><INIT_WIDTH>0</INIT_WIDTH><INIT_HEIGHT>0</INIT_HEIGHT>"
            "<INIT_DEPTH>0</INIT_DEPTH><INIT_SX>1</INIT_SX><INIT_SY>1</INIT_SY><INIT_SZ>1</INIT_SZ>"
            "<BG_TILED>false</BG_TILED><CUSTOM_IMAGE_WIDTH>-1</CUSTOM_IMAGE_WIDTH>"
            "<CUSTOM_IMAGE_HEIGHT>-1</CUSTOM_IMAGE_HEIGHT><SCALE_FACTOR>1</SCALE_FACTOR>"
            f"<UUID_STR>{{{leaf}}}</UUID_STR><SLOT>0</SLOT><SUB_SLOT>0</SUB_SLOT>"
            "<ICP_CSX>0</ICP_CSX><ICP_CSY>0</ICP_CSY></NODE>"
        )
        ch.append(el)

    def _make_cpur(self, x: int, leaf: str) -> str:
        c = (
            copy.deepcopy(self._donor_cpur)
            if self._donor_cpur is not None
            else ET.fromstring(
                "<PHYSICAL_CPUR><X_PN>0.03175</X_PN><Y_PN>0.134</Y_PN><X>0</X><Y>0</Y>"
                "<SLOT>0</SLOT><SUBSLOT>0</SUBSLOT><PARENT_PATH></PARENT_PATH>"
                "<CONTAINER_ID></CONTAINER_ID><ICP_CONTAINER_SCENE_X>0</ICP_CONTAINER_SCENE_X>"
                "<ICP_CONTAINER_SCENE_Y>0</ICP_CONTAINER_SCENE_Y>"
                "<ORIGINAL_DEVICE_UUID></ORIGINAL_DEVICE_UUID></PHYSICAL_CPUR>"
            )
        )

        def set_(tag: str, val: str) -> None:
            e = c.find(tag)
            if e is None:
                e = ET.SubElement(c, tag)
            e.text = val

        set_("PARENT_PATH", self._PP or "")
        set_("CONTAINER_ID", self._CID or "")
        set_("X", str(x))
        set_("Y", "0")
        set_("SLOT", "0")
        set_("SUBSLOT", "0")
        set_("ORIGINAL_DEVICE_UUID", f"{{{_det_uuid('cpur', leaf)}}}")
        return ET.tostring(c, encoding="unicode")

    def _next_mac(self) -> str:
        self._mac += 1
        n = self._mac
        return "%04X.%04X.%04X" % (0x0212, (n >> 16) & 0xFFFF, n & 0xFFFF)

    def device_names(self) -> list[str]:
        """Return the names of every device currently in the lab."""
        return [
            d.findtext("ENGINE/NAME") or ""
            for d in self.devs.findall("DEVICE")
            if d.find("ENGINE") is not None
        ]

    def _resolve_name(self, name: str, on_name_conflict: str) -> str:
        if on_name_conflict not in ("raise", "suffix"):
            raise ValueError(
                f"on_name_conflict must be 'raise' or 'suffix', got {on_name_conflict!r}"
            )
        taken = set(self.device_names())
        if name not in taken:
            return name
        if on_name_conflict == "raise":
            raise DeviceNameConflictError(
                f"Device name {name!r} is already in use; choose another name, "
                "call prune_seed_devices() first, or pass on_name_conflict='suffix'"
            )
        n = 1
        while f"{name}({n})" in taken:
            n += 1
        return f"{name}({n})"

    def _normalize_model(self, m: str) -> str:
        if not m:
            return m
        if m in self.models:
            return m
        key = m.strip().lower().replace(" ", "_")
        if key in _MODEL_ALIASES and _MODEL_ALIASES[key] in self.models:
            return _MODEL_ALIASES[key]
        for prefix in ("router_", "router-", "switch_", "switch-"):
            if key.startswith(prefix):
                stripped = key[len(prefix):]
                if stripped in self.models:
                    return stripped
                if stripped in _MODEL_ALIASES and _MODEL_ALIASES[stripped] in self.models:
                    return _MODEL_ALIASES[stripped]
        return m

    def add_device(
        self,
        model: str,
        name: str,
        x: int = 100,
        y: int = 100,
        power: bool = True,
        ios_config: Sequence[str] | None = None,
        pc_ip: Sequence[str] | None = None,
        install: str | None = None,
        bay: int | None = 0,
        slot: int | None = None,
        on_name_conflict: Literal["raise", "suffix"] = "raise",
    ) -> str:
        """Add a device to the lab and return its save-ref-id.

        Args:
            model: Hardware model (e.g. "2911", "2960-24TT", "PC-PT", "Server-PT").
            name: Label / hostname of the device.
            x: Canvas X coordinate.
            y: Canvas Y coordinate.
            power: True to power on, False to start switched off.
            ios_config: Optional list of Cisco IOS CLI command lines.
            pc_ip: Tuple of (ip, subnet_mask, default_gateway) for end-devices.
            install: Optional module to install (e.g. "HWIC-2T").
            bay: Bay index for backwards compatibility (0 or None for next empty).
            slot: Absolute slot index for module installation.
            on_name_conflict: "raise" (default) or "suffix" to auto-rename SW1(1).
        """
        # Resolve model name and tolerate swapped positional arguments (name, model)
        resolved_model = self._normalize_model(model)
        if resolved_model not in self.models and name:
            resolved_from_name = self._normalize_model(name)
            if resolved_from_name in self.models:
                model, name = resolved_from_name, model
            else:
                model = resolved_model
        else:
            model = resolved_model

        if model not in self.models:
            raise ValueError(
                f"Unknown model {model!r}. Available models include: 2911, 2960-24TT, PC-PT, Server-PT, 3650-24PS..."
            )
        name = self._resolve_name(name, on_name_conflict)
        i = self._n
        self._n += 1

        leaf = _det_uuid("leaf", self._CID or "", i, name, model)
        px = self._pos
        self._pos += 6
        self._add_leaf(name, leaf, x=px)
        phys = f"{self._PP},{self._CID},{{{leaf}}}"

        blk = self.models[model].decode("utf-8", "replace")
        sid = f"save-ref-id:{9_900_000_000_000_000_000 + i}"
        s = re.sub(
            r"save-ref-id:\d+",
            lambda _m: sid,
            blk,
        )
        s = re.sub(
            r"<NAME[^>]*>.*?</NAME>",
            f'<NAME translate="true">{name}</NAME>',
            s,
            count=1,
            flags=re.S,
        )
        s = re.sub(
            r"(<WORKSPACE>\s*<LOGICAL>\s*<X>)[^<]*(</X>\s*<Y>)[^<]*(</Y>)",
            lambda m: f"{m.group(1)}{x}{m.group(2)}{y}{m.group(3)}",
            s,
            count=1,
            flags=re.S,
        )
        s = re.sub(
            r"<PHYSICAL[^>]*>[^<]*</PHYSICAL>", f"<PHYSICAL>{phys}</PHYSICAL>", s
        )
        s = re.sub(r"<PHYSICAL_CPUR>.*?</PHYSICAL_CPUR>", "", s, flags=re.S)
        cpur = self._make_cpur(px, leaf)
        s = re.sub(
            r"(<PHYSICAL>[^<]*</PHYSICAL>)", lambda m: m.group(1) + cpur, s, count=1
        )

        el = ET.fromstring(s)
        for tag in ("MACADDRESS", "BIA"):
            for e in el.iter(tag):
                e.text = self._next_mac()
        eng = el.find("ENGINE")
        if eng is None:
            eng = ET.SubElement(el, "ENGINE")
        for e in list(eng.findall("SAVE_REF_ID")):
            eng.remove(e)
        ET.SubElement(eng, "SAVE_REF_ID").text = sid

        p = eng.find("POWER")
        if p is None:
            p = ET.Element("POWER")
            kids = list(eng)
            anchor = eng.find("NAME")
            at = kids.index(anchor) + 1 if anchor is not None else min(2, len(kids))
            eng.insert(at, p)
        p.text = "true" if power else "false"

        if ios_config:
            for rc in list(eng.findall("RUNNINGCONFIG")):
                eng.remove(rc)
            rc = ET.SubElement(eng, "RUNNINGCONFIG")
            for line in ios_config:
                ET.SubElement(rc, "LINE").text = line

        if pc_ip:
            port = el.find(".//PORT")
            if port is not None:
                for tag, val in (
                    ("IP", pc_ip[0]),
                    ("SUBNET", pc_ip[1]),
                    ("PORT_GATEWAY", pc_ip[2]),
                    ("PORT_DHCP_ENABLE", "false"),
                ):
                    e = port.find(tag)
                    if e is None:
                        e = ET.SubElement(port, tag)
                    e.text = val

        self.devs.append(el)
        self._els[sid] = el
        if install:
            self.install_module(sid, install, bay=bay, slot=slot)
        return sid

    def _resolve_device_el(self, dev_id_or_name: str) -> tuple[str, ET.Element]:
        """Resolve a device by save-ref-id or by device name."""
        if dev_id_or_name in self._els:
            return dev_id_or_name, self._els[dev_id_or_name]
        for sid, el in self._els.items():
            if el.findtext("ENGINE/NAME") == dev_id_or_name:
                return sid, el
        for el in self.devs.findall("DEVICE"):
            sid = el.findtext("ENGINE/SAVE_REF_ID")
            nm = el.findtext("ENGINE/NAME")
            if sid and (sid == dev_id_or_name or nm == dev_id_or_name):
                self._els[sid] = el
                return sid, el
        raise DeviceNotFoundError(
            f"Device {dev_id_or_name!r} not found in lab devices"
        )

    def install_module(
        self,
        dev_id: str,
        module_model: str,
        bay: int | None = None,
        *,
        slot: int | None = None,
    ) -> None:
        """Install a hardware module (e.g. HWIC-2T) into a device bay."""
        if module_model not in self.modules:
            raise ModuleBayError(f"Unknown module model {module_model!r}")
        _sid, el = self._resolve_device_el(dev_id)
        eng = el.find("ENGINE")
        if eng is None:
            raise ModuleBayError(f"{dev_id} has no ENGINE block")

        all_bays = [
            sl
            for sl in eng.iter("SLOT")
            if sl.findtext("TYPE") == "eInterfaceCard"
        ]
        empties = [sl for sl in all_bays if sl.find("MODULE") is None]

        if slot is not None:
            if slot < 0 or slot >= len(all_bays):
                raise ModuleBayError(
                    f"{dev_id}: slot {slot} out of range; device has {len(all_bays)} bay(s)"
                )
            target = all_bays[slot]
            if target.find("MODULE") is not None:
                raise ModuleBayError(
                    f"{dev_id}: bay {slot} is already occupied; pass slot=None for next empty"
                )
        else:
            if bay not in (None, 0):
                raise ModuleBayError(
                    f"bay={bay} renumbers as bays fill. Use slot=<index> or omit both."
                )
            if not empties:
                raise ModuleBayError(f"{dev_id}: no empty eInterfaceCard bays")
            target = empties[0]

        mod = ET.fromstring(self.modules[module_model])
        for tag in ("MACADDRESS", "BIA"):
            for e in mod.iter(tag):
                e.text = self._next_mac()
        for c in list(target):
            target.remove(c)
        for c in list(mod):
            target.append(c)

    def _append_config(self, dev_id: str, lines: Sequence[str]) -> None:
        _sid, el = self._resolve_device_el(dev_id)
        if not lines:
            return
        eng = el.find("ENGINE")
        if eng is None:
            return
        rc = eng.find("RUNNINGCONFIG")
        if rc is None:
            rc = ET.SubElement(eng, "RUNNINGCONFIG")
        kids = list(rc)
        idx = len(kids)
        if kids and (kids[-1].text or "").strip().lower() == "end":
            idx = len(kids) - 1
        for off, line in enumerate(lines):
            e = ET.Element("LINE")
            e.text = line
            rc.insert(idx + off, e)

    def _set_serial_port(self, dev_id: str, port_name: str, rate: int) -> None:
        _sid, el = self._resolve_device_el(dev_id)
        ports = [
            p for p in el.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"
        ]
        if not ports:
            return
        try:
            idx = int(port_name.split("/")[-1])
        except ValueError:
            idx = 0
        if idx >= len(ports):
            idx = 0
        p = ports[idx]
        for tag, val in (
            ("CLOCKRATE", str(rate)),
            ("CLOCKRATEFLAG", "true"),
            ("POWER", "true"),
        ):
            e = p.find(tag)
            if e is None:
                e = ET.SubElement(p, tag)
            e.text = val

    def link(
        self,
        a: str,
        a_port: str,
        b: str,
        b_port: str,
        kind: str = "copper",
        dce: str | None = None,
        dce_port: str | None = None,
        clock: int = 128000,
    ) -> None:
        """Add a cable connecting two device interfaces.

        Args:
            a: Device A ID or name.
            a_port: Port name on device A (e.g. "GigabitEthernet0/0").
            b: Device B ID or name.
            b_port: Port name on device B (e.g. "GigabitEthernet0/1").
            kind: "copper" (eStraightThrough) or "serial" (eSerial).
            dce: For serial, device ID/name of the DCE end (defaults to a).
            dce_port: Port name of the DCE end (defaults to a_port).
            clock: Serial clock rate in bps (default 128000).
        """
        a_id, _ = self._resolve_device_el(a)
        b_id, _ = self._resolve_device_el(b)

        links_node = self.net.find("LINKS")
        if links_node is None:
            links_node = ET.SubElement(self.net, "LINKS")

        L = ET.SubElement(links_node, "LINK")
        ET.SubElement(L, "TYPE").text = (
            "eCopper"
            if kind == "copper"
            else ("eSerial" if kind == "serial" else None)
        )
        cab = ET.SubElement(L, "CABLE")

        if kind == "copper":
            fields = [
                ("LENGTH", "1"),
                ("FUNCTIONAL", "true"),
                ("FROM", a_id),
                ("PORT", a_port),
                ("TO", b_id),
                ("PORT", b_port),
                ("FROM_DEVICE_MEM_ADDR", "1"),
                ("TO_DEVICE_MEM_ADDR", "2"),
                ("FROM_PORT_MEM_ADDR", "3"),
                ("TO_PORT_MEM_ADDR", "4"),
                ("GEO_VIEW_COLOR", "#6ba72e"),
                ("IS_MANAGED_IN_RACK_VIEW", "false"),
                ("TYPE", "eStraightThrough"),
            ]
        elif kind == "serial":
            dce_id = self._resolve_device_el(dce)[0] if dce else a_id
            dport = dce_port or (a_port if dce_id == a_id else b_port)
            self._set_serial_port(a_id, a_port, clock if dce_id == a_id else 0)
            self._set_serial_port(b_id, b_port, clock if dce_id == b_id else 0)
            self._append_config(
                dce_id, [f"interface {dport}", f" clock rate {clock}"]
            )
            fields = [
                ("LENGTH", "1"),
                ("FUNCTIONAL", "true"),
                ("FROM", a_id),
                ("PORT", a_port),
                ("TO", b_id),
                ("PORT", b_port),
                ("FROM_DEVICE_MEM_ADDR", "1"),
                ("TO_DEVICE_MEM_ADDR", "2"),
                ("FROM_PORT_MEM_ADDR", "3"),
                ("TO_PORT_MEM_ADDR", "4"),
                ("GEO_VIEW_COLOR", "#1e59a5"),
                ("IS_MANAGED_IN_RACK_VIEW", "false"),
                ("DCEDEV", dce_id),
                ("DCEPORT", dport),
            ]
        else:
            raise InvalidCableError(
                f"kind must be 'copper' or 'serial', got {kind!r}"
            )

        for tag, val in fields:
            ET.SubElement(cab, tag).text = val

    connect = link  # Convenient alias

    def set_os(
        self, dev_id: str, image: str | None = None, file_name: str | None = None
    ) -> None:
        """Set a device's OS image / boot file (<OS_IMAGE>, <OS_FILE_NAME>)."""
        _sid, el = self._resolve_device_el(dev_id)
        eng = el.find("ENGINE")
        if eng is None:
            return
        for tag, val in (("OS_IMAGE", image), ("OS_FILE_NAME", file_name)):
            if val is None:
                continue
            e = eng.find(tag)
            if e is None:
                e = ET.SubElement(eng, tag)
            e.text = val

    def set_config_register(self, dev_id: str, value: str | int) -> None:
        """Set a device's software configuration register."""
        _sid, el = self._resolve_device_el(dev_id)
        eng = el.find("ENGINE")
        if eng is None:
            return
        e = eng.find("CONFIG_REGISTER")
        if e is None:
            e = ET.SubElement(eng, "CONFIG_REGISTER")
        e.text = str(value)

    def set_wireless(
        self,
        dev_id: str,
        ssid: str | None = None,
        auth_type: str | None = None,
        encrypt_type: str | None = None,
        password: str | None = None,
        userid: str | None = None,
        channel: str | None = None,
        radio_band: str | None = None,
    ) -> int:
        """Set wireless SSID and security on wireless ports of a device."""
        _sid, el = self._resolve_device_el(dev_id)
        n = 0
        for p in el.iter("PORT"):
            if p.find("SSID") is None:
                continue
            n += 1

            def setp(tag: str, val: Any) -> None:
                e = p.find(tag)
                if e is None:
                    e = ET.SubElement(p, tag)
                e.text = str(val)

            if ssid is not None:
                setp("SSID", ssid)
            if auth_type is not None:
                setp("AUTHEN_TYPE", auth_type)
            if encrypt_type is not None:
                setp("ENCRYPT_TYPE", encrypt_type)
            if password is not None and p.find("WPA_EAP_PASSWORD") is not None:
                setp("WPA_EAP_PASSWORD", password)
            if userid is not None and p.find("WPA_EAP_USERID") is not None:
                setp("WPA_EAP_USERID", userid)
            if channel is not None:
                setp("CHANNEL", channel)
            if radio_band is not None:
                setp("RADIO_BAND", radio_band)
        return n

    def initial_id(self, index: int = 0) -> str | None:
        """Return the SAVE_REF_ID of an initial device inherited from the seed network."""
        if index < 0 or index >= len(self._initial_devs):
            return None
        eng = self._initial_devs[index].find("ENGINE")
        if eng is None:
            return None
        sid = eng.find("SAVE_REF_ID")
        return sid.text if sid is not None else None

    def prune_seed_devices(self) -> list[str]:
        """Remove devices inherited from the seed network."""
        dead: set[str] = set()
        names: list[str] = []
        for el in self._initial_devs:
            eng = el.find("ENGINE")
            if eng is not None:
                nm = eng.findtext("NAME") or ""
                names.append(nm)
                sid = eng.findtext("SAVE_REF_ID")
                if sid:
                    dead.add(sid)
            ph = el.findtext("WORKSPACE/PHYSICAL")
            if ph and self._wsroot is not None:
                leaf = "{%s}" % ph.split(",")[-1].strip().strip("{}")
                for n in list(self._wsroot.iter("NODE")):
                    if n.findtext("UUID_STR") == leaf:
                        for parent in self._wsroot.iter("NODE"):
                            ch = parent.find("CHILDREN")
                            if ch is not None and n in list(ch):
                                ch.remove(n)
            if el in list(self.devs):
                self.devs.remove(el)

        links = self.net.find("LINKS")
        if links is not None and dead:
            for L in list(links.findall("LINK")):
                cab = L.find("CABLE")
                if cab is not None and (
                    cab.findtext("FROM") in dead or cab.findtext("TO") in dead
                ):
                    links.remove(L)
        self._initial_devs = []
        return names

    drop_initial = prune_seed_devices
    drop_seed_devices = prune_seed_devices

    def auto_layout(self) -> None:
        """Rearrange placed devices into a clean, collision-free grid layout."""
        layout = Layout()
        for d in self.devs.findall("DEVICE"):
            eng = d.find("ENGINE")
            if eng is None:
                continue
            name = eng.findtext("NAME") or ""
            ty = eng.find("TYPE")
            model = (ty.get("model") or "") if ty is not None else ""
            p = layout.place(name, model)
            lg = d.find("WORKSPACE/LOGICAL")
            if lg is not None:
                xe = lg.find("X")
                ye = lg.find("Y")
                if xe is not None:
                    xe.text = str(p.x)
                if ye is not None:
                    ye.text = str(p.y)

    def to_xml(self) -> bytes:
        """Serialize the complete lab document to UTF-8 XML bytes."""
        return ET.tostring(self.base, encoding="utf-8")

    def save(self, path: str | Path, fmt: str = "pkt") -> None:
        """Encode and save the lab to a .pkt or .pka container file."""
        encode(path, self.to_xml(), fmt=fmt)  # type: ignore[arg-type]

    export = save  # Convenient alias

    def as_view(self) -> LabView:
        """Return a typed Pydantic Lab inspection view over this document."""
        from pkt_core.models.lab import Lab as LabView

        return LabView.from_bytes(self.to_xml())

    @property
    def device_count(self) -> int:
        return len(self.devs.findall("DEVICE"))

    @property
    def link_count(self) -> int:
        links = self.net.find("LINKS")
        return len(links.findall("LINK")) if links is not None else 0
