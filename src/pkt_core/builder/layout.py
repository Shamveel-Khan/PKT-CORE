"""Collision-free layout engine for Packet Tracer logical workspaces.

Provides label-inclusive sizing, greedy row-major packing, semantic tier
grouping, and occupancy detection so devices never visually overlap on the
canvas.
"""

from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET
from typing import Final, NamedTuple

__all__ = [
    "CHAR_W",
    "GUTTER",
    "LABEL_LINE",
    "ROW_PITCH",
    "FLOOR",
    "CANVAS_MIN",
    "CANVAS_MAX",
    "PAGE_WIDTH",
    "SKIP_STEP",
    "ICON_W",
    "Device",
    "Placement",
    "kind_for_model",
    "device_box",
    "label_box",
    "column_pitch",
    "tier_for_name",
    "parse_devices",
    "Layout",
]

# Geometry (docs/LAYOUT_INVESTIGATION.md): 1 workspace unit = 1 screen pixel at
# Packet Tracer's default 100% zoom; icon artwork measures 28-52 units wide;
# PT draws the model caption above and the device name below the icon at
# ~6.3 px/char (CHAR_W leaves a safety margin); human-authored corpus labs keep
# device centres 50-180 units apart with a hard floor of ~80.
CHAR_W: Final[int] = 7
GUTTER: Final[int] = 28
LABEL_LINE: Final[int] = 18
ROW_PITCH: Final[int] = 150
FLOOR: Final[int] = 80
CANVAS_MIN: Final[int] = 60
CANVAS_MAX: Final[int] = 3860
PAGE_WIDTH: Final[int] = 3900
SKIP_STEP: Final[int] = 20

ICON_W: Final[dict[str, tuple[int, int]]] = {
    "router": (52, 44),
    "switch": (50, 42),
    "multilayer-switch": (50, 42),
    "access-point": (50, 36),
    "pc": (36, 42),
    "laptop": (36, 42),
    "server": (30, 48),
    "iot": (40, 40),
    "sniffer": (50, 40),
    "firewall": (52, 42),
    "pdd": (40, 40),
    "default": (52, 44),
}

# Order matters: the first matching rule wins
_KIND_RULES: Final[tuple[tuple[str, str], ...]] = (
    (r"power distribution", "pdd"),
    (r"sniffer|cyberobserver", "sniffer"),
    (r"server|historian", "server"),
    (r"accesspoint|access point|wireless.?ap", "access-point"),
    (r"laptop|^lap-", "laptop"),
    (r"tablet|smartphone|^pc-|-pc$|home-pc", "pc"),
    (r"5505|asa|firewall|meraki-mx", "firewall"),
    (r"^(2960|2950|2900|ie-|switch-pt|hub-pt)", "switch"),
    (r"^(3560|3650|3550)-", "multilayer-switch"),
    (
        r"^(2911|2901|1941|1841|2811|26\d\d|isr|ir\d|cgr|8[12]\d|router-pt"
        r"|linksys|homerouter|dsl-modem|cloud-pt)",
        "router",
    ),
    (
        r"thing|sensor|monitor|motor|button|switch\(|\bled\b|fan|door|meter"
        r"|panel|turbine|speaker|siren|webcam|rfid|thermostat|humid|sprinkler"
        r"|furnace|heating|battery|beacon|light|window|garage|smoke|water"
        r"|sound|photo|piezo|servo|potentiometer|rocker|toggle|push|relay"
        r"|pressure|wind|solar|lcd|hmi|plc",
        "iot",
    ),
)
_KIND_RE: Final[tuple[tuple[re.Pattern[str], str], ...]] = tuple(
    (re.compile(p), k) for p, k in _KIND_RULES
)

_MAX_CELL_H = max(h for _w, h in ICON_W.values()) + 2 * LABEL_LINE + GUTTER
_MAX_HALF_H = (_MAX_CELL_H + 1) // 2


def kind_for_model(model: str) -> str:
    """Map a Packet Tracer device *model* string onto an icon-size class."""
    m = (model or "").lower()
    for rx, kind in _KIND_RE:
        if rx.search(m):
            return kind
    return "default"


def device_box(kind: str, name: str, model_caption: str) -> tuple[int, int]:
    """Return the label-inclusive cell (width, height) of one device.

    The box spans the icon plus the two label lines PT draws (model caption
    above, device name below) plus a GUTTER of clearance on every side, so two
    cells never overlap even when their labels are long. ``model_caption`` is
    the text PT prints above the icon (the model name).
    """
    icon_w, icon_h = ICON_W.get(kind, ICON_W["default"])
    w = max(icon_w, CHAR_W * len(name) + 16, CHAR_W * len(model_caption) + 16)
    h = icon_h + 2 * LABEL_LINE
    return w + GUTTER, h + GUTTER


def label_box(kind: str, name: str, model_caption: str) -> tuple[int, int]:
    """Return the icon+label box *without* the packing gutter (w, h)."""
    w, h = device_box(kind, name, model_caption)
    return w - GUTTER, h - GUTTER


def column_pitch(name: str) -> int:
    """Minimum centre-to-centre advance for a device called ``name``.

    Long device names draw long labels, so they need a wider column:
    200 units for names up to 16 characters, 260 for 17-24, 320 beyond.
    """
    n = len(name)
    return 200 if n <= 16 else 260 if n <= 24 else 320


# Semantic tiers of a generated lab, derived from device names so that packing
# keeps each tier in its own horizontal band. Order matters: first rule wins.
_TIER_RULES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("airborne", re.compile(r"^(E767|E2D|E2C|RC2)-\d\d-")),
    ("radar", re.compile(r"^RDR-")),
    ("airbase", re.compile(r"^AB-")),
    ("crc", re.compile(r"^CRC-")),
    ("nosc", re.compile(r"^NOSC-")),
    ("hq", re.compile(r"^ADC-")),
    (
        "backbone",
        re.compile(
            r"^(JADGE-BB-|CORE-RTR-|WAN-EDGE-|REG-HUB-"
            r"|DATALINK-AGG-|TDL-GW-|SATCOM-GW-|COALITION-GW-"
            r"|MGMT-GW-)"
        ),
    ),
    ("coalition", re.compile(r"^PARTNER-")),
    ("dc", re.compile(r"^(JADGE-|FW-)|-(SVR|SERVER)$|^DATA-HISTORIAN$")),
)


def tier_for_name(name: str) -> str:
    """Map a device name onto its semantic tier band (see :class:`Layout`)."""
    for tier, rx in _TIER_RULES:
        if rx.search(name):
            return tier
    return "misc"


class Device(NamedTuple):
    """One device as read back from a decoded lab."""

    name: str
    model: str
    kind: str
    x: float
    y: float


class Placement(NamedTuple):
    """One device as placed (or reserved) by :class:`Layout`."""

    name: str
    model: str
    kind: str
    group: str
    x: int
    y: int
    w: int
    h: int
    page: int


def parse_devices(xml: str | bytes) -> list[Device]:
    """Return every NETWORK device of a decoded lab, in document order."""
    if isinstance(xml, bytes):
        xml = xml.decode("utf-8", "replace")
    root = ET.fromstring(xml)
    devs = root.find("NETWORK/DEVICES")
    out: list[Device] = []
    if devs is None:
        return out
    for d in devs.findall("DEVICE"):
        eng = d.find("ENGINE")
        if eng is None:
            continue
        name = eng.findtext("NAME") or ""
        ty = eng.find("TYPE")
        model = (ty.get("model") or "") if ty is not None else ""
        lg = d.find("WORKSPACE/LOGICAL")
        if lg is None:
            continue
        xs, ys = lg.findtext("X"), lg.findtext("Y")
        if xs is None or ys is None:
            continue
        out.append(Device(name, model, kind_for_model(model), float(xs), float(ys)))
    return out


class _Band:
    """Row-major cursor state of one semantic group."""

    __slots__ = ("x0", "cy", "left", "row_h", "page", "prev")

    def __init__(self, x0: int, cy: int, page: int) -> None:
        self.x0 = x0
        self.cy = cy
        self.left = x0
        self.row_h = 0
        self.page = page
        self.prev: tuple[int, int, str] | None = None  # (cx, w, name)


class Layout:
    """Label-inclusive greedy row-major packer with an occupancy test.

    Devices are placed by :meth:`place`, which sizes each device with
    :func:`device_box` -- the icon *plus* both label lines PT draws (model
    caption above, device name below) plus a gutter -- so packed devices never
    have overlapping text. Each semantic *group* is a horizontal band: its
    first device starts at the group's anchor (see :meth:`anchor`) or, without
    an anchor, on the next row below everything already placed; the rest of the
    band packs row-major. A candidate position is AABB-tested against every
    already-placed or explicitly reserved box and skipped forward while
    occupied ("skip-occupied-cells"), and an 80-unit centre-to-centre floor is
    enforced as a hard invariant.

    Canvas containment: X, Y stay inside [CANVAS_MIN, CANVAS_MAX]; when a band
    runs out of vertical room it wraps to a second page column at x + PAGE_WIDTH
    (3900 units to the right). Spacing is never shrunk to force a fit.

    Placement is deterministic: the same call sequence always yields the same
    coordinates.
    """

    def __init__(
        self,
        x_min: int = CANVAS_MIN,
        y_min: int = CANVAS_MIN,
        x_max: int = CANVAS_MAX,
        y_max: int = CANVAS_MAX,
        page_width: int = PAGE_WIDTH,
    ) -> None:
        if not (x_min < x_max and y_min < y_max):
            raise ValueError("canvas bounds must satisfy min < max")
        self.x_min = x_min
        self.y_min = y_min
        self.x_max = x_max
        self.y_max = y_max
        self.page_width = page_width
        self._placed: list[Placement] = []
        self._anchors: dict[str, tuple[int, int]] = {}
        self._bands: dict[str, _Band] = {}

    def _page_x_min(self, page: int) -> int:
        return self.x_min + page * self.page_width

    def _page_x_max(self, page: int) -> int:
        return self.x_max + page * self.page_width

    @property
    def placements(self) -> list[Placement]:
        """Every placed/reserved device, in the order they were added."""
        return list(self._placed)

    def anchor(self, group: str, x: float, y: float) -> None:
        """Pin where a group's band starts: the first device's centre is placed
        near (x, y). The rest of the band still packs row-major and is still
        collision-checked. Anchors outside the canvas are clamped inside.
        """
        self._anchors[group] = (int(round(x)), int(round(y)))

    def reserve(
        self,
        name: str,
        model: str,
        x: float,
        y: float,
        kind: str | None = None,
    ) -> Placement:
        """Record an explicitly positioned device at exactly (x, y).

        Used for callers that pass x/y themselves: the device sits where asked
        and merely occupies space for later placements.
        """
        k = kind or kind_for_model(model)
        w, h = device_box(k, name, model)
        p = Placement(
            name,
            model,
            k,
            "",
            int(round(x)),
            int(round(y)),
            w,
            h,
            int(round(x)) // self.page_width,
        )
        self._placed.append(p)
        return p

    def forget(self, name: str) -> None:
        """Drop reserved/placed boxes called ``name`` (e.g. pruned seed)."""
        self._placed = [p for p in self._placed if p.name != name]

    def _band_for(self, group: str, w: int, h: int) -> _Band:
        band = self._bands.get(group)
        if band is not None:
            return band
        page = 0
        if group in self._anchors:
            ax, ay = self._anchors[group]
            cy = min(max(ay, self.y_min + _MAX_HALF_H), self.y_max - _MAX_HALF_H)
            left = min(max(ax - w // 2, self.x_min), self.x_max - w)
        else:
            cy = self.y_min + _MAX_HALF_H
            if self._placed:
                bottom = max(p.y + (p.h + 1) // 2 for p in self._placed)
                low = max(p.y for p in self._placed)
                cy = max(bottom + GUTTER // 2 + _MAX_HALF_H, low + ROW_PITCH)
                if cy + _MAX_HALF_H > self.y_max:  # wrap to page column 2
                    page = 1
                    cy = self.y_min + _MAX_HALF_H
            left = self._page_x_min(page)
        band = _Band(left, cy, page)
        self._bands[group] = band
        return band

    def _wrap_row(self, band: _Band) -> None:
        band.cy += max(ROW_PITCH, band.row_h)
        if band.cy + _MAX_HALF_H > self.y_max:
            band.page += 1
            band.cy = self.y_min + _MAX_HALF_H
        band.left = self._page_x_min(band.page)
        band.prev = None
        band.row_h = 0

    def _min_left_clear(
        self, cx: int, cy: int, w: int, h: int, band: _Band
    ) -> int | None:
        """Smallest cursor at which the cell clears every placed box, or None
        when the candidate (cx, cy) is already clear.
        """
        need: int | None = None
        for p in self._placed:
            dx = cx - p.x
            dy = cy - p.y
            overlap = abs(dx) * 2 < w + p.w and abs(dy) * 2 < h + p.h
            close = dx * dx + dy * dy < FLOOR * FLOOR
            if not overlap and not close:
                continue
            cand = band.left
            if abs(dy) * 2 < h + p.h:
                # moving right must lift the AABB overlap in x
                cand = max(cand, p.x + (p.w + w + 1) // 2 - w // 2)
            if dy * dy < FLOOR * FLOOR:
                need_dx = math.isqrt(FLOOR * FLOOR - dy * dy)
                if need_dx * need_dx < FLOOR * FLOOR - dy * dy:
                    need_dx += 1
                cand = max(cand, p.x + need_dx - w // 2)
            need = cand if need is None else max(need, cand)
        return need

    def place(
        self,
        name: str,
        model: str,
        group: str = "",
        kind: str | None = None,
    ) -> Placement:
        """Place one device and return its :class:`Placement`.

        The device is sized with :func:`device_box`, laid out row-major inside
        its group's band, and shifted right (wrapping to the next row / page
        column as needed) until it clears every already-placed box and honours
        the 80-unit floor.
        """
        k = kind or kind_for_model(model)
        w, h = device_box(k, name, model)
        if w > self.x_max - self.x_min or h > self.y_max - self.y_min:
            raise ValueError(f"device {name!r} does not fit the canvas")
        band = self._band_for(group, w, h)
        for _ in range(100_000):
            if band.left + w > self._page_x_max(band.page):
                self._wrap_row(band)
                continue
            cx = band.left + w // 2
            cy = band.cy
            if band.prev is not None:
                pcx, pw, pname = band.prev
                step = max(
                    column_pitch(pname),
                    column_pitch(name),
                    (pw + w + 1) // 2,
                    FLOOR,
                )
                if band.left < pcx + step - w // 2:
                    band.left = pcx + step - w // 2
                    continue
            need = self._min_left_clear(cx, cy, w, h, band)
            if need is not None:
                band.left = max(band.left + SKIP_STEP, need)
                continue
            p = Placement(name, model, k, group, cx, cy, w, h, band.page)
            self._placed.append(p)
            band.prev = (cx, w, name)
            band.left = cx + w - w // 2
            band.row_h = max(band.row_h, h)
            return p
        raise RuntimeError(f"layout: cannot place {name!r}")
