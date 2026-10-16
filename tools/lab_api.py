#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""lab_api.py -- backward compatibility shim for pkt_core.builder.

For new code, import directly from the SDK package::

    from pkt_core import Lab, Layout
    # or
    from pkt_core.builder import Lab, Layout
"""

import sys
from pathlib import Path

# Ensure src/ is on sys.path if running directly from repo checkout
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pkt_core.builder.lab import (
    Lab,
    _ENG_NAME_RE,
    _ENG_POWER_RE,
    _det_uuid,
    _iter_devices,
    harvest_models,
    harvest_modules,
    load_templates,
    normalise_device_power,
)
from pkt_core.builder.layout import (
    CANVAS_MAX,
    CANVAS_MIN,
    CHAR_W,
    FLOOR,
    GUTTER,
    ICON_W,
    LABEL_LINE,
    PAGE_WIDTH,
    ROW_PITCH,
    SKIP_STEP,
    Device,
    Layout,
    Placement,
    _KIND_RE,
    _KIND_RULES,
    _MAX_CELL_H,
    _MAX_HALF_H,
    _TIER_RULES,
    _Band,
    column_pitch,
    device_box,
    kind_for_model,
    label_box,
    parse_devices,
    tier_for_name,
)

__all__ = [
    "Lab",
    "Layout",
    "Placement",
    "Device",
    "load_templates",
    "harvest_models",
    "harvest_modules",
    "normalise_device_power",
    "kind_for_model",
    "device_box",
    "label_box",
    "column_pitch",
    "tier_for_name",
    "parse_devices",
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
]

if __name__ == "__main__":
    print("lab_api: import and use class Lab() or from pkt_core import Lab")
