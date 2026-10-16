#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""scoring.py -- backward compatibility shim for pkt_core.builder.scoring.

For new code, import directly from the SDK package::

    from pkt_core.builder import scoring
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pkt_core.builder.scoring import (
    SCAFFOLD_NAMES,
    derive_values,
    from_shapes,
    from_template,
    harvest_shapes,
    load_shapes,
    save_shapes,
)

__all__ = [
    "SCAFFOLD_NAMES",
    "from_template",
    "derive_values",
    "harvest_shapes",
    "save_shapes",
    "load_shapes",
    "from_shapes",
]
