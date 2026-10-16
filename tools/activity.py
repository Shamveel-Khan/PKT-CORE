#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""activity.py -- backward compatibility shim for pkt_core.builder.activity.

For new code, import directly from the SDK package::

    from pkt_core import Activity
    # or
    from pkt_core.builder import Activity
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pkt_core.builder.activity import PKT, Activity

__all__ = ["Activity", "PKT"]

if __name__ == "__main__":
    print("activity: import Activity or from pkt_core import Activity")
