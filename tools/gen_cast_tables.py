#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 pkt-core contributors
"""Regenerate ``native/pkt_core_native/src/cast_tables.rs``.

The CAST-128 S-boxes (RFC 2144) that CAST-256 reuses are copied into the Rust
crate *from the KAT-verified pure-Python module*, so the accelerated and
reference implementations cannot drift apart in transcription.  Run this only
when the tables themselves change (they are frozen standards text):

    python3 tools/gen_cast_tables.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from pkt_core.crypto import ciphers_pure as cp  # noqa: E402

OUT = REPO_ROOT / "native" / "pkt_core_native" / "src" / "cast_tables.rs"


def main() -> int:
    names = ["S1", "S2", "S3", "S4"]
    tables = [cp._S1, cp._S2, cp._S3, cp._S4]
    out = [
        "// SPDX-License-Identifier: GPL-3.0-or-later",
        "// SPDX-FileCopyrightText: 2026 pkt-core contributors",
        "//",
        "// CAST-128 S-boxes S1..S4 (RFC 2144 / RFC 2612 section 2.1.1), 256 u32",
        "// entries each.  GENERATED from src/pkt_core/crypto/ciphers_pure.py so the",
        "// Rust accelerator and the KAT-verified pure-Python implementation share",
        "// byte-identical constants.  Regenerate with tools/gen_cast_tables.py.",
        "",
        "//! CAST-256 S-boxes (RFC 2144), shared with CAST-128.",
        "",
    ]
    for name, table in zip(names, tables):
        out.append(f"pub(crate) static {name}: [u32; 256] = [")
        for i in range(0, 256, 4):
            row = ", ".join(f"0x{v:08X}" for v in table[i : i + 4])
            out.append(f"    {row},")
        out.append("];")
        out.append("")
    OUT.write_text("\n".join(out))
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
