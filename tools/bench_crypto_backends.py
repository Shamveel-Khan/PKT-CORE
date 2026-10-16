#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 pkt-core contributors
"""Benchmark block-cipher throughput across the three pkt-core backends.

Measures microseconds per 16-byte block for ``encrypt_block`` — the exact seam
CMAC, CTR and the Crypto++ EAX variant call — for every cipher/key size on
whichever backends this host provides:

* ``rust``   — the optional pkt_core_native accelerator,
* ``gcrypt`` — libgcrypt in ECB mode,
* ``pure``   — pkt_core.crypto.ciphers_pure.

Usage::

    python3 tools/bench_crypto_backends.py            # summary table
    python3 tools/bench_crypto_backends.py --blocks 20000 --repeat 5

The Rust backend is also measured in bulk mode (``encrypt_blocks``) to show
what the seam costs per call when the crossing is amortised.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from pkt_core.crypto.ciphers import available_backends, get_cipher  # noqa: E402

#: (label, cipher name, key size) grid; key sizes follow the pure registry.
GRID: list[tuple[str, str, int]] = [
    (name, name, key_len)
    for name, sizes in {
        "twofish": (16, 24, 32),
        "serpent128": (16,),
        "serpent192": (24,),
        "serpent256": (32,),
        "cast256": (16, 24, 32),
    }.items()
    for key_len in sizes
]

BACKENDS = ("rust", "gcrypt", "pure")


def bench_cipher(backend: str, name: str, key_len: int, blocks: int, repeat: int) -> float | None:
    """Median microseconds per block for one backend/cipher/key-size cell."""
    import random

    rng = random.Random(f"bench/{backend}/{name}/{key_len}")
    key = rng.randbytes(key_len)
    try:
        cipher = get_cipher(name, key, backend=backend)  # type: ignore[arg-type]
    except Exception:
        return None
    samples = [rng.randbytes(16) for _ in range(blocks)]
    times: list[float] = []
    sink = 0
    for _ in range(repeat):
        start = time.perf_counter()
        for block in samples:
            out = cipher.encrypt_block(block)
            sink += out[0]
        times.append(time.perf_counter() - start)
    if sink == -1:  # pragma: no cover - keep the loop observable
        print("impossible")
    return statistics.median(times) * 1e6 / blocks


def bench_bulk(name: str, key_len: int, blocks: int, repeat: int) -> float | None:
    """Median microseconds per block in native bulk mode (Rust only)."""
    import random

    rng = random.Random(f"bench/bulk/{name}/{key_len}")
    key = rng.randbytes(key_len)
    try:
        cipher = get_cipher(name, key, backend="rust")
    except Exception:
        return None
    if not hasattr(cipher, "encrypt_blocks"):
        return None
    data = rng.randbytes(16 * blocks)
    times: list[float] = []
    for _ in range(repeat):
        start = time.perf_counter()
        out = cipher.encrypt_blocks(data)
        times.append(time.perf_counter() - start)
    assert len(out) == len(data)
    return statistics.median(times) * 1e6 / blocks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blocks", type=int, default=8192, help="blocks per timing run")
    parser.add_argument("--repeat", type=int, default=5, help="timing runs per cell (median)")
    args = parser.parse_args()

    print(f"host backends: {', '.join(available_backends())}")
    print(f"blocks per run: {args.blocks}, runs per cell: {args.repeat} (median)")
    print()
    header = f"{'cipher':<14}{'key':>5}" + "".join(f"{b:>12}" for b in BACKENDS) + f"{'bulk':>12}"
    print(header)
    print("-" * len(header))
    for label, name, key_len in GRID:
        cells: list[str] = []
        for backend in BACKENDS:
            value = bench_cipher(backend, name, key_len, args.blocks, args.repeat)
            cells.append(f"{value:12.3f}" if value is not None else f"{'-':>12}")
        bulk = bench_bulk(name, key_len, args.blocks, args.repeat) if "rust" in available_backends() else None
        bulk_cell = f"{bulk:12.3f}" if bulk is not None else f"{'-':>12}"
        print(f"{label:<14}{key_len:>5}" + "".join(cells) + bulk_cell)
    print()
    print("units: microseconds per 16-byte block (lower is faster)")
    print("bulk: Rust encrypt_blocks() over the whole buffer (per-block cost)")
    print("note: libgcrypt has no CAST-256; '-'' means the backend cannot provide it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
