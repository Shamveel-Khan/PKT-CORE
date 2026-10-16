# pkt_core_native — optional Rust accelerator for pkt-core

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 pkt-core contributors -->

Rust (PyO3) implementation of the three 128-bit block ciphers the Packet
Tracer container formats use — **Twofish**, **Serpent** and **CAST-256** —
in the exact `encrypt_block` seam that
[`pkt_core.crypto.ciphers`](../../src/pkt_core/crypto/ciphers.py) plugs into.

It is a **pure accelerator**: `pkt-core` imports and works fully when this
module is absent. The backend preference order is

1. **Rust** (`pkt_core_native`) — fastest, and the only accelerated source of
   CAST-256 (libgcrypt does not implement it),
2. **libgcrypt** — where it covers the algorithm,
3. **pure Python** (`pkt_core.crypto.ciphers_pure`) — portable fallback and
   source of truth for the known-answer tests.

CMAC, the big-endian CTR mode and the Crypto++ EAX tag construction are *not*
re-implemented here: they stay in Python and only ever call `encrypt_block`,
which keeps the three backends interchangeable and the AEAD maths in one
reviewable place.

## Algorithm references and test vectors

| Cipher | Specification | Known-answer source |
| --- | --- | --- |
| Twofish | Schneier et al., "The Twofish Encryption Algorithm" (1998) | AES submission `ecb_tbl.txt` / `ecb_ival.txt` (as shipped in Crypto++ `TestData/twofishv.dat`, Botan `block/twofish.vec`) |
| Serpent | Anderson, Biham, Knudsen, "Serpent" (AES submission, 1998) | AES-submission / NESSIE vectors (Crypto++ `TestData/serpentv.dat`) |
| CAST-256 | Adams & Gilchrist, RFC 2612 (June 1999) | RFC 2612 appendix A, including the per-quad-round ROTK/MASK/OUT intermediates |

The Serpent implementation is the interoperable **bit-slice formulation
without the optional IP/FP permutations** — the variant libgcrypt, Crypto++,
Botan and the NESSIE vectors use.

## Build

Requires a Rust toolchain (1.74+) and Python 3.10+. `maturin` drives the
build; a Makefile wraps the common flows.

```sh
# from this directory
make test        # cargo test: the published KATs, --no-default-features
make wheel       # maturin build --release  -> dist/pkt_core_native-*.whl
make install     # build + pip install into the active Python
make bench       # run ../../tools/bench_crypto_backends.py
make clean
```

Or by hand:

```sh
python3 -m pip install maturin
python3 -m maturin build --release --out dist
python3 -m pip install dist/pkt_core_native-*.whl
```

`abi3-py310` means one wheel covers every CPython >= 3.10.

> `cargo test` must run with `--no-default-features`: the `extension-module`
> feature (what maturin builds with) tells PyO3 not to link `libpython`, which
> a standalone test binary cannot do without. The Makefile handles this.

Verify the wiring after installing:

```sh
python3 - <<'PY'
from pkt_core.crypto import ciphers
print("backends:", ciphers.available_backends())
print("rust check:", ciphers.rust_check())
PY
```

## Python API

The module exposes one class and two helpers:

```python
import pkt_core_native

cipher = pkt_core_native.Cipher("twofish", key)   # 16/24/32-byte key
cipher.block_size      # 16
cipher.key_size        # len(key)
cipher.encrypt_block(block)      # 16 bytes -> 16 bytes
cipher.encrypt_blocks(data)      # bulk ECB over whole 16-byte blocks
pkt_core_native.available_ciphers()
pkt_core_native.version()
```

`encrypt_block` is the seam the Python layer uses; `encrypt_blocks` is a bulk
convenience that amortises the Python/Rust boundary for callers that have many
blocks available (benchmarks, future CTR/CMAC fast paths).

## Selection, fallback and the environment knob

`pkt_core.crypto.ciphers.get_cipher(name, key)` probes for this module lazily
and falls back cleanly. Tests and benchmarks can pin a backend explicitly:

```sh
PKT_CORE_BACKEND=rust   pytest tests/     # force the accelerator
PKT_CORE_BACKEND=pure   pytest tests/     # force the pure-Python path
PKT_CORE_BACKEND=gcrypt pytest tests/     # force libgcrypt where it applies
PKT_CORE_DISABLE_RUST=1 pytest tests/     # pretend the module is not installed
```

## Correctness

* `cargo test` runs the published known-answer tests inside the crate,
  including RFC 2612 appendix A's intermediate key-schedule values
  (`Kr_(0)`, `Km_(0)`, the block after `Q_0`) which pin the CAST-256 key
  ordering.
* `tests/test_rust_backend.py` (repo root) mirrors every KAT of
  `tests/test_ciphers.py` through the native module and cross-checks
  `Rust == pure Python` on 200 random key/plaintext pairs per cipher and key
  size, plus byte-identical container decoding of real corpus files.
* `tests/test_ciphers.py` keeps proving `libgcrypt == published KATs` and
  `pure Python == libgcrypt`, so the three-way equality closes transitively.

## Licence

GPL-3.0-or-later, the same as the rest of pkt-core.
