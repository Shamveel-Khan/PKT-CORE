# jasdf_layout — enterprise-generator layout patch

The JASDF/JADGE generator (`../jasdf_aewc/build_jasdf_aewc.py`) used to lay
devices out with hand-typed literals and index-derived constant-pitch formulas
(`bx + 350` inside a 310-unit airframe grid, `x = 250 + i * 400` CRC columns,
`y = 1120` NOSC row 30 units from the `y = 1150` TDL row, ...).  Independent
section grids overlapped wherever their hard-coded origins coincided, nothing
accounted for icon size or label length, and the model ran off the page
(Y = 5140 on a 3900x3900 canvas).  See `docs/LAYOUT_INVESTIGATION.md`.

This directory carries the fix as a **patch**, not an edit to the generator
source: the validator/sanitiser work is landing in that same file, so the
layout change is kept separable and re-appliable.

## `layout.patch`

Two hunks against `generators/jasdf_aewc/build_jasdf_aewc.py`:

1. `__init__` creates a `lab_api.Layout` helper — the label-inclusive greedy
   row-major packer that is now part of `tools/lab_api.py`.
2. `JASDF.add()` routes placement through it.  The positional `x, y` arguments
   of the old call sites are kept but demoted to *hints*; they no longer
   position anything literally.  Devices pack row-major inside their semantic
   tier band (`lab_api.tier_for_name`: airborne / radar / airbase / crc / nosc
   / hq / backbone / coalition / dc), so no two devices — or their model
   captions and name labels — can collide, the 80-unit centre floor from the
   human-authored corpus is enforced, and everything stays on the 3900x3900
   page (overflow wraps to a second page column at +3900).

All 57 `self.add(...)` call sites are left untouched: only the wrapper
changes.  That keeps the patch small enough to re-apply on top of concurrent
validator/sanitiser edits.

## Applying

```sh
cd packet-tracer-pkt-format
patch -p1 --forward < generators/jasdf_layout/layout.patch
```

The patch is written as a `git`-style diff (`a/` `b/` prefixes, `-p1`).

## Rebuilding the delivered artefacts

The maintainer runs `tools/repack_layout.py` against the delivered `.pkt`
files (single-writer rule: nothing in this directory writes them).  Running
the patched generator reproduces the same placement the repack tool computes,
because both call the same `lab_api.Layout` with the same tier mapping and the
same document order.
